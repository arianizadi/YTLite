"""Validate the trusted YTPlus inputs and the artifacts produced by the workflows."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import plistlib
import re
import stat
import struct
import sys
import tarfile
import unicodedata
import zipfile
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path, PurePosixPath

OFFICIAL_BUNDLE_ID = "com.google.ios.youtube"
PACKAGE_ID = "com.dvntm.ytlite"
BUNDLE_ID_PATTERN = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
ROOTFUL_SUBSTRATE_PATH = "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
INJECTED_SUBSTRATE_PATH = "@rpath/CydiaSubstrate.framework/CydiaSubstrate"
DYLIB_COMMANDS = frozenset(
    {0xC, 0x18, 0x1F, 0x20, 0x23, 0x80000018, 0x8000001F, 0x80000023}
)

# GitHub publishes the DEB checksums. The raw dylib, section, and bundle digests
# are derived from those exact official rootful assets. The packaged-dylib
# digests are the deterministic result of the pinned Cyan commit performing its
# one required CydiaSubstrate load-path rewrite.
RELEASES = {
    "5.2b4": {
        "access": "free",
        "deb_sha256": "56130dd4c7a1c9c80acc38c88d12002de3d099ca8de3698f87729331258ed9fa",
        "deb_size": 6_417_712,
        "dylib_sha256": "c98528f3583960ab618a9374747408e96807102389acd472f38e82c83188e28e",
        "packaged_dylib_sha256": "5691b31ce17a039cdc8b917b56792641409e989a01e0dff74e3c180ddf33e14d",
        "text_sha256": "0cc05599c0f09ad499d3c4cd8ad0feec333400c961f832d9611306104f031959",
        "sections_sha256": "96c1f82fe72575c8a388496471745c4c5efc8350737a3351c45aa8913833c735",
        "bundle_sha256": "a930ce23150fa692cbc1fdd2590b7720c9bbe973a0b318a11c19e1f3aa0e7e3f",
        "youtube_version": "20.42.3",
    },
    "5.2.2": {
        "access": "subscription",
        "deb_sha256": "132db2162a7a5163c36a9c6ce5637f45139c035279bacd36e8d3b97feba4ebc7",
        "deb_size": 7_361_308,
        "dylib_sha256": "bdcc4d4ccaa5835d35bc97ccbdfc1c3dff514cb7161848265dcc0585f364c0ca",
        "packaged_dylib_sha256": "0464beece8991fc1168d30db3fd9fbc0410f823797c92bb9278ef880d3b300d1",
        "text_sha256": "73fabfb984369100e7785d3dc5e726140d0f973f0cc31d66632d12d91ad717c2",
        "sections_sha256": "2d5e1bc397ad74fb15178b1c1c044204575189af02c8fd9edc2a49dc2985989d",
        "bundle_sha256": "bc746261d6c7b5d2fa8d194adaab479139eef42d1c968a2fee589bcc3f6aee92",
        "youtube_version": "21.16.2",
    },
}

REQUIRED_DEB_PATHS = {
    "Library/Application Support/YTLite.bundle/Info.plist",
    "Library/MobileSubstrate/DynamicLibraries/YTLite.dylib",
    "Library/MobileSubstrate/DynamicLibraries/YTLite.plist",
}

MAX_DEB_MEMBERS = 20_000
MAX_DEB_MEMBER_SIZE = 256 * 1024 * 1024
MAX_DEB_TOTAL_SIZE = 512 * 1024 * 1024
MAX_ZIP_MEMBERS = 100_000
MAX_ZIP_MEMBER_SIZE = 2 * 1024 * 1024 * 1024
MAX_ZIP_TOTAL_SIZE = 5 * 1024 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 1_000
MAX_AR_MEMBERS = 16


class ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AppInfo:
    app_prefix: str
    bundle_id: str
    version: str
    executable: str


@dataclass(frozen=True)
class MachOSlice:
    offset: int
    size: int
    endian: str
    is_64: bool
    cpu_type: int
    file_type: int
    commands: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class PackagedInfo:
    app: AppInfo
    dylib_digest: str
    continuity_digest: str
    substrate_paths: tuple[tuple[str, ...], ...]
    text_digests: tuple[str, ...]
    section_digest: str
    bundle_digest: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(files: dict[str, bytes], prefix: str) -> str:
    selected = {
        name.removeprefix(prefix): contents
        for name, contents in files.items()
        if name.startswith(prefix)
    }
    if not selected:
        raise ValidationError(f"No regular files found under {prefix}")
    digest = hashlib.sha256()
    for name in sorted(selected):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(selected[name]).digest())
    return digest.hexdigest()


def release(version: str) -> dict[str, object]:
    try:
        return RELEASES[version]
    except KeyError as exc:
        supported = ", ".join(RELEASES)
        raise ValidationError(
            f"Unsupported YTPlus version {version!r}; supported versions: {supported}"
        ) from exc


def validate_bundle_id(bundle_id: str) -> None:
    if not BUNDLE_ID_PATTERN.fullmatch(bundle_id):
        raise ValidationError(f"Invalid output bundle ID: {bundle_id!r}")


def safe_archive_name(name: str) -> str:
    normalized = name.removeprefix("./")
    path = PurePosixPath(normalized)
    canonical = str(path)
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in path.parts
        or normalized.rstrip("/") != canonical
    ):
        raise ValidationError(f"Unsafe archive member path: {name!r}")
    return canonical


def canonical_archive_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        raise ValidationError("The tweak file is not a Debian ar archive")

    members: dict[str, bytes] = {}
    offset = 8
    while offset < len(data):
        if len(members) >= MAX_AR_MEMBERS:
            raise ValidationError("Debian ar archive contains too many members")
        if offset + 60 > len(data):
            raise ValidationError("Truncated ar member header")
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise ValidationError("Invalid ar member header")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as exc:
            raise ValidationError("Invalid ar member size") from exc

        raw_name = header[:16].decode("ascii", "strict").strip()
        payload_start = offset + 60
        payload_end = payload_start + size
        if payload_end > len(data):
            raise ValidationError("Truncated ar member payload")

        payload = data[payload_start:payload_end]
        if raw_name.startswith("#1/"):
            try:
                name_length = int(raw_name[3:])
            except ValueError as exc:
                raise ValidationError("Invalid extended ar member name") from exc
            if name_length > len(payload):
                raise ValidationError("Truncated extended ar member name")
            name = payload[:name_length].decode("utf-8")
            payload = payload[name_length:]
        else:
            name = raw_name.rstrip("/")

        if name in members:
            raise ValidationError(f"Duplicate ar member: {name}")
        members[name] = payload
        offset = payload_end + (payload_end % 2)

    return members


def tar_members(data: bytes, label: str) -> dict[str, bytes | None]:
    members: dict[str, bytes | None] = {}
    canonical_names: set[str] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            archive_members = archive.getmembers()
            if len(archive_members) > MAX_DEB_MEMBERS:
                raise ValidationError(f"{label} archive contains too many members")
            for member in archive_members:
                name = safe_archive_name(member.name)
                canonical_name = canonical_archive_key(name)
                if canonical_name in canonical_names:
                    raise ValidationError(f"Duplicate {label} member: {name}")
                canonical_names.add(canonical_name)
                if not (member.isfile() or member.isdir()):
                    raise ValidationError(
                        f"Unsupported {label} member type for {name}: links and devices are forbidden"
                    )
                if member.isfile():
                    if member.size > MAX_DEB_MEMBER_SIZE:
                        raise ValidationError(f"{label} member is too large: {name}")
                    total_size += member.size
                    if total_size > MAX_DEB_TOTAL_SIZE:
                        raise ValidationError(
                            f"{label} archive expands beyond the size limit"
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ValidationError(f"Cannot read {label} member: {name}")
                    members[name] = extracted.read()
                else:
                    members[name] = None
    except (tarfile.TarError, EOFError, lzma_error()) as exc:
        raise ValidationError(f"Cannot read {label} archive: {exc}") from exc
    return members


def lzma_error() -> type[Exception]:
    # Importing lazily keeps the exception tuple portable across Python builds.
    import lzma

    return lzma.LZMAError


def parse_control(data: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for raw_line in data.decode("utf-8", "strict").splitlines():
        if raw_line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + raw_line[1:]
            continue
        if ":" not in raw_line:
            current = None
            continue
        current, value = raw_line.split(":", 1)
        fields[current] = value.strip()
    return fields


def find_member(members: dict[str, bytes], prefix: str) -> bytes:
    matches = [value for name, value in members.items() if name.startswith(prefix)]
    if len(matches) != 1:
        raise ValidationError(
            f"Expected exactly one {prefix}* member, found {len(matches)}"
        )
    return matches[0]


def unpack_deb(
    data: bytes, label: str
) -> tuple[dict[str, str], dict[str, bytes | None]]:
    archive = ar_members(data)
    if archive.get("debian-binary") != b"2.0\n":
        raise ValidationError(f"{label} has an invalid debian-binary member")

    control_archive = find_member(archive, "control.tar")
    control_members = tar_members(control_archive, "control")
    control_data = control_members.get("control")
    if not isinstance(control_data, bytes):
        raise ValidationError(f"{label} does not contain a regular control file")
    fields = parse_control(control_data)
    data_archive = find_member(archive, "data.tar")
    payload = tar_members(data_archive, "data")
    return fields, payload


def inspect_deb(data: bytes, label: str) -> tuple[dict[str, str], bytes, str]:
    fields, payload = unpack_deb(data, label)
    expected_fields = {"Package": PACKAGE_ID, "Architecture": "iphoneos-arm"}
    for field, expected in expected_fields.items():
        if fields.get(field) != expected:
            raise ValidationError(
                f"{label} {field} mismatch: expected {expected!r}, "
                f"got {fields.get(field)!r}"
            )

    missing = sorted(REQUIRED_DEB_PATHS - payload.keys())
    if missing:
        raise ValidationError(
            f"{label} is missing required paths: {', '.join(missing)}"
        )

    dylib = payload["Library/MobileSubstrate/DynamicLibraries/YTLite.dylib"]
    if not isinstance(dylib, bytes):
        raise ValidationError("YTLite.dylib is not a regular file")
    validate_macho_kind(dylib, "YTLite.dylib", 0x6)

    filter_path = "Library/MobileSubstrate/DynamicLibraries/YTLite.plist"
    bundle_path = "Library/Application Support/YTLite.bundle/Info.plist"
    filter_data = payload[filter_path]
    bundle_data = payload[bundle_path]
    if not isinstance(filter_data, bytes) or not isinstance(bundle_data, bytes):
        raise ValidationError(f"{label} contains a non-regular required plist")
    try:
        filter_plist = plistlib.loads(filter_data)
        bundle_plist = plistlib.loads(bundle_data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ValidationError(f"{label} contains an invalid plist: {exc}") from exc
    if not isinstance(filter_plist, dict) or not isinstance(bundle_plist, dict):
        raise ValidationError(f"{label} contains a non-dictionary plist")
    filter_section = filter_plist.get("Filter")
    if not isinstance(filter_section, dict):
        raise ValidationError(f"{label} contains an invalid tweak filter")
    bundles = filter_section.get("Bundles", [])
    if not isinstance(bundles, list) or OFFICIAL_BUNDLE_ID not in bundles:
        raise ValidationError(f"{label} does not target the official YouTube bundle ID")
    if bundle_plist.get("CFBundleIdentifier") != PACKAGE_ID:
        raise ValidationError(f"{label} contains the wrong YTLite.bundle identifier")

    if not fields.get("Version"):
        raise ValidationError(f"{label} control file has no Version")
    regular_payload = {
        name: contents
        for name, contents in payload.items()
        if isinstance(contents, bytes)
    }
    bundle_digest = tree_digest(
        regular_payload, "Library/Application Support/YTLite.bundle/"
    )
    return fields, dylib, bundle_digest


def reject_ytlite_collision(data: bytes, label: str) -> None:
    _, payload = unpack_deb(data, label)
    collisions = [
        name
        for name in payload
        if PurePosixPath(name).name.casefold() == "ytlite.dylib"
        or "ytlite.bundle" in {part.casefold() for part in PurePosixPath(name).parts}
    ]
    if collisions:
        raise ValidationError(
            f"{label} collides with the official YTLite payload: {', '.join(collisions[:3])}"
        )


def validate_deb_bytes(data: bytes, version: str, label: str) -> None:
    metadata = release(version)
    actual_digest = sha256(data)
    if len(data) != metadata["deb_size"]:
        raise ValidationError(
            f"{label} size mismatch: expected {metadata['deb_size']}, got {len(data)}"
        )
    if actual_digest != metadata["deb_sha256"]:
        raise ValidationError(
            f"{label} SHA-256 mismatch: expected {metadata['deb_sha256']}, "
            f"got {actual_digest}"
        )

    fields, dylib, bundle_digest = inspect_deb(data, label)
    if fields["Version"] != version:
        raise ValidationError(
            f"{label} Version mismatch: expected {version!r}, got {fields['Version']!r}"
        )
    if sha256(dylib) != metadata["dylib_sha256"]:
        raise ValidationError("YTLite.dylib does not match the official release bytes")
    if text_digests(dylib, "YTLite.dylib") != [metadata["text_sha256"]]:
        raise ValidationError("YTLite.dylib code does not match the official release")
    if section_manifest_digest(dylib, "YTLite.dylib") != metadata["sections_sha256"]:
        raise ValidationError("YTLite.dylib sections do not match the official release")
    if bundle_digest != metadata["bundle_sha256"]:
        raise ValidationError("YTLite.bundle does not match the official release")


def zip_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members: dict[str, zipfile.ZipInfo] = {}
    canonical_names: set[str] = set()
    total_size = 0
    archive_members = archive.infolist()
    if len(archive_members) > MAX_ZIP_MEMBERS:
        raise ValidationError("Zip archive contains too many members")
    for info in archive_members:
        name = safe_archive_name(info.filename)
        canonical_name = canonical_archive_key(name)
        if canonical_name in canonical_names:
            raise ValidationError(f"Duplicate zip member: {name}")
        canonical_names.add(canonical_name)
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValidationError(
                f"Unsupported zip member type for {name}: links and devices are forbidden"
            )
        if info.file_size > MAX_ZIP_MEMBER_SIZE:
            raise ValidationError(f"Zip member is too large: {name}")
        total_size += info.file_size
        if total_size > MAX_ZIP_TOTAL_SIZE:
            raise ValidationError("Zip archive expands beyond the size limit")
        if (
            info.file_size > 1024 * 1024
            and info.compress_size > 0
            and info.file_size / info.compress_size > MAX_ZIP_COMPRESSION_RATIO
        ):
            raise ValidationError(
                f"Suspicious compression ratio for zip member: {name}"
            )
        members[name] = info
    corrupt = archive.testzip()
    if corrupt:
        raise ValidationError(f"Corrupt zip member: {corrupt}")
    return members


def top_level_app(
    archive: zipfile.ZipFile,
) -> tuple[AppInfo, dict[str, zipfile.ZipInfo]]:
    members = zip_members(archive)
    info_paths = sorted(
        name
        for name in members
        if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
    )
    if len(info_paths) != 1:
        raise ValidationError(
            f"Expected one top-level app Info.plist, found {len(info_paths)}"
        )

    info_path = info_paths[0]
    try:
        plist = plistlib.loads(archive.read(members[info_path]))
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ValidationError(f"Cannot parse {info_path}: {exc}") from exc
    if not isinstance(plist, dict):
        raise ValidationError(f"{info_path} does not contain a plist dictionary")

    required = (
        "CFBundleIdentifier",
        "CFBundleShortVersionString",
        "CFBundleExecutable",
    )
    missing = [key for key in required if not isinstance(plist.get(key), str)]
    if missing:
        raise ValidationError(
            f"Info.plist is missing string keys: {', '.join(missing)}"
        )

    prefix = info_path.removesuffix("Info.plist")
    executable_path = prefix + plist["CFBundleExecutable"]
    if executable_path not in members:
        raise ValidationError(f"Main executable is missing: {executable_path}")
    executable = archive.read(members[executable_path])
    validate_macho_kind(executable, executable_path, 0x2)
    cryptids = macho_cryptids(executable, executable_path)
    if any(cryptid != 0 for cryptid in cryptids):
        raise ValidationError(
            "The source app executable is still encrypted (cryptid is not zero)"
        )
    if len(cryptids) != len(parse_macho(executable, executable_path)):
        warning(
            "One or more app slices have no LC_ENCRYPTION_INFO command; "
            "their decryption state could not be independently confirmed"
        )

    return (
        AppInfo(
            app_prefix=prefix,
            bundle_id=plist["CFBundleIdentifier"],
            version=plist["CFBundleShortVersionString"],
            executable=plist["CFBundleExecutable"],
        ),
        members,
    )


def parse_macho(data: bytes, label: str) -> list[MachOSlice]:
    layouts: list[MachOSlice] = []
    for slice_offset, slice_size in macho_slices(data, label):
        magic = data[slice_offset : slice_offset + 4]
        thin = {
            b"\xce\xfa\xed\xfe": ("<", False),
            b"\xcf\xfa\xed\xfe": ("<", True),
            b"\xfe\xed\xfa\xce": (">", False),
            b"\xfe\xed\xfa\xcf": (">", True),
        }.get(magic)
        if thin is None:
            raise ValidationError(f"Invalid Mach-O slice in {label}")
        endian, is_64 = thin
        header_size = 32 if is_64 else 28
        slice_end = slice_offset + slice_size
        if slice_offset + header_size > slice_end:
            raise ValidationError(f"Truncated Mach-O header in {label}")

        cpu_type = struct.unpack_from(f"{endian}I", data, slice_offset + 4)[0]
        file_type = struct.unpack_from(f"{endian}I", data, slice_offset + 12)[0]
        ncmds, sizeofcmds = struct.unpack_from(f"{endian}II", data, slice_offset + 16)
        commands_end = slice_offset + header_size + sizeofcmds
        if ncmds < 1 or commands_end > slice_end:
            raise ValidationError(f"Invalid Mach-O load-command table in {label}")

        commands: list[tuple[int, int, int]] = []
        cursor = slice_offset + header_size
        for _ in range(ncmds):
            if cursor + 8 > commands_end:
                raise ValidationError(f"Truncated Mach-O load command in {label}")
            command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
            if command_size < 8 or cursor + command_size > commands_end:
                raise ValidationError(f"Invalid Mach-O load command size in {label}")
            commands.append((command, cursor, command_size))
            cursor += command_size
        if cursor != commands_end:
            raise ValidationError(f"Mach-O load-command size mismatch in {label}")
        layouts.append(
            MachOSlice(
                offset=slice_offset,
                size=slice_size,
                endian=endian,
                is_64=is_64,
                cpu_type=cpu_type,
                file_type=file_type,
                commands=tuple(commands),
            )
        )
    return layouts


def validate_macho_kind(data: bytes, label: str, expected_file_type: int) -> None:
    layouts = parse_macho(data, label)
    for layout in layouts:
        if layout.cpu_type != 0x0100000C:
            raise ValidationError(f"{label} contains a non-arm64 Mach-O slice")
        if layout.file_type != expected_file_type:
            raise ValidationError(
                f"{label} has Mach-O file type {layout.file_type}, "
                f"expected {expected_file_type}"
            )
    sections = macho_sections(data, label, "__TEXT", "__text")
    if any(not section for section in sections):
        raise ValidationError(f"{label} contains an empty __TEXT,__text section")


def macho_cryptids(data: bytes, label: str) -> list[int]:
    cryptids: list[int] = []
    for layout in parse_macho(data, label):
        slice_cryptids: list[int] = []
        for command, cursor, command_size in layout.commands:
            if command in (0x21, 0x2C):
                if command_size < 20:
                    raise ValidationError(f"Invalid encryption load command in {label}")
                slice_cryptids.append(
                    struct.unpack_from(f"{layout.endian}I", data, cursor + 16)[0]
                )
        if len(slice_cryptids) > 1:
            raise ValidationError(f"Duplicate encryption load commands in {label}")
        cryptids.extend(slice_cryptids)
    return cryptids


def command_string(
    data: bytes,
    layout: MachOSlice,
    cursor: int,
    command_size: int,
    label: str,
) -> str:
    if command_size < 12:
        raise ValidationError(f"Invalid string load command in {label}")
    string_offset = struct.unpack_from(f"{layout.endian}I", data, cursor + 8)[0]
    if string_offset < 12 or string_offset >= command_size:
        raise ValidationError(f"Invalid load-command string offset in {label}")
    raw = data[cursor + string_offset : cursor + command_size].split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"Invalid load-command string in {label}") from exc


def macho_dependencies(data: bytes, label: str) -> list[list[str]]:
    result: list[list[str]] = []
    for layout in parse_macho(data, label):
        dependencies = [
            command_string(data, layout, cursor, size, label)
            for command, cursor, size in layout.commands
            if command in DYLIB_COMMANDS
        ]
        result.append(dependencies)
    return result


def macho_rpaths(data: bytes, label: str) -> list[list[str]]:
    result: list[list[str]] = []
    for layout in parse_macho(data, label):
        rpaths = [
            command_string(data, layout, cursor, size, label)
            for command, cursor, size in layout.commands
            if command == 0x8000001C
        ]
        result.append(rpaths)
    return result


def substrate_paths(data: bytes, label: str) -> tuple[tuple[str, ...], ...]:
    expected = {ROOTFUL_SUBSTRATE_PATH, INJECTED_SUBSTRATE_PATH}
    return tuple(
        tuple(path for path in dependencies if path in expected)
        for dependencies in macho_dependencies(data, label)
    )


def fixed_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", "strict")


def macho_section_records(
    data: bytes, label: str
) -> list[list[tuple[str, str, bytes, bytes]]]:
    result: list[list[tuple[str, str, bytes, bytes]]] = []
    for layout in parse_macho(data, label):
        records: list[tuple[str, str, bytes, bytes]] = []
        for command, cursor, command_size in layout.commands:
            expected_command = 0x19 if layout.is_64 else 0x1
            if command != expected_command:
                continue
            segment_header_size = 72 if layout.is_64 else 56
            section_size = 80 if layout.is_64 else 68
            if command_size < segment_header_size:
                raise ValidationError(f"Invalid segment command in {label}")
            current_segment = fixed_string(data[cursor + 8 : cursor + 24])
            nsects_offset = cursor + (64 if layout.is_64 else 48)
            nsects = struct.unpack_from(f"{layout.endian}I", data, nsects_offset)[0]
            if segment_header_size + nsects * section_size > command_size:
                raise ValidationError(f"Invalid section table in {label}")
            for index in range(nsects):
                section_cursor = cursor + segment_header_size + index * section_size
                current_section = fixed_string(
                    data[section_cursor : section_cursor + 16]
                )
                section_segment = fixed_string(
                    data[section_cursor + 16 : section_cursor + 32]
                )
                if layout.is_64:
                    size = struct.unpack_from(
                        f"{layout.endian}Q", data, section_cursor + 40
                    )[0]
                    file_offset = struct.unpack_from(
                        f"{layout.endian}I", data, section_cursor + 48
                    )[0]
                    flags_offset = section_cursor + 64
                else:
                    size, file_offset = struct.unpack_from(
                        f"{layout.endian}II", data, section_cursor + 36
                    )
                    flags_offset = section_cursor + 56
                flags = struct.unpack_from(f"{layout.endian}I", data, flags_offset)[0]
                section_type = flags & 0xFF
                if section_type in (0x1, 0xC, 0x12):
                    contents = b""
                else:
                    start = layout.offset + file_offset
                    end = start + size
                    if start < layout.offset or end > layout.offset + layout.size:
                        raise ValidationError(f"Invalid section bounds in {label}")
                    contents = data[start:end]
                if current_segment != section_segment:
                    raise ValidationError(f"Mismatched section segment name in {label}")
                section_header = data[section_cursor : section_cursor + section_size]
                records.append(
                    (current_segment, current_section, section_header, contents)
                )
        if not records:
            raise ValidationError(f"No Mach-O sections found in {label}")
        result.append(records)
    return result


def macho_sections(
    data: bytes, label: str, segment_name: str, section_name: str
) -> list[bytes]:
    result: list[bytes] = []
    for records in macho_section_records(data, label):
        matches = [
            contents
            for segment, section, _, contents in records
            if segment == segment_name and section == section_name
        ]
        if len(matches) != 1:
            raise ValidationError(
                f"Expected one {segment_name},{section_name} section per slice in {label}"
            )
        result.append(matches[0])
    return result


def text_digests(data: bytes, label: str) -> list[str]:
    return [
        sha256(section) for section in macho_sections(data, label, "__TEXT", "__text")
    ]


def section_manifest_digest(data: bytes, label: str) -> str:
    digest = hashlib.sha256()
    for slice_index, records in enumerate(macho_section_records(data, label)):
        for segment, section, header, contents in records:
            digest.update(str(slice_index).encode("ascii"))
            digest.update(b"\0")
            digest.update(segment.encode("ascii"))
            digest.update(b"\0")
            digest.update(section.encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(header).digest())
            digest.update(hashlib.sha256(contents).digest())
    return digest.hexdigest()


def first_file_data_offset(data: bytes, layout: MachOSlice, label: str) -> int:
    offsets: list[int] = []
    for command, cursor, command_size in layout.commands:
        expected_command = 0x19 if layout.is_64 else 0x1
        if command != expected_command:
            continue
        segment_header_size = 72 if layout.is_64 else 56
        section_size = 80 if layout.is_64 else 68
        if command_size < segment_header_size:
            raise ValidationError(f"Invalid segment command in {label}")
        nsects_offset = cursor + (64 if layout.is_64 else 48)
        nsects = struct.unpack_from(f"{layout.endian}I", data, nsects_offset)[0]
        if segment_header_size + nsects * section_size > command_size:
            raise ValidationError(f"Invalid section table in {label}")
        for index in range(nsects):
            section_cursor = cursor + segment_header_size + index * section_size
            if layout.is_64:
                size = struct.unpack_from(
                    f"{layout.endian}Q", data, section_cursor + 40
                )[0]
                file_offset = struct.unpack_from(
                    f"{layout.endian}I", data, section_cursor + 48
                )[0]
                flags_offset = section_cursor + 64
            else:
                size, file_offset = struct.unpack_from(
                    f"{layout.endian}II", data, section_cursor + 36
                )
                flags_offset = section_cursor + 56
            section_type = (
                struct.unpack_from(f"{layout.endian}I", data, flags_offset)[0] & 0xFF
            )
            if size and section_type not in (0x1, 0xC, 0x12):
                offsets.append(file_offset)

    if not offsets:
        raise ValidationError(f"No file-backed Mach-O sections found in {label}")
    result = min(offsets)
    header_size = 32 if layout.is_64 else 28
    command_end = header_size + sum(size for _, _, size in layout.commands)
    if result < command_end or result > layout.size:
        raise ValidationError(f"Invalid first section offset in {label}")
    return layout.offset + result


def continuity_command(
    data: bytes,
    layout: MachOSlice,
    command: int,
    cursor: int,
    command_size: int,
    label: str,
) -> bytes:
    if command not in DYLIB_COMMANDS:
        return data[cursor : cursor + command_size]
    if command_size < 24:
        raise ValidationError(f"Invalid dylib load command in {label}")
    path = command_string(data, layout, cursor, command_size, label)
    if path in {ROOTFUL_SUBSTRATE_PATH, INJECTED_SUBSTRATE_PATH}:
        path = INJECTED_SUBSTRATE_PATH
    return (
        struct.pack(">I", command)
        + data[cursor + 12 : cursor + 24]
        + path.encode("utf-8")
        + b"\0"
    )


def macho_continuity_digest(data: bytes, label: str) -> str:
    """Hash every byte while permitting only Cyan's substrate-path rewrite."""

    normalized = bytearray(data)
    command_records: list[list[bytes]] = []
    for layout in parse_macho(data, label):
        header_size = 32 if layout.is_64 else 28
        command_start = layout.offset + header_size
        content_start = first_file_data_offset(data, layout, label)
        normalized[layout.offset + 16 : layout.offset + 24] = b"\0" * 8
        normalized[command_start:content_start] = b"\0" * (
            content_start - command_start
        )
        command_records.append(
            [
                continuity_command(
                    data,
                    layout,
                    command,
                    cursor,
                    command_size,
                    label,
                )
                for command, cursor, command_size in layout.commands
            ]
        )

    digest = hashlib.sha256(normalized)
    for slice_index, records in enumerate(command_records):
        digest.update(struct.pack(">I", slice_index))
        for record in records:
            digest.update(struct.pack(">I", len(record)))
            digest.update(record)
    return digest.hexdigest()


def macho_slices(data: bytes, label: str) -> list[tuple[int, int]]:
    if len(data) < 4:
        raise ValidationError(f"{label} is too small to be a Mach-O binary")
    magic = data[:4]
    if magic in {
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }:
        return [(0, len(data))]

    fat = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }.get(magic)
    if fat is None:
        raise ValidationError(f"{label} is not a Mach-O binary")
    endian, is_64 = fat
    if len(data) < 8:
        raise ValidationError(f"Truncated fat Mach-O header in {label}")
    count = struct.unpack_from(f"{endian}I", data, 4)[0]
    if count < 1 or count > 32:
        raise ValidationError(f"Invalid fat Mach-O slice count in {label}: {count}")
    entry_size = 32 if is_64 else 20
    if 8 + count * entry_size > len(data):
        raise ValidationError(f"Truncated fat Mach-O table in {label}")

    slices: list[tuple[int, int]] = []
    table_end = 8 + count * entry_size
    for index in range(count):
        cursor = 8 + index * entry_size
        if is_64:
            offset, size = struct.unpack_from(f"{endian}QQ", data, cursor + 8)
        else:
            offset, size = struct.unpack_from(f"{endian}II", data, cursor + 8)
        if size < 4 or offset < table_end or offset + size > len(data):
            raise ValidationError(f"Invalid fat Mach-O slice in {label}")
        slices.append((offset, size))
    ordered = sorted(slices)
    for (previous_offset, previous_size), (current_offset, _) in pairwise(ordered):
        if previous_offset + previous_size > current_offset:
            raise ValidationError(f"Overlapping fat Mach-O slices in {label}")
    return slices


def validate_version(
    actual: str, version: str, allow_unverified: bool, label: str
) -> None:
    expected = str(release(version)["youtube_version"])
    if actual == expected:
        return
    message = (
        f"{label} YouTube version {actual!r} is not the verified {expected!r} "
        f"pair for YTPlus {version}"
    )
    if allow_unverified:
        warning(message)
    else:
        raise ValidationError(message + "; enable the explicit override to continue")


def inspect_source_ipa(path: Path) -> AppInfo:
    try:
        with zipfile.ZipFile(path) as archive:
            app, members = top_level_app(archive)
            main_path = app.app_prefix + app.executable
            main_binary = archive.read(members[main_path])
            if any(
                "@rpath/YTLite.dylib" in dependencies
                for dependencies in macho_dependencies(main_binary, main_path)
            ):
                raise ValidationError("Source IPA is already injected with YTLite")
            forbidden_paths = {
                app.app_prefix + "Frameworks/YTLite.dylib",
                app.app_prefix + "YTLite.bundle/Info.plist",
            }
            if forbidden_paths & members.keys():
                raise ValidationError(
                    "Source IPA already contains YTLite payload files"
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"Cannot read source IPA: {exc}") from exc
    if app.bundle_id != OFFICIAL_BUNDLE_ID:
        raise ValidationError(
            f"Source IPA bundle ID must be {OFFICIAL_BUNDLE_ID!r}, got {app.bundle_id!r}"
        )
    return app


def validate_source_ipa(path: Path, version: str, allow_unverified: bool) -> None:
    release(version)
    app = inspect_source_ipa(path)
    validate_version(app.version, version, allow_unverified, "Source IPA")


def inspect_packaged_ipa(path: Path, bundle_id: str) -> PackagedInfo:
    validate_bundle_id(bundle_id)
    try:
        with zipfile.ZipFile(path) as archive:
            app, members = top_level_app(archive)
            dylib_path = app.app_prefix + "Frameworks/YTLite.dylib"
            bundle_prefix = app.app_prefix + "YTLite.bundle/"
            bundle_info_path = bundle_prefix + "Info.plist"
            ytlite_dylibs = [
                name
                for name in members
                if PurePosixPath(name).name.casefold() == "ytlite.dylib"
            ]
            ytlite_bundle_infos = [
                name
                for name in members
                if name.casefold().endswith("/ytlite.bundle/info.plist")
            ]
            if ytlite_dylibs != [dylib_path]:
                raise ValidationError(
                    "Packaged IPA does not contain exactly one YTLite.dylib at the expected path"
                )
            if ytlite_bundle_infos != [bundle_info_path]:
                raise ValidationError(
                    "Packaged IPA does not contain exactly one YTLite.bundle at the expected path"
                )

            dylib = archive.read(members[dylib_path])
            validate_macho_kind(dylib, dylib_path, 0x6)
            main_path = app.app_prefix + app.executable
            main_binary = archive.read(members[main_path])
            for dependencies in macho_dependencies(main_binary, main_path):
                if dependencies.count("@rpath/YTLite.dylib") != 1:
                    raise ValidationError(
                        "Main executable does not load exactly one @rpath/YTLite.dylib"
                    )
            for rpaths in macho_rpaths(main_binary, main_path):
                if "@executable_path/Frameworks" not in rpaths:
                    raise ValidationError(
                        "Main executable is missing the Frameworks runtime search path"
                    )

            required_bundle_paths = {
                bundle_info_path,
                bundle_prefix + "Assets.car",
                bundle_prefix + "en.lproj/Localizable.strings",
            }
            missing = sorted(required_bundle_paths - members.keys())
            if missing:
                raise ValidationError(
                    f"Packaged YTLite.bundle is missing: {', '.join(missing)}"
                )
            try:
                bundle_plist = plistlib.loads(archive.read(members[bundle_info_path]))
            except (plistlib.InvalidFileException, ValueError) as exc:
                raise ValidationError(
                    f"Cannot parse {bundle_info_path}: {exc}"
                ) from exc
            if (
                not isinstance(bundle_plist, dict)
                or bundle_plist.get("CFBundleIdentifier") != PACKAGE_ID
            ):
                raise ValidationError("Packaged YTLite.bundle has the wrong identity")

            bundle_files = {
                name: archive.read(info)
                for name, info in members.items()
                if name.startswith(bundle_prefix) and not info.is_dir()
            }
            packaged = PackagedInfo(
                app=app,
                dylib_digest=sha256(dylib),
                continuity_digest=macho_continuity_digest(dylib, dylib_path),
                substrate_paths=substrate_paths(dylib, dylib_path),
                text_digests=tuple(text_digests(dylib, dylib_path)),
                section_digest=section_manifest_digest(dylib, dylib_path),
                bundle_digest=tree_digest(bundle_files, bundle_prefix),
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"Cannot read packaged IPA: {exc}") from exc
    if app.bundle_id != bundle_id:
        raise ValidationError(
            f"Packaged IPA bundle ID mismatch: expected {bundle_id!r}, got {app.bundle_id!r}"
        )
    return packaged


def validate_packaged_ipa(
    path: Path,
    version: str,
    bundle_id: str,
    allow_unverified: bool,
) -> None:
    release(version)
    packaged = inspect_packaged_ipa(path, bundle_id)
    metadata = release(version)
    if packaged.dylib_digest != metadata["packaged_dylib_sha256"]:
        raise ValidationError(
            "Packaged YTLite binary does not match the pinned injector output"
        )
    if list(packaged.text_digests) != [metadata["text_sha256"]]:
        raise ValidationError(
            "Packaged YTLite code does not match the official release"
        )
    if packaged.section_digest != metadata["sections_sha256"]:
        raise ValidationError(
            "Packaged YTLite sections do not match the official release"
        )
    if packaged.bundle_digest != metadata["bundle_sha256"]:
        raise ValidationError(
            "Packaged YTLite resources do not match the official release"
        )
    validate_version(packaged.app.version, version, allow_unverified, "Packaged IPA")


def validate_custom_packaged_ipa(path: Path, bundle_id: str, deb_path: Path) -> None:
    _, reference_dylib, reference_bundle_digest = inspect_deb(
        deb_path.read_bytes(), str(deb_path)
    )
    packaged = inspect_packaged_ipa(path, bundle_id)
    reference_paths = substrate_paths(reference_dylib, "Reference YTLite.dylib")
    if any(
        len(paths) != 1
        or paths[0] not in {ROOTFUL_SUBSTRATE_PATH, INJECTED_SUBSTRATE_PATH}
        for paths in reference_paths
    ):
        raise ValidationError(
            "Reference YTLite.dylib must contain exactly one supported substrate dependency per slice"
        )
    if any(paths != (INJECTED_SUBSTRATE_PATH,) for paths in packaged.substrate_paths):
        raise ValidationError(
            "Packaged YTLite.dylib does not contain the expected injected substrate dependency"
        )
    if packaged.continuity_digest != macho_continuity_digest(
        reference_dylib, "Reference YTLite.dylib"
    ):
        raise ValidationError(
            "Packaged YTLite.dylib does not match the supplied custom DEB"
        )
    if packaged.bundle_digest != reference_bundle_digest:
        raise ValidationError(
            "Packaged YTLite.bundle does not match the supplied custom DEB"
        )


def validate_cyan(path: Path, version: str, bundle_id: str, display_name: str) -> None:
    release(version)
    try:
        with zipfile.ZipFile(path) as archive:
            members = zip_members(archive)
            required = ("config.json", "inject/ytplus.deb")
            missing = [name for name in required if name not in members]
            if missing:
                raise ValidationError(f"Cyan file is missing: {', '.join(missing)}")
            config = json.loads(archive.read(members["config.json"]))
            if not isinstance(config, dict):
                raise ValidationError("Cyan config is not a JSON object")
            if config.get("b") != bundle_id:
                raise ValidationError("Cyan config contains the wrong bundle ID")
            if config.get("n") != display_name:
                raise ValidationError("Cyan config contains the wrong display name")
            expected_flags = {
                "f": True,
                "remove_supported_devices": True,
                "no_watch": True,
                "remove_extensions": True,
            }
            for flag, expected in expected_flags.items():
                if config.get(flag) is not expected:
                    raise ValidationError(
                        f"Cyan config is missing required flag {flag}"
                    )
            validate_deb_bytes(
                archive.read(members["inject/ytplus.deb"]),
                version,
                "Embedded YTPlus DEB",
            )
            extension_paths = {
                "inject/OpenYoutubeSafariExtension.appex/Info.plist",
                "inject/OpenYoutubeSafariExtension.appex/OpenYouTubeSafariExtension",
            }
            missing_extension = sorted(extension_paths - members.keys())
            if missing_extension:
                raise ValidationError(
                    f"Cyan file is missing Safari extension files: {', '.join(missing_extension)}"
                )
            for name, info in members.items():
                if (
                    name.startswith("inject/")
                    and name.endswith(".deb")
                    and name != "inject/ytplus.deb"
                ):
                    reject_ytlite_collision(archive.read(info), name)
                if name != "inject/ytplus.deb" and (
                    PurePosixPath(name).name.casefold() == "ytlite.dylib"
                    or "ytlite.bundle"
                    in {part.casefold() for part in PurePosixPath(name).parts}
                ):
                    raise ValidationError(
                        f"Cyan file contains a colliding payload: {name}"
                    )
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise ValidationError(f"Cannot read Cyan file: {exc}") from exc


def validate_trollfools(path: Path, version: str) -> None:
    metadata = release(version)
    try:
        with zipfile.ZipFile(path) as archive:
            members = zip_members(archive)
            dylibs = [
                name
                for name in members
                if PurePosixPath(name).name.casefold() == "ytlite.dylib"
            ]
            bundle_infos = [
                name
                for name in members
                if name.casefold().endswith("ytlite.bundle/info.plist")
            ]
            if dylibs != ["YTLite.dylib"]:
                raise ValidationError(
                    "TrollFools zip does not contain exactly one root YTLite.dylib"
                )
            if bundle_infos != ["YTLite.bundle/Info.plist"]:
                raise ValidationError(
                    "TrollFools zip does not contain exactly one root YTLite.bundle"
                )
            dylib = archive.read(members["YTLite.dylib"])
            if sha256(dylib) != metadata["dylib_sha256"]:
                raise ValidationError(
                    "TrollFools YTLite.dylib is not an official release binary"
                )
            validate_macho_kind(dylib, "YTLite.dylib", 0x6)
            if text_digests(dylib, "YTLite.dylib") != [metadata["text_sha256"]]:
                raise ValidationError("TrollFools YTLite code is not official")
            bundle_prefix = "YTLite.bundle/"
            bundle_files = {
                name: archive.read(info)
                for name, info in members.items()
                if name.startswith(bundle_prefix) and not info.is_dir()
            }
            if tree_digest(bundle_files, bundle_prefix) != metadata["bundle_sha256"]:
                raise ValidationError("TrollFools YTLite.bundle is not official")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValidationError(f"Cannot read TrollFools zip: {exc}") from exc


def warning(message: str) -> None:
    print(f"::warning::{message}", file=sys.stderr)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    deb = commands.add_parser("deb", help="validate an official YTPlus DEB")
    deb.add_argument("--file", required=True, type=Path)
    deb.add_argument("--version", required=True)

    custom_deb = commands.add_parser(
        "custom-deb", help="validate the structure of a user-supplied YTPlus DEB"
    )
    custom_deb.add_argument("--file", required=True, type=Path)

    source = commands.add_parser("source-ipa", help="validate the supplied base IPA")
    source.add_argument("--file", required=True, type=Path)
    source.add_argument("--version", required=True)
    source.add_argument("--allow-unverified-version", action="store_true")

    custom_source = commands.add_parser(
        "custom-source-ipa", help="validate a base IPA without enforcing a version pair"
    )
    custom_source.add_argument("--file", required=True, type=Path)

    packaged = commands.add_parser("packaged-ipa", help="validate an injected IPA")
    packaged.add_argument("--file", required=True, type=Path)
    packaged.add_argument("--version", required=True)
    packaged.add_argument("--bundle-id", required=True)
    packaged.add_argument("--allow-unverified-version", action="store_true")

    custom_packaged = commands.add_parser(
        "custom-packaged-ipa",
        help="validate an injected IPA without enforcing a version pair",
    )
    custom_packaged.add_argument("--file", required=True, type=Path)
    custom_packaged.add_argument("--bundle-id", required=True)
    custom_packaged.add_argument(
        "--deb",
        required=True,
        type=Path,
        help="the exact custom DEB supplied to the injector",
    )

    cyan = commands.add_parser("cyan", help="validate a generated Cyan bundle")
    cyan.add_argument("--file", required=True, type=Path)
    cyan.add_argument("--version", required=True)
    cyan.add_argument("--bundle-id", required=True)
    cyan.add_argument("--display-name", required=True)

    trollfools = commands.add_parser("trollfools", help="validate a TrollFools zip")
    trollfools.add_argument("--file", required=True, type=Path)
    trollfools.add_argument("--version", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "deb":
            validate_deb_bytes(args.file.read_bytes(), args.version, str(args.file))
        elif args.command == "custom-deb":
            inspect_deb(args.file.read_bytes(), str(args.file))
        elif args.command == "source-ipa":
            validate_source_ipa(args.file, args.version, args.allow_unverified_version)
        elif args.command == "custom-source-ipa":
            inspect_source_ipa(args.file)
        elif args.command == "packaged-ipa":
            validate_packaged_ipa(
                args.file,
                args.version,
                args.bundle_id,
                args.allow_unverified_version,
            )
        elif args.command == "custom-packaged-ipa":
            validate_custom_packaged_ipa(args.file, args.bundle_id, args.deb)
        elif args.command == "cyan":
            validate_cyan(
                args.file,
                args.version,
                args.bundle_id,
                args.display_name,
            )
        elif args.command == "trollfools":
            validate_trollfools(args.file, args.version)
        else:  # pragma: no cover - argparse enforces the command set.
            raise AssertionError(args.command)
    except (OSError, UnicodeError, ValidationError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print(f"Validated {args.command}: {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
