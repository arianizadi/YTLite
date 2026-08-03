from __future__ import annotations

import importlib.util
import io
import plistlib
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("verify_build.py")
SPEC = importlib.util.spec_from_file_location("verify_build", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_build = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_build
SPEC.loader.exec_module(verify_build)


def load_command(command: int, value: str) -> bytes:
    encoded = value.encode() + b"\0"
    size = (24 + len(encoded) + 7) & ~7
    return (
        struct.pack("<IIIIII", command, size, 24, 0, 0, 0)
        + encoded
        + bytes(size - 24 - len(encoded))
    )


def rpath_command(value: str) -> bytes:
    encoded = value.encode() + b"\0"
    size = (12 + len(encoded) + 7) & ~7
    return (
        struct.pack("<III", 0x8000001C, size, 12)
        + encoded
        + bytes(size - 12 - len(encoded))
    )


def macho(
    cryptid: int | None = 0,
    *,
    file_type: int = 0x2,
    load_ytlite: bool = False,
    dependency: str | None = None,
) -> bytes:
    text = b"\xc0\x03\x5f\xd6"
    command_count = (
        1 + (cryptid is not None) + (2 if load_ytlite else 0) + (dependency is not None)
    )
    extra_commands = b""
    if cryptid is not None:
        extra_commands += struct.pack("<IIIIII", 0x2C, 24, 0, 0, cryptid, 0)
    if load_ytlite:
        extra_commands += load_command(0x80000018, "@rpath/YTLite.dylib")
        extra_commands += rpath_command("@executable_path/Frameworks")
    if dependency is not None:
        extra_commands += load_command(0xC, dependency)

    segment_size = 72 + 80
    commands_size = segment_size + len(extra_commands)
    text_offset = 32 + commands_size
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        segment_size,
        b"__TEXT",
        0,
        len(text),
        text_offset,
        len(text),
        5,
        5,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        0,
        len(text),
        text_offset,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        file_type,
        command_count,
        commands_size,
        0,
        0,
    )
    return header + segment + section + extra_commands + text


def source_ipa(path: Path, version: str = "20.42.3", cryptid: int = 0) -> None:
    info = {
        "CFBundleExecutable": "YouTube",
        "CFBundleIdentifier": verify_build.OFFICIAL_BUNDLE_ID,
        "CFBundleShortVersionString": version,
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(info))
        archive.writestr("Payload/YouTube.app/YouTube", macho(cryptid))


def packaged_ipa(
    path: Path,
    bundle_id: str = "com.example.youtube",
    dylib: bytes | None = None,
) -> None:
    info = {
        "CFBundleExecutable": "YouTube",
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": "20.42.3",
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(info))
        archive.writestr("Payload/YouTube.app/YouTube", macho(load_ytlite=True))
        archive.writestr(
            "Payload/YouTube.app/Frameworks/YTLite.dylib",
            dylib if dylib is not None else macho(None, file_type=0x6),
        )
        archive.writestr(
            "Payload/YouTube.app/YTLite.bundle/Info.plist",
            plistlib.dumps({"CFBundleIdentifier": verify_build.PACKAGE_ID}),
        )
        archive.writestr("Payload/YouTube.app/YTLite.bundle/Assets.car", b"assets")
        archive.writestr(
            "Payload/YouTube.app/YTLite.bundle/en.lproj/Localizable.strings",
            b"strings",
        )


class VerifyBuildTests(unittest.TestCase):
    def test_macho_encryption_state(self) -> None:
        self.assertEqual(verify_build.macho_cryptids(macho(0), "test"), [0])
        self.assertEqual(verify_build.macho_cryptids(macho(1), "test"), [1])

    def test_overlapping_fat_macho_slices_are_rejected(self) -> None:
        thin = macho()
        header_size = 8 + 2 * 20
        fat = struct.pack(">II", 0xCAFEBABE, 2)
        fat += struct.pack(">iiIII", 0x0100000C, 0, header_size, len(thin), 2)
        fat += struct.pack(">iiIII", 0x0100000C, 0, header_size, len(thin), 2)
        fat += thin
        with self.assertRaisesRegex(verify_build.ValidationError, "Overlapping"):
            verify_build.macho_slices(fat, "fat-test")

    def test_continuity_digest_allows_only_substrate_path_rewrite(self) -> None:
        original = macho(
            None,
            file_type=0x6,
            dependency=verify_build.ROOTFUL_SUBSTRATE_PATH,
        )
        old_path = verify_build.ROOTFUL_SUBSTRATE_PATH.encode() + b"\0"
        new_path = verify_build.INJECTED_SUBSTRATE_PATH.encode() + b"\0"
        injected = original.replace(
            old_path,
            new_path + bytes(len(old_path) - len(new_path)),
        )
        self.assertEqual(
            verify_build.macho_continuity_digest(original, "original"),
            verify_build.macho_continuity_digest(injected, "injected"),
        )

        tampered = bytearray(injected)
        tampered[-1] ^= 1
        self.assertNotEqual(
            verify_build.macho_continuity_digest(injected, "injected"),
            verify_build.macho_continuity_digest(bytes(tampered), "tampered"),
        )

    def test_source_ipa_accepts_verified_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "YouTube.ipa")
            source_ipa(path)
            verify_build.validate_source_ipa(path, "5.2b4", False)

    def test_source_ipa_rejects_unverified_pair_without_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "YouTube.ipa")
            source_ipa(path, version="20.32.4")
            with self.assertRaisesRegex(
                verify_build.ValidationError, "is not the verified"
            ):
                verify_build.validate_source_ipa(path, "5.2b4", False)
            verify_build.validate_source_ipa(path, "5.2b4", True)

    def test_source_ipa_rejects_encrypted_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "YouTube.ipa")
            source_ipa(path, cryptid=1)
            with self.assertRaisesRegex(verify_build.ValidationError, "encrypted"):
                verify_build.validate_source_ipa(path, "5.2b4", False)

    def test_packaged_ipa_contains_one_tweak_and_expected_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "YouTubePlus.ipa")
            packaged_ipa(path)
            verify_build.inspect_packaged_ipa(path, "com.example.youtube")

    def test_official_packaged_ipa_rejects_decoy_tweak_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "YouTubePlus.ipa")
            packaged_ipa(path)
            with self.assertRaisesRegex(
                verify_build.ValidationError, "binary does not match"
            ):
                verify_build.validate_packaged_ipa(
                    path,
                    "5.2b4",
                    "com.example.youtube",
                    False,
                )

    def test_official_packaged_ipa_rejects_modified_load_command(self) -> None:
        original_dylib = macho(None, file_type=0x6, load_ytlite=True)
        tampered_dylib = original_dylib.replace(b"YTLite.dylib", b"EvilXX.dylib")
        self.assertNotEqual(original_dylib, tampered_dylib)

        with tempfile.TemporaryDirectory() as directory:
            original_path = Path(directory, "original.ipa")
            tampered_path = Path(directory, "tampered.ipa")
            packaged_ipa(original_path, dylib=original_dylib)
            packaged_ipa(tampered_path, dylib=tampered_dylib)
            original = verify_build.inspect_packaged_ipa(
                original_path, "com.example.youtube"
            )
            tampered = verify_build.inspect_packaged_ipa(
                tampered_path, "com.example.youtube"
            )
            self.assertEqual(original.section_digest, tampered.section_digest)
            self.assertNotEqual(original.dylib_digest, tampered.dylib_digest)

            verify_build.RELEASES["test"] = {
                "packaged_dylib_sha256": original.dylib_digest,
                "text_sha256": original.text_digests[0],
                "sections_sha256": original.section_digest,
                "bundle_sha256": original.bundle_digest,
                "youtube_version": original.app.version,
            }
            try:
                verify_build.validate_packaged_ipa(
                    original_path,
                    "test",
                    "com.example.youtube",
                    False,
                )
                with self.assertRaisesRegex(
                    verify_build.ValidationError, "pinned injector output"
                ):
                    verify_build.validate_packaged_ipa(
                        tampered_path,
                        "test",
                        "com.example.youtube",
                        False,
                    )
            finally:
                del verify_build.RELEASES["test"]

    def test_official_deb_rejects_modified_bytes_before_parsing(self) -> None:
        with self.assertRaisesRegex(verify_build.ValidationError, "size mismatch"):
            verify_build.validate_deb_bytes(b"modified", "5.2b4", "test.deb")

    def test_unsupported_release_fails_closed(self) -> None:
        with self.assertRaisesRegex(verify_build.ValidationError, "Unsupported"):
            verify_build.release("5.2.3")

    def test_unsafe_archive_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_build.ValidationError, "Unsafe"):
            verify_build.safe_archive_name("../payload")

    def test_noncanonical_archive_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(verify_build.ValidationError, "Unsafe"):
            verify_build.safe_archive_name("Payload/App.app/./file")

    def test_zip_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "symlink.ipa")
            link = zipfile.ZipInfo("Payload/YouTube.app/escape")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(link, "../../outside")
            with (
                zipfile.ZipFile(path) as archive,
                self.assertRaisesRegex(
                    verify_build.ValidationError, "Unsupported zip member"
                ),
            ):
                verify_build.zip_members(archive)

    def test_tar_symlink_is_rejected(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            link = tarfile.TarInfo("Library/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)
        with self.assertRaisesRegex(
            verify_build.ValidationError, "links and devices are forbidden"
        ):
            verify_build.tar_members(buffer.getvalue(), "test")


if __name__ == "__main__":
    unittest.main()
