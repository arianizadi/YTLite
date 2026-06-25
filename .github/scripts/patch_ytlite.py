#!/usr/bin/env python3
"""
Patch YTLite 5.2.1 paywall/donation dispatch sites.

YTLite guards selected YTPSettingsBuilder methods with an obfuscated
flag-based dispatch. At each method entry, the binary loads a flag, compares it
with zero, then uses `cset wN, eq` to choose a jump-table entry. This script
flips the required `cset ..., eq` instructions to `cset ..., ne`.

Supported layouts:
    - iphoneos-arm64.deb rootless layout
    - iphoneos-arm64e.deb layout

Usage:
    python3 patch_ytlite.py <path_to_ytlite.dylib_or_deb>
"""

import os
import shutil
import subprocess
import sys
import tempfile


PATCH_BYTE_INDEX = 1  # byte at offset+1: 0x17 (eq) -> 0x07 (ne)
EQ_CONDITION = 0x17
NE_CONDITION = 0x07


# File offset == virtual address for these YTLite binaries (__TEXT at fileoff 0).
# Each site is validated as: ldar, cmp #0, cset ..., eq/ne.
PATCH_SETS = {
    "YTLite 5.2.1 iphoneos-arm64 rootless": [
        ("YTPSettingsBuilder.contribsTable", 0x0015C4D4),
        ("YTPSettingsBuilder.thanksTable", 0x00164928),
        ("YTPSettingsBuilder.creditsSection", 0x001677D0),
        ("YTPSettingsBuilder.showDonationSheet:", 0x00169178),
    ],
    "YTLite 5.2.1 iphoneos-arm64e": [
        ("YTPSettingsBuilder.contribsTable", 0x0015C118),
        ("YTPSettingsBuilder.thanksTable", 0x00164604),
        ("YTPSettingsBuilder.creditsSection", 0x001674D4),
        ("YTPSettingsBuilder.showDonationSheet:", 0x00168E34),
    ],
}


def patch_dylib(dylib_path: str):
    """Patch the YTLite dylib in-place.

    Returns (patched_count, total_required_sites, layout_name).
    Raises RuntimeError if the dylib does not match a supported layout.
    """
    if not os.path.exists(dylib_path):
        raise RuntimeError(f"File not found: {dylib_path}")

    fd = os.open(dylib_path, os.O_RDWR)
    try:
        layout_name, sites, site_states = _select_patch_set(fd)
        print(f"  Matched layout: {layout_name}")

        patched = 0
        already_patched = 0
        for method_name, offset in sites:
            state = site_states[offset]
            if state == "already_patched":
                print(f"  SKIP: {method_name} @ 0x{offset:08x} already patched")
                already_patched += 1
                continue

            os.pwrite(fd, bytes([NE_CONDITION]), offset + PATCH_BYTE_INDEX)
            new_state, message = _validate_site(fd, offset)
            if new_state != "already_patched":
                raise RuntimeError(
                    f"Write verification failed for {method_name} @ 0x{offset:08x}: {message}"
                )

            print(f"  PATCH: {method_name} @ 0x{offset:08x} eq -> ne")
            patched += 1
    finally:
        os.close(fd)

    return patched, len(sites), layout_name, already_patched


def extract_and_patch_deb(deb_path: str) -> str:
    """Extract a .deb, find YTLite.dylib, patch it, and repack it."""
    work_dir = tempfile.mkdtemp(prefix="ytlite_patch_")
    try:
        if shutil.which("dpkg-deb") is not None:
            return _patch_deb_dpkg(deb_path, work_dir)
        return _patch_deb_ar(deb_path, work_dir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _patch_deb_dpkg(deb_path: str, work_dir: str) -> str:
    """Extract and repack using dpkg-deb."""
    extract_dir = os.path.join(work_dir, "extracted")
    os.makedirs(extract_dir)

    subprocess.run(["dpkg-deb", "-R", deb_path, extract_dir], check=True)

    dylib_path = _find_dylib(extract_dir)
    patched, total, layout_name, already_patched = patch_dylib(dylib_path)
    print(
        f"  Validated {total}/{total} required dispatch sites "
        f"({patched} patched, {already_patched} already patched)"
    )

    output_deb = _patched_deb_path(deb_path)
    subprocess.run(["dpkg-deb", "-b", extract_dir, output_deb], check=True)
    shutil.move(output_deb, deb_path)
    print(f"  Repacked {layout_name}")
    return deb_path


def _patch_deb_ar(deb_path: str, work_dir: str) -> str:
    """Extract and repack using ar + tar when dpkg-deb is unavailable."""
    subprocess.run(["ar", "x", deb_path], cwd=work_dir, check=True)

    data_tar_name = None
    control_tar_name = None
    for name in os.listdir(work_dir):
        if name.startswith("data.tar"):
            data_tar_name = name
        elif name.startswith("control.tar"):
            control_tar_name = name

    if not data_tar_name:
        raise RuntimeError("No data.tar found in deb")
    if not control_tar_name:
        raise RuntimeError("No control.tar found in deb")

    data_tar_path = os.path.join(work_dir, data_tar_name)
    extract_dir = os.path.join(work_dir, "data")
    os.makedirs(extract_dir)

    extract_cmd = ["tar", "xf", data_tar_path, "-C", extract_dir]
    if data_tar_name.endswith(".lzma"):
        extract_cmd = ["tar", "--lzma", "-xf", data_tar_path, "-C", extract_dir]
    elif data_tar_name.endswith(".xz"):
        extract_cmd = ["tar", "--xz", "-xf", data_tar_path, "-C", extract_dir]
    elif data_tar_name.endswith(".gz"):
        extract_cmd = ["tar", "-xzf", data_tar_path, "-C", extract_dir]

    subprocess.run(extract_cmd, check=True)

    dylib_path = _find_dylib(extract_dir)
    patched, total, layout_name, already_patched = patch_dylib(dylib_path)
    print(
        f"  Validated {total}/{total} required dispatch sites "
        f"({patched} patched, {already_patched} already patched)"
    )

    ext = ""
    flag = None
    if data_tar_name.endswith(".lzma"):
        ext = ".lzma"
        flag = "--lzma"
    elif data_tar_name.endswith(".xz"):
        ext = ".xz"
        flag = "--xz"
    elif data_tar_name.endswith(".gz"):
        ext = ".gz"
        flag = "-z"

    new_data_tar_name = "data.tar" + ext
    new_data_tar = os.path.join(work_dir, new_data_tar_name)
    if flag:
        subprocess.run(["tar", flag, "-cf", new_data_tar, "."], cwd=extract_dir, check=True)
    else:
        subprocess.run(["tar", "-cf", new_data_tar, "."], cwd=extract_dir, check=True)

    output_deb = os.path.abspath(_patched_deb_path(deb_path))
    subprocess.run(
        ["ar", "rcs", output_deb, "debian-binary", control_tar_name, new_data_tar_name],
        cwd=work_dir,
        check=True,
    )
    shutil.move(output_deb, deb_path)
    print(f"  Repacked {layout_name}")
    return deb_path


def _select_patch_set(fd):
    matches = []
    failures = {}

    for layout_name, sites in PATCH_SETS.items():
        site_states = {}
        site_failures = []
        for method_name, offset in sites:
            state, message = _validate_site(fd, offset)
            if state in ("needs_patch", "already_patched"):
                site_states[offset] = state
            else:
                site_failures.append(f"{method_name} @ 0x{offset:08x}: {message}")

        if site_failures:
            failures[layout_name] = site_failures
        else:
            matches.append((layout_name, sites, site_states))

    if len(matches) == 1:
        return matches[0]

    if len(matches) > 1:
        names = ", ".join(match[0] for match in matches)
        raise RuntimeError(f"Ambiguous YTLite layout; matched multiple patch sets: {names}")

    details = []
    for layout_name, site_failures in failures.items():
        details.append(f"  {layout_name}:")
        details.extend(f"    - {failure}" for failure in site_failures)
    raise RuntimeError("Unsupported YTLite dylib layout. Validation failures:\n" + "\n".join(details))


def _validate_site(fd, offset: int):
    ldar = os.pread(fd, 4, offset - 8)
    cmp_zero = os.pread(fd, 4, offset - 4)
    cset = os.pread(fd, 4, offset)

    if len(ldar) != 4 or not _is_ldar_word(ldar):
        return "invalid", f"expected ldar wN at 0x{offset - 8:08x}, got {_format_bytes(ldar)}"
    if len(cmp_zero) != 4 or not _is_cmp_zero_word(cmp_zero):
        return "invalid", f"expected cmp wN, #0 at 0x{offset - 4:08x}, got {_format_bytes(cmp_zero)}"
    if len(cset) != 4 or not _is_cset_eq_or_ne(cset):
        return "invalid", f"expected cset wN, eq/ne at 0x{offset:08x}, got {_format_bytes(cset)}"

    if cset[PATCH_BYTE_INDEX] == EQ_CONDITION:
        return "needs_patch", _format_bytes(cset)
    if cset[PATCH_BYTE_INDEX] == NE_CONDITION:
        return "already_patched", _format_bytes(cset)

    return "invalid", f"unexpected condition byte in cset: {_format_bytes(cset)}"


def _is_ldar_word(data: bytes) -> bool:
    # ldar w8/w9, [xN] encodes as ?? fd df 88 in the verified sites.
    return len(data) == 4 and data[1:] == b"\xfd\xdf\x88"


def _is_cmp_zero_word(data: bytes) -> bool:
    # cmp w8/w9, #0 encodes as 1f/3f 01 00 71 in the verified sites.
    return len(data) == 4 and data[0] in (0x1F, 0x3F) and data[1:] == b"\x01\x00\x71"


def _is_cset_eq_or_ne(data: bytes) -> bool:
    # cset w8/w9, eq/ne encodes as e8/e9 17/07 9f 1a in the verified sites.
    return (
        len(data) == 4
        and data[0] in (0xE8, 0xE9)
        and data[PATCH_BYTE_INDEX] in (EQ_CONDITION, NE_CONDITION)
        and data[2:] == b"\x9f\x1a"
    )


def _find_dylib(extract_dir: str) -> str:
    """Find YTLite.dylib in an extracted deb directory."""
    for root, _dirs, files in os.walk(extract_dir):
        for name in files:
            if name == "YTLite.dylib":
                dylib_path = os.path.join(root, name)
                print(f"  Found dylib: {dylib_path}")
                return dylib_path
    raise RuntimeError("YTLite.dylib not found in deb")


def _patched_deb_path(deb_path: str) -> str:
    if deb_path.endswith(".deb"):
        return deb_path[:-4] + "_patched.deb"
    return deb_path + "_patched.deb"


def _format_bytes(data: bytes) -> str:
    return data.hex() if data else "<no bytes>"


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: patch_ytlite.py <path_to_dylib_or_deb>", file=sys.stderr)
        return 1

    target = sys.argv[1]

    try:
        if target.endswith(".deb"):
            print(f"Patching deb: {target}")
            extract_and_patch_deb(target)
            print(f"Done! Patched deb: {target}")
        elif target.endswith(".dylib"):
            print(f"Patching dylib: {target}")
            patched, total, layout_name, already_patched = patch_dylib(target)
            print(
                f"Done! {layout_name}: validated {total}/{total} required dispatch sites "
                f"({patched} patched, {already_patched} already patched)"
            )
        else:
            print(f"ERROR: Expected .dylib or .deb file, got: {target}", file=sys.stderr)
            return 1
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
