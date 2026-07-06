from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import checksum_ok, fix_header_checksum, verify


BASE_VA = 0x81BF6A28
PATCHES = {
    # Replace `jalr $v1` and its delay slot after GUI+0x834 with:
    #   move $v0, $zero
    #   nop
    0x81C510CC: bytes.fromhex("21100000 00000000"),
    0x81C511B0: bytes.fromhex("21100000 00000000"),
}


def patch_no834(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())
    for va, patch in PATCHES.items():
        off = va - BASE_VA
        if off < 0 or off + len(patch) > len(data):
            raise ValueError(f"patch VA 0x{va:08x} maps outside file at 0x{off:x}")
        original = data[off : off + len(patch)]
        if original[:4] != bytes.fromhex("09f86000"):
            raise ValueError(
                f"unexpected instruction at VA 0x{va:08x}: {original[:4].hex()}"
            )
        data[off : off + len(patch)] = patch
    fix_header_checksum(data)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    if not checksum_ok(data):
        raise ValueError("patched BDA checksum verification failed")


def main() -> None:
    ap = argparse.ArgumentParser(description="Patch Mission BDA GUI+0x834 call sites to no-op.")
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ns = ap.parse_args()
    patch_no834(ns.src, ns.dst)
    print(verify(ns.dst.read_bytes()))


if __name__ == "__main__":
    main()
