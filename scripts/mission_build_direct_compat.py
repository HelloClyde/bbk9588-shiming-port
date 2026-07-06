from __future__ import annotations

import argparse
import struct
from pathlib import Path

from bda_header import fix_header_checksum, verify


BDA_BASE = 0x81BF6A28
NOP = b"\0\0\0\0"
LI_V0_1 = struct.pack("<I", 0x24020001)
JR_RA = struct.pack("<I", 0x03E00008)


GUI_INIT_CALL_SITES = (
    # 9588 has GUI+0x7fc/+0x800 as return stubs, while S1 uses them during
    # the pet-manager-to-main transition. Skipping the three calls is the
    # narrowest patch that preserves GUI+0x7e0, which is required for the pet UI.
    0x81C15B7C,
    0x81C15B80,
    0x81C15BA0,
    0x81C15BA4,
    0x81C15BEC,
    0x81C15BF0,
)

CONFIG_LOAD_FUNC = 0x81C16464


def va_to_off(va: int) -> int:
    return va - BDA_BASE


def patch_word(data: bytearray, va: int, blob: bytes) -> None:
    off = va_to_off(va)
    if off < 0 or off + len(blob) > len(data):
        raise ValueError(f"VA 0x{va:08x} maps outside file")
    data[off : off + len(blob)] = blob


def build(input_path: Path, output_path: Path, *, skip_config_load: bool) -> None:
    data = bytearray(input_path.read_bytes())

    for va in GUI_INIT_CALL_SITES:
        patch_word(data, va, NOP)

    if skip_config_load:
        patch_word(data, CONFIG_LOAD_FUNC, LI_V0_1 + JR_RA + NOP)

    fix_header_checksum(data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

    print(f"output={output_path}")
    print("gui_init_call_sites=" + ",".join(f"0x{va:08x}" for va in GUI_INIT_CALL_SITES))
    print(f"skip_config_load={skip_config_load}")
    print(verify(data))


def main() -> None:
    ap = argparse.ArgumentParser(description="Build direct-patched Mission 9588 compatibility BDA.")
    ap.add_argument("--input", type=Path, default=Path("build") / "使命_9588_std95f8_h1shield_cat4.bda")
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--skip-config-load", action="store_true")
    ns = ap.parse_args()

    build(ns.input, ns.output, skip_config_load=ns.skip_config_load)


if __name__ == "__main__":
    main()
