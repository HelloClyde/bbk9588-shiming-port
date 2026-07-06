from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import fix_header_checksum, verify
from mission_build_direct_compat import build as build_direct
from mission_build_gui_table_shim import addiu, bne, jal, jr, li_addr, lw, nop, ori, sw


BDA_BASE = 0x81BF6A28
PROBE_VA = 0x81C8BE68
PROBE_OFF = 0x95440
HOOK_4F474 = 0x81C16398
TARGET_4F474 = 0x81C4F474


def write_blob(data: bytearray, va: int, blob: bytes) -> None:
    off = va - BDA_BASE
    data[off : off + len(blob)] = blob


def build_wrapper(loop_count: int) -> bytes:
    code = bytearray()
    code += addiu("sp", "sp", -0x30)
    code += sw("ra", 0x2C, "sp")
    code += sw("a0", 0x28, "sp")
    code += sw("a1", 0x24, "sp")
    code += sw("a2", 0x20, "sp")
    code += sw("a3", 0x1C, "sp")
    code += li_addr("t0", loop_count)
    loop_pc = PROBE_VA + len(code)
    code += addiu("t0", "t0", -1)
    code += bne("t0", "zero", loop_pc + 4, loop_pc)
    code += nop()
    code += lw("a0", 0x28, "sp")
    code += lw("a1", 0x24, "sp")
    code += lw("a2", 0x20, "sp")
    code += lw("a3", 0x1C, "sp")
    code += jal(TARGET_4F474)
    code += nop()
    code += lw("ra", 0x2C, "sp")
    code += jr("ra")
    code += addiu("sp", "sp", 0x30)
    return bytes(code)


def build(input_path: Path, output_path: Path, *, loop_count: int, skip_config_load: bool) -> None:
    temp = output_path.with_suffix(".tmp.bda")
    build_direct(input_path, temp, skip_config_load=skip_config_load)
    data = bytearray(temp.read_bytes())
    temp.unlink()

    wrapper = build_wrapper(loop_count)
    cave = data[PROBE_OFF : PROBE_OFF + len(wrapper)]
    if any(cave):
        raise SystemExit(f"probe cave at 0x{PROBE_OFF:x} is not empty for 0x{len(wrapper):x} bytes")
    data[PROBE_OFF : PROBE_OFF + len(wrapper)] = wrapper
    write_blob(data, HOOK_4F474, jal(PROBE_VA))
    fix_header_checksum(data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    print(f"output={output_path}")
    print(f"hook=0x{HOOK_4F474:08x} target=0x{TARGET_4F474:08x} wrapper=0x{PROBE_VA:08x} loop_count=0x{loop_count:x}")
    print(verify(data))


def main() -> None:
    ap = argparse.ArgumentParser(description="Build Mission compatibility BDA with a timing shim before 0x81c4f474.")
    ap.add_argument("--input", type=Path, default=Path("build") / "使命_9588_std95f8_h1shield_cat4.bda")
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--loop-count", type=lambda text: int(text, 0), default=0x200000)
    ap.add_argument("--skip-config-load", action="store_true")
    ns = ap.parse_args()
    build(ns.input, ns.output, loop_count=ns.loop_count, skip_config_load=ns.skip_config_load)


if __name__ == "__main__":
    main()
