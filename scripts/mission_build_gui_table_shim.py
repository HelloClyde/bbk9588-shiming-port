from __future__ import annotations

import argparse
import struct
from pathlib import Path

from bda_header import fix_header_checksum, verify


BDA_BASE = 0x81BF6A28
HOOK_VA = 0x81C0018C
SHIM_VA = 0x81C8BE68
SHIM_OFF = 0x95440
GUI_GLOBAL = 0x81C9B6A4
MEM_GLOBAL = 0x81C9B6B0
GUI_COPY = 0x81D4C000
GUI_COPY_SIZE = 0x850


REG = {
    "zero": 0,
    "at": 1,
    "v0": 2,
    "v1": 3,
    "a0": 4,
    "a1": 5,
    "a2": 6,
    "a3": 7,
    "t0": 8,
    "t1": 9,
    "t2": 10,
    "t3": 11,
    "t4": 12,
    "sp": 29,
    "ra": 31,
}


def r(name: str) -> int:
    return REG[name]


def word(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def r_type(rs: int, rt: int, rd: int, shamt: int, funct: int) -> bytes:
    return word((rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct)


def addu(rd: str, rs: str, rt: str) -> bytes:
    return r_type(r(rs), r(rt), r(rd), 0, 0x21)


def i_type(op: int, rs: int, rt: int, imm: int) -> bytes:
    return word((op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF))


def lui(rt: str, imm: int) -> bytes:
    return i_type(0x0F, 0, r(rt), imm)


def ori(rt: str, rs: str, imm: int) -> bytes:
    return i_type(0x0D, r(rs), r(rt), imm)


def addiu(rt: str, rs: str, imm: int) -> bytes:
    return i_type(0x09, r(rs), r(rt), imm)


def lw(rt: str, imm: int, rs: str) -> bytes:
    return i_type(0x23, r(rs), r(rt), imm)


def sw(rt: str, imm: int, rs: str) -> bytes:
    return i_type(0x2B, r(rs), r(rt), imm)


def sb(rt: str, imm: int, rs: str) -> bytes:
    return i_type(0x28, r(rs), r(rt), imm)


def beq(rs: str, rt: str, pc: int, target: int) -> bytes:
    delta = (target - (pc + 4)) // 4
    return i_type(0x04, r(rs), r(rt), delta)


def bne(rs: str, rt: str, pc: int, target: int) -> bytes:
    delta = (target - (pc + 4)) // 4
    return i_type(0x05, r(rs), r(rt), delta)


def jal(target: int) -> bytes:
    return word((0x03 << 26) | ((target >> 2) & 0x03FFFFFF))


def jr(rs: str) -> bytes:
    return word((r(rs) << 21) | 0x08)


def jalr(rs: str) -> bytes:
    return word((r(rs) << 21) | (31 << 11) | 0x09)


def nop() -> bytes:
    return b"\0\0\0\0"


def li_addr(rt: str, address: int) -> bytes:
    hi = ((address + 0x8000) >> 16) & 0xFFFF
    lo = address & 0xFFFF
    return lui(rt, hi) + addiu(rt, rt, lo if lo < 0x8000 else lo - 0x10000)


class Asm:
    def __init__(self, va: int) -> None:
        self.va = va
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, str, str]] = []

    @property
    def pc(self) -> int:
        return self.va + len(self.buf)

    def label(self, name: str) -> None:
        self.labels[name] = self.pc

    def emit(self, data: bytes) -> None:
        self.buf += data

    def branch(self, kind: str, rs: str, rt: str, label: str) -> None:
        self.fixups.append((len(self.buf), kind, rs, rt + ":" + label))
        self.emit(nop())

    def resolve(self) -> bytes:
        for off, kind, rs, packed in self.fixups:
            rt, label = packed.split(":", 1)
            pc = self.va + off
            target = self.labels[label]
            self.buf[off : off + 4] = beq(rs, rt, pc, target) if kind == "beq" else bne(rs, rt, pc, target)
        return bytes(self.buf)


def build_shim(
    include_7e: bool = False,
    include_7e0: bool = False,
    include_7e4: bool = False,
    include_glyph: bool = True,
    dynamic_copy: bool = False,
) -> bytes:
    a = Asm(SHIM_VA)
    a.emit(addiu("sp", "sp", -0x18))
    a.emit(sw("ra", 0x14, "sp"))
    if dynamic_copy:
        a.emit(li_addr("t0", MEM_GLOBAL))
        a.emit(lw("t1", 0, "t0"))
        a.emit(lw("t4", 8, "t1"))
        a.emit(jalr("t4"))
        a.emit(ori("a0", "zero", GUI_COPY_SIZE))
        a.emit(addu("t2", "v0", "zero"))
        a.branch("bne", "t2", "zero", "copy_dest_ready")
        a.emit(nop())
    a.emit(li_addr("t2", GUI_COPY))
    a.label("copy_dest_ready")
    a.emit(sw("t2", 0x10, "sp"))
    a.emit(li_addr("t0", GUI_GLOBAL))
    a.emit(lw("t1", 0, "t0"))
    a.emit(ori("t3", "zero", GUI_COPY_SIZE))
    a.label("copy_loop")
    a.emit(lw("t4", 0, "t1"))
    a.emit(sw("t4", 0, "t2"))
    a.emit(addiu("t1", "t1", 4))
    a.emit(addiu("t2", "t2", 4))
    a.emit(addiu("t3", "t3", -4))
    a.branch("bne", "t3", "zero", "copy_loop")
    a.emit(nop())
    a.emit(lw("t2", 0x10, "sp"))
    ret1_addr_patch = len(a.buf)
    a.emit(li_addr("t4", 0))
    if include_7e or include_7e0:
        a.emit(sw("t4", 0x7E0, "t2"))
    if include_7e or include_7e4:
        a.emit(sw("t4", 0x7E4, "t2"))
    a.emit(sw("t4", 0x7FC, "t2"))
    a.emit(sw("t4", 0x800, "t2"))
    glyph_addr_patch = None
    if include_glyph:
        glyph_addr_patch = len(a.buf)
        a.emit(li_addr("t4", 0))
        a.emit(sw("t4", 0x834, "t2"))
    a.emit(li_addr("t0", GUI_GLOBAL))
    a.emit(sw("t2", 0, "t0"))
    a.emit(lw("ra", 0x14, "sp"))
    a.emit(jr("ra"))
    a.emit(addiu("sp", "sp", 0x18))

    ret1_va = a.pc
    a.label("ret1")
    a.emit(jr("ra"))
    a.emit(addiu("v0", "zero", 1))

    if include_glyph:
        glyph_va = a.pc
        a.label("glyph_stub")
        a.branch("beq", "a2", "zero", "glyph_ret")
        a.emit(nop())
        a.emit(ori("t0", "zero", 0x48))
        a.label("glyph_loop")
        a.emit(sb("zero", 0, "a2"))
        a.emit(addiu("a2", "a2", 1))
        a.emit(addiu("t0", "t0", -1))
        a.branch("bne", "t0", "zero", "glyph_loop")
        a.emit(nop())
        a.label("glyph_ret")
        a.emit(jr("ra"))
        a.emit(addiu("v0", "zero", 1))

    code = bytearray(a.resolve())
    code[ret1_addr_patch : ret1_addr_patch + 8] = li_addr("t4", ret1_va)
    if glyph_addr_patch is not None:
        code[glyph_addr_patch : glyph_addr_patch + 8] = li_addr("t4", glyph_va)
    return bytes(code)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build Mission 9588 BDA with an internal GUI table shim.")
    ap.add_argument("--input", type=Path, default=Path("build") / "使命_9588_std95f8_h1shield_cat4.bda")
    ap.add_argument("-o", "--output", type=Path, default=Path("build") / "使命_9588_std95f8_h1shield_cat4_gui_table_shim_v5.bda")
    ap.add_argument("--include-7e", action="store_true", help="Also override GUI+0x7e0/+0x7e4 with the ret1 shim.")
    ap.add_argument("--include-7e0", action="store_true", help="Override only GUI+0x7e0 with the ret1 shim.")
    ap.add_argument("--include-7e4", action="store_true", help="Override only GUI+0x7e4 with the ret1 shim.")
    ap.add_argument("--no-glyph", action="store_true", help="Do not override GUI+0x834.")
    ap.add_argument("--dynamic-copy", action="store_true", help="Allocate the copied GUI table through MEM+0x08 instead of using fixed BSS.")
    ns = ap.parse_args()

    data = bytearray(ns.input.read_bytes())
    shim = build_shim(
        include_7e=ns.include_7e,
        include_7e0=ns.include_7e0,
        include_7e4=ns.include_7e4,
        include_glyph=not ns.no_glyph,
        dynamic_copy=ns.dynamic_copy,
    )
    cave = data[SHIM_OFF : SHIM_OFF + len(shim)]
    if any(cave):
        raise SystemExit(f"code cave at 0x{SHIM_OFF:x} is not empty for 0x{len(shim):x} bytes")
    if len(shim) > 0x128:
        raise SystemExit(f"shim too large: 0x{len(shim):x} bytes")

    hook_off = HOOK_VA - BDA_BASE
    data[hook_off : hook_off + 20] = (
        jal(SHIM_VA)
        + nop()
        + lw("ra", 0x10, "sp")
        + jr("ra")
        + addiu("sp", "sp", 0x18)
    )
    data[SHIM_OFF : SHIM_OFF + len(shim)] = shim
    fix_header_checksum(data)

    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_bytes(data)
    print(f"output={ns.output}")
    print(f"shim_va=0x{SHIM_VA:08x} shim_off=0x{SHIM_OFF:x} shim_size=0x{len(shim):x}")
    print(f"hook_va=0x{HOOK_VA:08x} gui_global=0x{GUI_GLOBAL:08x} gui_copy=0x{GUI_COPY:08x} copy_size=0x{GUI_COPY_SIZE:x}")
    print(f"include_7e={ns.include_7e}")
    print(f"include_7e0={ns.include_7e0}")
    print(f"include_7e4={ns.include_7e4}")
    print(f"include_glyph={not ns.no_glyph}")
    print(f"dynamic_copy={ns.dynamic_copy}")
    print(verify(data))


if __name__ == "__main__":
    main()
