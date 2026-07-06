from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path


REGS = {
    "$zero": 0,
    "$0": 0,
    "$at": 1,
    "$v0": 2,
    "$v1": 3,
    "$a0": 4,
    "$a1": 5,
    "$a2": 6,
    "$a3": 7,
    "$t0": 8,
    "$t1": 9,
    "$t2": 10,
    "$t3": 11,
    "$t4": 12,
    "$t5": 13,
    "$t6": 14,
    "$t7": 15,
    "$s0": 16,
    "$s1": 17,
    "$s2": 18,
    "$s3": 19,
    "$s4": 20,
    "$s5": 21,
    "$s6": 22,
    "$s7": 23,
    "$t8": 24,
    "$t9": 25,
    "$k0": 26,
    "$k1": 27,
    "$gp": 28,
    "$sp": 29,
    "$fp": 30,
    "$s8": 30,
    "$ra": 31,
}


@dataclass
class Item:
    op: str
    args: list[str]
    line: str
    lineno: int
    addr: int = 0


def parse_int(s: str) -> int:
    return int(s, 0)


def reg(s: str) -> int:
    key = s.strip().lower()
    if key not in REGS:
        raise ValueError(f"unknown register {s}")
    return REGS[key]


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].split(";", 1)[0].strip()


def split_args(text: str) -> list[str]:
    return [x.strip() for x in text.split(",") if x.strip()]


def item_size(item: Item) -> int:
    if item.op in {".asciiz", ".ascii"}:
        raw = parse_string(item.args[0])
        return len(raw) + (1 if item.op == ".asciiz" else 0)
    if item.op == ".word":
        return 4 * len(item.args)
    if item.op == ".half":
        return 2 * len(item.args)
    if item.op == ".byte":
        return len(item.args)
    if item.op == ".space":
        return parse_int(item.args[0])
    if item.op == ".align":
        return 0
    if item.op in {"la", "li"}:
        if item.op == "li":
            try:
                value = parse_int(item.args[1]) & 0xFFFFFFFF
                if value <= 0xFFFF:
                    return 4
            except ValueError:
                pass
        return 8
    return 4


def parse_string(s: str) -> bytes:
    s = s.strip()
    if not (s.startswith('"') and s.endswith('"')):
        raise ValueError(f"expected quoted string, got {s}")
    return bytes(s[1:-1], "utf-8").decode("unicode_escape").encode("latin1")


def preprocess(source: str, base_va: int) -> tuple[list[Item], dict[str, int]]:
    items: list[Item] = []
    labels: dict[str, int] = {}
    addr = base_va
    for lineno, raw in enumerate(source.splitlines(), 1):
        line = strip_comment(raw)
        if not line:
            continue
        while ":" in line:
            label, rest = line.split(":", 1)
            label = label.strip()
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", label):
                break
            labels[label] = addr
            line = rest.strip()
            if not line:
                break
        if not line:
            continue
        parts = line.split(None, 1)
        op = parts[0].lower()
        args = split_args(parts[1]) if len(parts) > 1 else []
        if op == ".align":
            align = 1 << parse_int(args[0])
            addr = (addr + align - 1) & ~(align - 1)
            continue
        item = Item(op, args, raw, lineno, addr)
        items.append(item)
        addr += item_size(item)
    return items, labels


def r_type(rs: int, rt: int, rd: int, sh: int, fn: int) -> bytes:
    return struct.pack("<I", (rs << 21) | (rt << 16) | (rd << 11) | (sh << 6) | fn)


def i_type(op: int, rs: int, rt: int, imm: int) -> bytes:
    return struct.pack("<I", (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF))


def j_type(op: int, addr: int) -> bytes:
    return struct.pack("<I", (op << 26) | ((addr >> 2) & 0x03FFFFFF))


def resolve(arg: str, labels: dict[str, int]) -> int:
    arg = arg.strip()
    return labels[arg] if arg in labels else parse_int(arg)


def parse_mem(arg: str) -> tuple[int, int]:
    m = re.match(r"^(.+?)\((\$[A-Za-z0-9]+)\)$", arg.replace(" ", ""))
    if not m:
        raise ValueError(f"expected offset(register), got {arg}")
    return parse_int(m.group(1)), reg(m.group(2))


def branch_imm(item: Item, target: str, labels: dict[str, int]) -> int:
    addr = resolve(target, labels)
    return (addr - (item.addr + 4)) >> 2


def emit_item(item: Item, labels: dict[str, int]) -> bytes:
    op, a = item.op, item.args
    if op == ".asciiz":
        return parse_string(a[0]) + b"\0"
    if op == ".ascii":
        return parse_string(a[0])
    if op == ".word":
        return b"".join(struct.pack("<I", resolve(x, labels) & 0xFFFFFFFF) for x in a)
    if op == ".half":
        return b"".join(struct.pack("<H", resolve(x, labels) & 0xFFFF) for x in a)
    if op == ".byte":
        return b"".join(struct.pack("B", resolve(x, labels) & 0xFF) for x in a)
    if op == ".space":
        return b"\0" * parse_int(a[0])
    if op == "nop":
        return b"\0\0\0\0"
    if op == "jr":
        return r_type(reg(a[0]), 0, 0, 0, 0x08)
    if op == "jalr":
        return r_type(reg(a[0]), 0, 31, 0, 0x09)
    if op == "move":
        return r_type(reg(a[1]), 0, reg(a[0]), 0, 0x21)
    if op == "addu":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x21)
    if op == "subu":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x23)
    if op == "and":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x24)
    if op == "or":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x25)
    if op == "xor":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x26)
    if op == "slt":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x2A)
    if op == "sltu":
        return r_type(reg(a[1]), reg(a[2]), reg(a[0]), 0, 0x2B)
    if op == "sll":
        return r_type(0, reg(a[1]), reg(a[0]), resolve(a[2], labels), 0x00)
    if op == "srl":
        return r_type(0, reg(a[1]), reg(a[0]), resolve(a[2], labels), 0x02)
    if op == "lui":
        return i_type(0x0F, 0, reg(a[0]), resolve(a[1], labels))
    if op == "ori":
        return i_type(0x0D, reg(a[1]), reg(a[0]), resolve(a[2], labels))
    if op == "andi":
        return i_type(0x0C, reg(a[1]), reg(a[0]), resolve(a[2], labels))
    if op == "xori":
        return i_type(0x0E, reg(a[1]), reg(a[0]), resolve(a[2], labels))
    if op == "addiu":
        return i_type(0x09, reg(a[1]), reg(a[0]), resolve(a[2], labels))
    if op in {"slti", "sltiu"}:
        return i_type(0x0A if op == "slti" else 0x0B, reg(a[1]), reg(a[0]), resolve(a[2], labels))
    if op in {"lw", "sw", "lb", "lbu", "lh", "lhu", "sb", "sh"}:
        imm, base = parse_mem(a[1])
        opcodes = {
            "lb": 0x20,
            "lh": 0x21,
            "lw": 0x23,
            "lbu": 0x24,
            "lhu": 0x25,
            "sb": 0x28,
            "sh": 0x29,
            "sw": 0x2B,
        }
        return i_type(opcodes[op], base, reg(a[0]), imm)
    if op in {"beq", "bne"}:
        return i_type(0x04 if op == "beq" else 0x05, reg(a[0]), reg(a[1]), branch_imm(item, a[2], labels))
    if op == "beqz":
        return i_type(0x04, reg(a[0]), 0, branch_imm(item, a[1], labels))
    if op == "bnez":
        return i_type(0x05, reg(a[0]), 0, branch_imm(item, a[1], labels))
    if op == "li":
        value = resolve(a[1], labels) & 0xFFFFFFFF
        if value <= 0xFFFF:
            return i_type(0x0D, 0, reg(a[0]), value)
        hi = (value + 0x8000) >> 16
        lo = value & 0xFFFF
        return i_type(0x0F, 0, reg(a[0]), hi) + i_type(0x09, reg(a[0]), reg(a[0]), lo)
    if op == "j":
        return j_type(0x02, resolve(a[0], labels))
    if op == "jal":
        return j_type(0x03, resolve(a[0], labels))
    if op == "la":
        addr = resolve(a[1], labels)
        hi = (addr + 0x8000) >> 16
        lo = addr & 0xFFFF
        return i_type(0x0F, 0, reg(a[0]), hi) + i_type(0x09, reg(a[0]), reg(a[0]), lo)
    raise ValueError(f"unsupported op {op!r} at line {item.lineno}: {item.line}")


def assemble(source: str, base_va: int) -> bytes:
    items, labels = preprocess(source, base_va)
    out = bytearray()
    cur = base_va
    for item in items:
        if item.addr > cur:
            out.extend(b"\0" * (item.addr - cur))
            cur = item.addr
        data = emit_item(item, labels)
        out.extend(data)
        cur += len(data)
    return bytes(out)


def assemble_file(path: Path, base_va: int) -> bytes:
    return assemble(path.read_text(encoding="utf-8"), base_va)
