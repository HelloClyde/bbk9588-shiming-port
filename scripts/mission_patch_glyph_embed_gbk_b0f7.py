from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import checksum_ok, fix_header_checksum, put_encoded_word, verify
from bda_layout import analyze
from minimips import assemble


BDA_BASE = 0x81BF6A28
GLYPH_VA = 0x81C8E780
GLYPH_OFF = GLYPH_VA - BDA_BASE
GLYPH_LIMIT = 0x138

HZK_BASE_OFF = 0x1A84B0
GLYPH_SIZE = 24
GBK_HI_FIRST = 0xA1
GBK_HI_LAST = 0xF7
GBK_ROW_COUNT = GBK_HI_LAST - GBK_HI_FIRST + 1
GBK_ROW_WIDTH = 190
EMBED_SIZE = GBK_ROW_COUNT * GBK_ROW_WIDTH * GLYPH_SIZE
ASCII_FIRST = 0x20
ASCII_COUNT = 0x5F
ASCII_SIZE = ASCII_COUNT * GLYPH_SIZE
ASCII_RETURN_SITE = 0x81C511B8
ADDIU_V0_12 = (0x2402000C).to_bytes(4, "little")

FILE_SIZE_MINUS_4_OFF = 0x10

CALL_SITES = {
    0x81C510CC: bytes.fromhex("21302002"),
    0x81C511B0: bytes.fromhex("21304002"),
}


def jal(target: int) -> bytes:
    return (((0x03 << 26) | ((target >> 2) & 0x03FFFFFF)) & 0xFFFFFFFF).to_bytes(4, "little")


def s1_gbk_index(hi: int, lo: int) -> int:
    return hi * 190 + lo - (0x5FFE if lo < 0x80 else 0x5FFF)


ASCII_FONT_5X7 = {
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
    "!": ["00100", "00100", "00100", "00100", "00100", "00000", "00100"],
    '"': ["01010", "01010", "01010", "00000", "00000", "00000", "00000"],
    "#": ["01010", "11111", "01010", "01010", "11111", "01010", "00000"],
    "$": ["00100", "01111", "10100", "01110", "00101", "11110", "00100"],
    "%": ["11000", "11001", "00010", "00100", "01000", "10011", "00011"],
    "&": ["01100", "10010", "10100", "01000", "10101", "10010", "01101"],
    "'": ["00100", "00100", "01000", "00000", "00000", "00000", "00000"],
    "(": ["00010", "00100", "01000", "01000", "01000", "00100", "00010"],
    ")": ["01000", "00100", "00010", "00010", "00010", "00100", "01000"],
    "*": ["00000", "00100", "10101", "01110", "10101", "00100", "00000"],
    "+": ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
    ",": ["00000", "00000", "00000", "00000", "00100", "00100", "01000"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    "/": ["00001", "00010", "00100", "01000", "10000", "00000", "00000"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00010", "11100"],
    ":": ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
    ";": ["00000", "01100", "01100", "00000", "01100", "00100", "01000"],
    "<": ["00010", "00100", "01000", "10000", "01000", "00100", "00010"],
    "=": ["00000", "00000", "11111", "00000", "11111", "00000", "00000"],
    ">": ["01000", "00100", "00010", "00001", "00010", "00100", "01000"],
    "?": ["01110", "10001", "00001", "00010", "00100", "00000", "00100"],
    "@": ["01110", "10001", "10111", "10101", "10111", "10000", "01110"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01111", "10000", "10000", "10111", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "J": ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    "[": ["01110", "01000", "01000", "01000", "01000", "01000", "01110"],
    "\\": ["10000", "01000", "00100", "00010", "00001", "00000", "00000"],
    "]": ["01110", "00010", "00010", "00010", "00010", "00010", "01110"],
    "^": ["00100", "01010", "10001", "00000", "00000", "00000", "00000"],
    "_": ["00000", "00000", "00000", "00000", "00000", "00000", "11111"],
    "`": ["01000", "00100", "00010", "00000", "00000", "00000", "00000"],
    "{": ["00010", "00100", "00100", "01000", "00100", "00100", "00010"],
    "|": ["00100", "00100", "00100", "00000", "00100", "00100", "00100"],
    "}": ["01000", "00100", "00100", "00010", "00100", "00100", "01000"],
    "~": ["00000", "00000", "01000", "10101", "00010", "00000", "00000"],
}


def ascii_glyph(ch: str) -> bytes:
    pattern = ASCII_FONT_5X7.get(ch)
    if pattern is None and "a" <= ch <= "z":
        pattern = ASCII_FONT_5X7.get(ch.upper())
    if pattern is None:
        pattern = ASCII_FONT_5X7[" "]
    rows = [0] * 12
    for y, bits in enumerate(pattern, 2):
        row = 0
        for x, bit in enumerate(bits):
            if bit == "1":
                row |= 0x80 >> x
        rows[y] = row
    return bytes(rows + [0] * 12)


def build_embed_table(hzk: bytes) -> bytes:
    out = bytearray()
    for hi in range(GBK_HI_FIRST, GBK_HI_LAST + 1):
        for pos in range(GBK_ROW_WIDTH):
            lo = pos + 0x40 if pos < 0x3F else pos + 0x41
            off = HZK_BASE_OFF + s1_gbk_index(hi, lo) * GLYPH_SIZE
            out += hzk[off : off + GLYPH_SIZE]
    if len(out) != EMBED_SIZE:
        raise ValueError(f"unexpected embed size: 0x{len(out):x}")
    for code in range(ASCII_FIRST, ASCII_FIRST + ASCII_COUNT):
        out += ascii_glyph(chr(code))
    if len(out) != EMBED_SIZE + ASCII_SIZE:
        raise ValueError(f"unexpected embed+ascii size: 0x{len(out):x}")
    return bytes(out)


def build_glyph_code(table_va: int, ascii_va: int) -> bytes:
    return assemble(
        f"""
        beqz $a2, done
        nop
        move $t8, $a2
        lbu $t0, 0($a0)
        sltiu $t2, $t0, 0x80
        bnez $t2, ascii
        nop
        addiu $t2, $t0, -{GBK_HI_FIRST}
        sltiu $t3, $t2, {GBK_ROW_COUNT}
        beqz $t3, blank
        nop
        lbu $t1, 1($a0)
        sltiu $t3, $t1, 0x40
        bnez $t3, blank
        nop
        sltiu $t3, $t1, 0xff
        beqz $t3, blank
        nop
        ori $t3, $zero, 0x7f
        beq $t1, $t3, blank
        nop
        sltiu $t3, $t1, 0x80
        bnez $t3, low_left
        nop
        addiu $t1, $t1, -0x41
        j low_done
        nop
    low_left:
        addiu $t1, $t1, -0x40
    low_done:
        sll $t4, $t2, 7
        sll $t5, $t2, 6
        addu $t4, $t4, $t5
        sll $t5, $t2, 1
        subu $t4, $t4, $t5
        addu $t4, $t4, $t1
        sll $t5, $t4, 4
        sll $t6, $t4, 3
        addu $t5, $t5, $t6
        li $t7, {table_va}
        addu $t7, $t7, $t5
        j copy_src
        nop
    ascii:
        addiu $t2, $t0, -{ASCII_FIRST}
        sltiu $t3, $t2, {ASCII_COUNT}
        beqz $t3, blank
        nop
        sll $t5, $t2, 4
        sll $t6, $t2, 3
        addu $t5, $t5, $t6
        li $t7, {ascii_va}
        addu $t7, $t7, $t5
    copy_src:
        ori $t3, $zero, {GLYPH_SIZE}
    copy_loop:
        lbu $t4, 0($t7)
        sb $t4, 0($a2)
        addiu $t7, $t7, 1
        addiu $a2, $a2, 1
        addiu $t3, $t3, -1
        bnez $t3, copy_loop
        nop
        j done
        nop
    blank:
        move $a2, $t8
        ori $t3, $zero, {GLYPH_SIZE}
    blank_loop:
        sb $zero, 0($a2)
        addiu $a2, $a2, 1
        addiu $t3, $t3, -1
        bnez $t3, blank_loop
        nop
    done:
        jr $ra
        addiu $v0, $zero, 1
        """,
        GLYPH_VA,
    )


def patch(src: Path, hzk_path: Path, dst: Path, *, after_bss: bool) -> None:
    data = bytearray(src.read_bytes())
    min_table_off = len(data)
    if after_bss:
        layout = analyze(src)
        bss_end = layout.get("bss_end")
        file_base = layout.get("runtime_file_base")
        if bss_end is None or file_base is None:
            raise ValueError("could not infer BSS end; rerun with --no-after-bss if intentional")
        min_table_off = max(min_table_off, int(bss_end) - int(file_base))
    pad = (-min_table_off) & 3
    table_off = min_table_off + pad
    table_va = BDA_BASE + table_off
    ascii_va = table_va + EMBED_SIZE
    glyph = build_glyph_code(table_va, ascii_va)
    if len(glyph) > GLYPH_LIMIT:
        raise ValueError(f"glyph too large: 0x{len(glyph):x} > 0x{GLYPH_LIMIT:x}")
    if any(data[GLYPH_OFF : GLYPH_OFF + len(glyph)]):
        raise ValueError(f"glyph cave is not empty at 0x{GLYPH_OFF:x}")
    data[GLYPH_OFF : GLYPH_OFF + len(glyph)] = glyph
    for va, delay_slot in CALL_SITES.items():
        off = va - BDA_BASE
        old = data[off : off + 4]
        if old not in (bytes.fromhex("21100000"), bytes.fromhex("09f86000")):
            raise ValueError(f"unexpected call-site instruction at 0x{va:08x}: {old.hex()}")
        data[off : off + 4] = jal(GLYPH_VA)
        data[off + 4 : off + 8] = delay_slot
    return_off = ASCII_RETURN_SITE - BDA_BASE
    old_return = data[return_off : return_off + 4]
    if old_return != bytes.fromhex("21106002"):
        raise ValueError(f"unexpected ASCII return instruction at 0x{ASCII_RETURN_SITE:08x}: {old_return.hex()}")
    data[return_off : return_off + 4] = ADDIU_V0_12
    if len(data) < table_off:
        data += b"\0" * (table_off - len(data))
    data += build_embed_table(hzk_path.read_bytes())
    put_encoded_word(data, FILE_SIZE_MINUS_4_OFF, len(data) - 4)
    fix_header_checksum(data)
    if not checksum_ok(data):
        raise ValueError("patched BDA checksum verification failed")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    print(
        f"glyph=0x{len(glyph):x} table_off=0x{table_off:x} "
        f"gbk_va=0x{table_va:08x} gbk=0x{EMBED_SIZE:x} "
        f"ascii_va=0x{ascii_va:08x} ascii=0x{ASCII_SIZE:x}"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Embed A1-F7 GBK HZK glyphs plus a tiny ASCII font in Mission BDA.")
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ap.add_argument("--hzk", type=Path, default=Path("系统") / "数据" / "HZK_LIB.BIN")
    ap.add_argument("--no-after-bss", action="store_true", help="append directly after file instead of after inferred BSS")
    ns = ap.parse_args()
    patch(ns.src, ns.hzk, ns.dst, after_bss=not ns.no_after_bss)
    print(verify(ns.dst.read_bytes()))


if __name__ == "__main__":
    main()
