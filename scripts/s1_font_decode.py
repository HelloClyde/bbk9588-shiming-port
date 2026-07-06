from __future__ import annotations

import argparse
import sys
from pathlib import Path


S1_HZK_BASE = 0x1A84B0
GLYPH_SIZE = 24


def gbk_index(pair: bytes) -> int:
    high, low = pair[0], pair[1]
    bias = 0x5FFE if low < 0x80 else 0x5FFF
    return high * 190 + low - bias


def s1_char_class(pair: bytes) -> int:
    a0 = (pair[0] << 8) | pair[1]
    a2 = pair[1]

    def u16(value: int) -> int:
        return value & 0xFFFF

    if a0 == 0xACF1:
        return 2
    if u16(a0 + 0x555F) < 0x1F:
        return 1
    value = u16(a0 + 0x551F)
    if value < 0xD3 and a2 >= 0xA1:
        return 1
    if u16(a0 + 0x5440) < 8:
        return 1
    if u16(a0 + 0x5433) < 0x0B:
        return 1
    value = u16(a0 + 0x5424)
    if value < 2:
        return 0
    if value < 0x1E8 and a2 >= 0xA1:
        return 1
    if u16(a0 + 0x5035) < 0x28:
        return 1
    if u16(a0 + 0x5BAA) < 7:
        return 0
    if u16(a0 + 0x5B98) < 0x0A:
        return 0
    if u16(a0 + 0x5B8C) < 0x10:
        return 0
    return 1 if u16(a0 + 0x5B74) < 6 else 0


def render_12x16(glyph: bytes) -> list[str]:
    rows: list[str] = []
    for row in range(12):
        value = (glyph[row * 2] << 8) | glyph[row * 2 + 1]
        rows.append("".join("#" if value & (1 << (15 - bit)) else "." for bit in range(16)))
    return rows


def decode_text(hzk: bytes, text: str) -> str:
    out: list[str] = []
    for ch in text:
        pair = ch.encode("gbk")
        if len(pair) != 2:
            out.append(f"{ch} ascii/unsupported {pair.hex()}")
            continue
        index = gbk_index(pair)
        offset = S1_HZK_BASE + index * GLYPH_SIZE
        glyph = hzk[offset : offset + GLYPH_SIZE]
        if len(glyph) != GLYPH_SIZE:
            out.append(f"{ch} {pair.hex()} idx={index} off=0x{offset:x} OUT_OF_RANGE")
            continue
        out.append(f"{ch} gbk={pair.hex()} idx={index} class={s1_char_class(pair)} off=0x{offset:x} raw={glyph.hex()}")
        out.extend(render_12x16(glyph))
        out.append("")
    return "\n".join(out)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Decode S1/default HZK glyphs using Mission's GUI+0x834 indexing path.")
    ap.add_argument("--hzk", type=Path, default=Path("系统") / "数据" / "HZK_LIB.BIN")
    ap.add_argument("--text", default="新的征程\n载入存档\n游戏设置\n离开游戏\n使命")
    ap.add_argument("--out", type=Path)
    ns = ap.parse_args()

    hzk = ns.hzk.read_bytes()
    result = "\n".join(decode_text(hzk, line) for line in ns.text.splitlines())
    if ns.out:
        ns.out.parent.mkdir(parents=True, exist_ok=True)
        ns.out.write_text(result, encoding="utf-8")
    print(result)


if __name__ == "__main__":
    main()
