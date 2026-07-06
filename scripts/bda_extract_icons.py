from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

from bda_header import decoded_header_words


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def write_png(path: Path, width: int, height: int, rgb: bytes) -> None:
    rows = bytearray()
    stride = width * 3
    for y in range(height):
        rows.append(0)
        rows.extend(rgb[y * stride : (y + 1) * stride])
    payload = b"\x89PNG\r\n\x1a\n"
    payload += png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    payload += png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    payload += png_chunk(b"IEND", b"")
    path.write_bytes(payload)


def rgb565_to_rgb(data: bytes, width: int, height: int, endian: str) -> bytes:
    out = bytearray()
    for i in range(width * height):
        raw = data[i * 2 : i * 2 + 2]
        v = int.from_bytes(raw, endian)
        r = (v >> 11) & 0x1F
        g = (v >> 5) & 0x3F
        b = v & 0x1F
        out.extend(((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)))
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="从原生 BDA 导出 VX RGB565 菜单图标为 PNG。",
        add_help=False,
    )
    ap._positionals.title = "位置参数"
    ap._optionals.title = "选项"
    ap.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    ap.add_argument("bda", type=Path, help="要导出图标的 BDA")
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("build/icons"), help="输出目录")
    ap.add_argument("--endian", choices=["little", "big"], default="little", help="VX RGB565 像素字节序")
    ns = ap.parse_args()

    data = ns.bda.read_bytes()
    words = decoded_header_words(data)
    start = words[6]
    sizes = words[7:11]
    ns.out_dir.mkdir(parents=True, exist_ok=True)

    cur = start
    stem = ns.bda.stem
    for idx, size in enumerate(sizes):
        hdr = data[cur : cur + 0x18]
        if hdr[:2] != b"VX":
            print(f"{idx}: 0x{cur:x} 缺少 VX")
            cur += size
            continue
        width = int.from_bytes(hdr[6:10], "little")
        height = int.from_bytes(hdr[10:14], "little")
        pixels = data[cur + 0x18 : cur + size]
        expected = width * height * 2
        if len(pixels) < expected:
            print(f"{idx}: 0x{cur:x} 像素数据不足")
            cur += size
            continue
        rgb = rgb565_to_rgb(pixels[:expected], width, height, ns.endian)
        out = ns.out_dir / f"{stem}_icon{idx}_{width}x{height}_{ns.endian}.png"
        write_png(out, width, height, rgb)
        print(f"{idx}: off=0x{cur:x} size=0x{size:x} {width}x{height} -> {out}")
        cur += size


if __name__ == "__main__":
    main()
