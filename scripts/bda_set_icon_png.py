from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

from bda_header import decoded_header_words, fix_header_checksum

ICON_SPECS = ((80, 80), (80, 80), (54, 54), (58, 58))


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def read_png(path: Path) -> tuple[int, int, list[tuple[int, int, int, int]]]:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SystemExit("只支持 PNG 输入")
    pos = 8
    width = height = color_type = bit_depth = None
    idat = bytearray()
    while pos + 8 <= len(data):
        ln = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        payload = data[pos + 8 : pos + 8 + ln]
        pos += 12 + ln
        if kind == b"IHDR":
            width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(">IIBBBBB", payload)
            if bit_depth != 8 or comp != 0 or filt != 0 or interlace != 0:
                raise SystemExit("PNG 必须是 8-bit 非隔行格式")
            if color_type not in (2, 6):
                raise SystemExit("PNG 必须是 RGB 或 RGBA")
        elif kind == b"IDAT":
            idat.extend(payload)
        elif kind == b"IEND":
            break
    if width is None or height is None:
        raise SystemExit("PNG 缺少 IHDR")

    channels = 3 if color_type == 2 else 4
    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    rows: list[bytearray] = []
    i = 0
    prev = bytearray(stride)
    for _y in range(height):
        ft = raw[i]
        i += 1
        cur = bytearray(raw[i : i + stride])
        i += stride
        for x in range(stride):
            left = cur[x - channels] if x >= channels else 0
            up = prev[x]
            ul = prev[x - channels] if x >= channels else 0
            if ft == 0:
                val = cur[x]
            elif ft == 1:
                val = cur[x] + left
            elif ft == 2:
                val = cur[x] + up
            elif ft == 3:
                val = cur[x] + ((left + up) >> 1)
            elif ft == 4:
                p = left + up - ul
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - ul)
                pred = left if pa <= pb and pa <= pc else up if pb <= pc else ul
                val = cur[x] + pred
            else:
                raise SystemExit(f"不支持的 PNG filter：{ft}")
            cur[x] = val & 0xFF
        rows.append(cur)
        prev = cur

    pixels: list[tuple[int, int, int, int]] = []
    for row in rows:
        for x in range(0, len(row), channels):
            if channels == 3:
                r, g, b = row[x], row[x + 1], row[x + 2]
                a = 255
            else:
                r, g, b, a = row[x], row[x + 1], row[x + 2], row[x + 3]
            pixels.append((r, g, b, a))
    return width, height, pixels


def resize_cover(
    src_w: int, src_h: int, pixels: list[tuple[int, int, int, int]], dst_w: int, dst_h: int
) -> list[tuple[int, int, int, int]]:
    scale = max(dst_w / src_w, dst_h / src_h)
    crop_w = dst_w / scale
    crop_h = dst_h / scale
    ox = (src_w - crop_w) / 2
    oy = (src_h - crop_h) / 2
    out: list[tuple[int, int, int, int]] = []
    for y in range(dst_h):
        y0 = oy + y / scale
        y1 = oy + (y + 1) / scale
        iy0 = max(0, int(y0))
        iy1 = min(src_h - 1, int(y1) + 1)
        for x in range(dst_w):
            x0 = ox + x / scale
            x1 = ox + (x + 1) / scale
            ix0 = max(0, int(x0))
            ix1 = min(src_w - 1, int(x1) + 1)
            total = rr = gg = bb = aa = 0.0
            for sy in range(iy0, iy1 + 1):
                wy = max(0.0, min(y1, sy + 1.0) - max(y0, float(sy)))
                if wy == 0.0:
                    continue
                row = sy * src_w
                for sx in range(ix0, ix1 + 1):
                    wx = max(0.0, min(x1, sx + 1.0) - max(x0, float(sx)))
                    w = wx * wy
                    if w == 0.0:
                        continue
                    r, g, b, a = pixels[row + sx]
                    total += w
                    aa += a * w
                    rr += r * a * w
                    gg += g * a * w
                    bb += b * a * w
            if total == 0.0 or aa == 0.0:
                out.append((0, 0, 0, 0))
            else:
                alpha = int(round(aa / total))
                out.append((
                    int(round(rr / aa)),
                    int(round(gg / aa)),
                    int(round(bb / aa)),
                    alpha,
                ))
    return out


def rgb565_bytes(
    pixels: list[tuple[int, int, int, int]],
    bg: tuple[int, int, int],
    *,
    transparent_key: tuple[int, int, int] | None = None,
    alpha_threshold: int = 8,
) -> bytes:
    out = bytearray()
    br, bgc, bb = bg
    for r, g, b, a in pixels:
        if transparent_key is not None:
            if a <= alpha_threshold:
                r, g, b = transparent_key
            # VX icons only have a color key, not per-pixel alpha. Use the
            # already despilled source color for visible edge pixels rather
            # than blending them with the key color and creating a fringe.
            a = 255
        if a < 255:
            r = (r * a + br * (255 - a)) // 255
            g = (g * a + bgc * (255 - a)) // 255
            b = (b * a + bb * (255 - a)) // 255
        v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        out.extend(v.to_bytes(2, "little"))
    return bytes(out)


def make_vx(width: int, height: int, pixels565: bytes) -> bytes:
    # This preserves the observed VX header shape: magic, padding, width, height,
    # padding/color-key-looking fields.
    hdr = bytearray()
    hdr.extend(b"VX")
    hdr.extend(b"\xCC\xCC\xCC\xCC")
    hdr.extend(width.to_bytes(4, "little"))
    hdr.extend(height.to_bytes(4, "little"))
    hdr.extend(b"\xCC\xCC\xCC\xCC\xCC\xCC\xFF\xFF\xFF\xFF")
    return bytes(hdr) + pixels565


def icon_ranges(data: bytes) -> list[tuple[int, int]]:
    words = decoded_header_words(data)
    cur = words[6]
    ranges: list[tuple[int, int]] = []
    for size in words[7:11]:
        ranges.append((cur, cur + size))
        cur += size
    return ranges


def parse_bg(s: str) -> tuple[int, int, int]:
    s = s.strip().lstrip("#")
    if len(s) != 6:
        raise argparse.ArgumentTypeError("背景色必须是 RRGGBB 六位十六进制")
    return int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="从 PNG 生成并替换 BDA 的四个 VX 菜单图标。",
        add_help=False,
    )
    ap._positionals.title = "位置参数"
    ap._optionals.title = "选项"
    ap.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    ap.add_argument("input", type=Path, help="要修改的 BDA")
    ap.add_argument("--png", type=Path, required=True, help="RGB/RGBA 8-bit 非隔行 PNG")
    ap.add_argument("-o", "--output", type=Path, required=True, help="输出 BDA 路径")
    ap.add_argument("--background", type=parse_bg, default=(0, 0, 0), help="PNG 透明背景色，默认 000000")
    ap.add_argument("--transparent-key", type=parse_bg, default=None, help="把 alpha 透明像素写成该 RGB565 colorkey，例如 FF00FF")
    ap.add_argument("--alpha-threshold", type=int, default=8, help="alpha 小于等于该值时写 transparent-key，默认 8")
    ns = ap.parse_args()

    src_w, src_h, src_pixels = read_png(ns.png)
    data = bytearray(ns.input.read_bytes())
    ranges = icon_ranges(data)
    for idx, ((width, height), (start, end)) in enumerate(zip(ICON_SPECS, ranges)):
        resized = resize_cover(src_w, src_h, src_pixels, width, height)
        vx = make_vx(
            width,
            height,
            rgb565_bytes(
                resized,
                ns.background,
                transparent_key=ns.transparent_key,
                alpha_threshold=ns.alpha_threshold,
            ),
        )
        if len(vx) != end - start:
            raise SystemExit(f"生成的图标 {idx} 大小不匹配")
        data[start:end] = vx
        print(f"icon{idx}: {width}x{height} -> 0x{start:x}-0x{end:x}")
    checksum = fix_header_checksum(data)
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_bytes(data)
    print(f"output={ns.output}")
    print(f"checksum=0x{checksum:08x}")


if __name__ == "__main__":
    main()
