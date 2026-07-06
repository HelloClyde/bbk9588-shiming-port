from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import fix_header_checksum, set_title


def main() -> None:
    ap = argparse.ArgumentParser(description="修改 BDA header 中 16 字节菜单标题字段。")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--title", required=True, help="ASCII/GBK 标题，编码后最多 16 字节。")
    ns = ap.parse_args()

    data = bytearray(ns.input.read_bytes())
    try:
        set_title(data, ns.title)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    checksum = fix_header_checksum(data)
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_bytes(data)
    print(f"output={ns.output}")
    print(f"title={ns.title}")
    print(f"checksum=0x{checksum:08x}")


if __name__ == "__main__":
    main()
