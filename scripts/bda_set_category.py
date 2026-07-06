from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import encode_word, fix_header_checksum, set_category


def main() -> None:
    ap = argparse.ArgumentParser(description="修改 BDA header 中 XOR 编码的分类/菜单分组字段。")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--category", type=lambda x: int(x, 0), required=True)
    ns = ap.parse_args()

    data = bytearray(ns.input.read_bytes())
    try:
        set_category(data, ns.category)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    encoded = encode_word(ns.category)
    checksum = fix_header_checksum(data)
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_bytes(data)
    print(f"output={ns.output}")
    print(f"category=0x{ns.category:x}")
    print(f"encoded=0x{encoded:08x}")
    print(f"checksum=0x{checksum:08x}")


if __name__ == "__main__":
    main()
