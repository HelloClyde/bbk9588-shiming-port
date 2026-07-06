from __future__ import annotations

import argparse
from pathlib import Path

from bda_header import CHECKSUM_OFF, decoded_checksum_sum, fix_header_checksum


def main() -> None:
    ap = argparse.ArgumentParser(
        description="修复 BDA header 0x84 处的 checksum 字段。",
        add_help=False,
    )
    ap._positionals.title = "位置参数"
    ap._optionals.title = "选项"
    ap.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    ap.add_argument("input", type=Path, help="要修复 checksum 的 BDA 文件")
    ap.add_argument("-o", "--output", type=Path, required=True, help="输出 BDA 路径")
    ap.add_argument(
        "--mode",
        choices=["exact", "xor-template", "delta-template", "low16-delta"],
        default="exact",
        help="exact 使用已验证固件公式；其他模式仅保留作历史对比。",
    )
    ap.add_argument("--template", type=Path, help="历史对比模式使用的原机 BDA；exact 模式不需要")
    ns = ap.parse_args()

    data = bytearray(ns.input.read_bytes())

    new_sum = decoded_checksum_sum(data)
    templ_sum: int | None = None
    templ_raw: int | None = None
    if ns.mode != "exact":
        if ns.template is None:
            raise SystemExit("历史 checksum 对比模式需要 --template；普通修复请使用默认 exact 模式")
        templ = ns.template.read_bytes()
        templ_sum = decoded_checksum_sum(templ)
        templ_raw = int.from_bytes(templ[CHECKSUM_OFF : CHECKSUM_OFF + 4], "little")

    if ns.mode == "exact":
        patched = fix_header_checksum(data)
    elif ns.mode == "xor-template":
        assert templ_sum is not None and templ_raw is not None
        key = templ_raw ^ templ_sum
        patched = new_sum ^ key
    elif ns.mode == "delta-template":
        assert templ_sum is not None and templ_raw is not None
        delta = (templ_raw - templ_sum) & 0xFFFFFFFF
        patched = (new_sum + delta) & 0xFFFFFFFF
    else:
        assert templ_sum is not None and templ_raw is not None
        delta = ((templ_raw & 0xFFFF) - (templ_sum & 0xFFFF)) & 0xFFFF
        patched = (templ_raw & 0xFFFF0000) | ((new_sum + delta) & 0xFFFF)

    if ns.mode != "exact":
        data[CHECKSUM_OFF : CHECKSUM_OFF + 4] = patched.to_bytes(4, "little")
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    ns.output.write_bytes(data)

    print(f"output={ns.output}")
    print(f"mode={ns.mode}")
    if templ_sum is not None and templ_raw is not None:
        print(f"template_sum=0x{templ_sum:x} template_raw=0x{templ_raw:08x}")
    print(f"new_sum=0x{new_sum:x} patched_raw84=0x{patched:08x}")


if __name__ == "__main__":
    main()
