from __future__ import annotations

import argparse
import json
from pathlib import Path

from bda_header import (
    CATEGORY_OFFSET,
    CHECKSUM_OFF,
    CHECKSUM_XOR_KEY,
    ENCODED_WORD_END,
    TITLE_OFFSET,
    TITLE_SIZE,
    XOR_KEY,
    decoded_header_words,
    verify as verify_header,
)


EXPECTED_MAGIC = 0x004B4242
EXPECTED_WORD04 = 0x5D245562
EXPECTED_VERSION = 0x01000102
MIN_ICON_START = CHECKSUM_OFF + 4
RUNTIME_ENTRY_BASE = 0x81C00020
COMMON_ENTRY_OFFSET = 0x95F8
MIPS_BEQ_ZERO_ZERO_SELF = 0x1000FFFF


def validate_bda(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    header = verify_header(data)
    errors: list[str] = []
    warnings: list[str] = []

    if len(data) < CHECKSUM_OFF + 4:
        errors.append(f"文件太短，无法包含完整 BDA header：0x{len(data):x} 字节")
        return {
            "path": str(path),
            "size": len(data),
            "header": header,
            "icon_ranges": [],
            "errors": errors,
            "warnings": warnings,
            "ok": False,
        }

    words = decoded_header_words(data)
    if len(words) < 11:
        errors.append("header encoded word 不足 11 个 u32")
    else:
        if words[0] != EXPECTED_MAGIC:
            errors.append(f"header magic=0x{words[0]:08x}，期望 0x{EXPECTED_MAGIC:08x}")
        if words[1] != EXPECTED_WORD04:
            errors.append(f"header word04=0x{words[1]:08x}，期望 0x{EXPECTED_WORD04:08x}")
        if words[2] != EXPECTED_VERSION:
            errors.append(f"header version=0x{words[2]:08x}，期望 0x{EXPECTED_VERSION:08x}")

    if header.get("checksum_ok") is not True:
        errors.append("header checksum 不匹配")

    body_size = header.get("file_size_minus_4")
    if isinstance(body_size, int) and body_size != len(data) - 4:
        errors.append(f"header file_size_minus_4=0x{body_size:x}，实际应为 0x{len(data) - 4:x}")

    entry_offset = header.get("entry_offset")
    entry_va: int | None = None
    runtime_file_base: int | None = None
    entry_code_word: int | None = None
    if not isinstance(entry_offset, int):
        errors.append("缺少 entry offset 字段")
    elif entry_offset >= len(data):
        errors.append(f"entry offset 0x{entry_offset:x} 超出文件大小 0x{len(data):x}")
    elif entry_offset % 4:
        errors.append(f"entry offset 0x{entry_offset:x} 不是 4 字节对齐")
    else:
        entry_va = RUNTIME_ENTRY_BASE + (entry_offset - COMMON_ENTRY_OFFSET)
        runtime_file_base = entry_va - entry_offset
        entry_word = data[entry_offset : entry_offset + 4]
        if len(entry_word) < 4:
            errors.append(f"entry code 0x{entry_offset:x} 后不足 4 byte 指令")
        else:
            entry_code_word = int.from_bytes(entry_word, "little")
            if entry_word in (b"\0\0\0\0", b"\xff\xff\xff\xff"):
                errors.append(f"entry code 0x{entry_offset:x} 看起来为空或未初始化")
            elif entry_code_word == MIPS_BEQ_ZERO_ZERO_SELF:
                errors.append(f"entry code 0x{entry_offset:x} 是入口自跳转，会卡住 launcher")
        if entry_offset != COMMON_ENTRY_OFFSET:
            warnings.append(
                f"entry offset 0x{entry_offset:x} 不是常见 no-template/原机应用入口 0x{COMMON_ENTRY_OFFSET:x}"
            )

    icon_start = header.get("icon_start")
    icon_sizes = header.get("icon_sizes")
    icon_ranges: list[dict[str, object]] = []
    if not isinstance(icon_start, int) or not isinstance(icon_sizes, list) or len(icon_sizes) != 4:
        errors.append("缺少四个 icon block size 字段")
    elif icon_start < MIN_ICON_START:
        errors.append(f"icon start offset 0x{icon_start:x} 小于 header 结束 0x{MIN_ICON_START:x}")
    else:
        cur = icon_start
        for idx, size_obj in enumerate(icon_sizes):
            if not isinstance(size_obj, int):
                errors.append(f"icon {idx} size 字段不是整数")
                continue
            start = cur
            end = cur + size_obj
            item = {"index": idx, "start": start, "end": end, "size": size_obj, "vx": False}
            if start < 0 or end > len(data):
                errors.append(f"icon {idx} range 0x{start:x}-0x{end:x} 超出文件")
            elif data[start : start + 2] != b"VX":
                errors.append(f"icon {idx} 在 0x{start:x} 缺少 VX 签名")
            else:
                item["vx"] = True
                if size_obj < 0x18:
                    errors.append(f"icon {idx} size 0x{size_obj:x} 小于 VX header")
            icon_ranges.append(item)
            cur = end

        if isinstance(entry_offset, int) and cur > entry_offset:
            errors.append(f"icon 区结束 0x{cur:x} 超过 entry offset 0x{entry_offset:x}")
        elif isinstance(entry_offset, int) and cur < entry_offset:
            warnings.append(f"icon 区结束 0x{cur:x} 到 entry 0x{entry_offset:x} 之间存在 padding/未知数据")

    return {
        "path": str(path),
        "size": len(data),
        "title": header.get("title"),
        "category": header.get("category"),
        "decoded_words": words,
        "entry_offset": entry_offset,
        "entry_va": entry_va,
        "runtime_file_base": runtime_file_base,
        "entry_code_word": entry_code_word,
        "file_size_minus_4": body_size,
        "expected_file_size_minus_4": len(data) - 4,
        "checksum_ok": header.get("checksum_ok"),
        "expected_magic": EXPECTED_MAGIC,
        "expected_word04": EXPECTED_WORD04,
        "expected_version": EXPECTED_VERSION,
        "header_xor_key": XOR_KEY,
        "checksum_offset": CHECKSUM_OFF,
        "checksum_xor_key": CHECKSUM_XOR_KEY,
        "encoded_word_end": ENCODED_WORD_END,
        "title_offset": TITLE_OFFSET,
        "title_size": TITLE_SIZE,
        "category_offset": CATEGORY_OFFSET,
        "min_icon_start": MIN_ICON_START,
        "mips_beq_zero_zero_self": MIPS_BEQ_ZERO_ZERO_SELF,
        "icon_ranges": icon_ranges,
        "errors": errors,
        "warnings": warnings,
        "ok": not errors,
    }


def print_text(report: dict[str, object]) -> None:
    print(f"文件: {report['path']}")
    print(f"大小: 0x{int(report['size']):x}")
    print(f"标题: {report.get('title')}")
    print(f"分类: {report.get('category')}")
    entry = report.get("entry_offset")
    print(f"entry offset: {entry if not isinstance(entry, int) else f'0x{entry:x}'}")
    entry_va = report.get("entry_va")
    if isinstance(entry_va, int):
        print(f"entry VA: 0x{entry_va:x}")
    runtime_file_base = report.get("runtime_file_base")
    if isinstance(runtime_file_base, int):
        print(f"runtime file base: 0x{runtime_file_base:x}")
    entry_code_word = report.get("entry_code_word")
    if isinstance(entry_code_word, int):
        print(f"entry code word: 0x{entry_code_word:08x}")
    print(f"checksum: {'ok' if report.get('checksum_ok') else 'BAD'}")
    print("icon:")
    for item in report.get("icon_ranges", []):
        row = dict(item)
        print(
            f"  icon{row['index']}: 0x{int(row['start']):x}-0x{int(row['end']):x} "
            f"size=0x{int(row['size']):x} vx={row['vx']}"
        )
    for warning in report.get("warnings", []):
        print(f"警告: {warning}")
    for error in report.get("errors", []):
        print(f"错误: {error}")
    print(f"结果: {'通过' if report.get('ok') else '失败'}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="静态校验原生 BBK 9588 BDA header、entry 和 VX icon 区。",
        add_help=False,
    )
    ap._positionals.title = "位置参数"
    ap._optionals.title = "选项"
    ap.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    ap.add_argument("bda", type=Path, help="要校验的 BDA 文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON，便于脚本集成")
    ns = ap.parse_args()

    report = validate_bda(ns.bda)
    if ns.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_text(report)
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
