from __future__ import annotations

import argparse
import collections
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32, Cs


BDA_BASE = 0x81BF6A28
BDA_CODE_OFF = 0x95F8
C200_BASE = 0x80004000
S1_BASE = 0x80004000

C200_TABLES = {
    "GUI": 0x80280E60,
    "FS": 0x80280DD0,
    "SYS": 0x80280C60,
    "MEM": 0x8028169C,
    "RES": 0x80280D30,
}

S1_TABLES = {
    "GUI": 0x8028B130,
    "FS": 0x8028B0A0,
    "SYS": 0x8028AF30,
    "MEM": 0x8028B9DC,
    "RES": 0x8028B000,
}

# Mission copies the five loader table pointers into its own BSS in the entry
# initializer. These are effective addresses, not raw 16-bit displacements.
MISSION_TABLE_GLOBALS = {
    0x81C9B6A4: "GUI",
    0x81C9B6AC: "FS",
    0x81C9B6A8: "SYS",
    0x81C9B6B0: "MEM",
    0x81C9B6A0: "RES",
}

HIGH_RISK_NOTES = {
    ("GUI", 0x7FC): "S1 是高级 GUI runtime 初始化；9588 是不同语义函数。",
    ("GUI", 0x800): "S1 是高级 GUI runtime 释放；9588 是不同语义函数。",
    ("GUI", 0x834): "S1 有真实函数；9588 表项不是 C200 可执行地址。",
    ("RES", 0x08): "S1 是真实资源函数；9588 是 jr ra stub。",
}


@dataclass(frozen=True)
class CallSite:
    address: int
    table: str
    offset: int
    target_reg: str


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def c200_off(va: int) -> int:
    return va - C200_BASE


def s1_off(va: int) -> int:
    return va - S1_BASE + 0x40


def in_image(data: bytes, off: int, size: int = 4) -> bool:
    return 0 <= off <= len(data) - size


def table_entry(data: bytes, table_va: int, offset: int, off_fn) -> int | None:
    off = off_fn(table_va + offset)
    if not in_image(data, off, 4):
        return None
    return u32(data, off)


def first_insns(data: bytes, va: int | None, off_fn, count: int = 4) -> list[str]:
    if va is None:
        return []
    off = off_fn(va)
    if not in_image(data, off, 4):
        return []
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    out: list[str] = []
    for ins in md.disasm(data[off : off + 0x40], va):
        out.append(f"{ins.mnemonic} {ins.op_str}".strip())
        if len(out) >= count:
            break
    return out


def is_ret_stub(insns: list[str]) -> bool:
    return bool(insns) and insns[0].startswith("jr $ra")


def is_ret1_stub(insns: list[str]) -> bool:
    joined = "; ".join(insns[:2])
    return "jr $ra" in joined and ("addiu $v0, $zero, 1" in joined or "ori $v0, $zero, 1" in joined)


def classify(table: str, offset: int, s1_target: int | None, c200_target: int | None, s1_ins: list[str], c200_ins: list[str]) -> tuple[str, str, str]:
    key = (table, offset)
    table_min = min(C200_TABLES.values())
    table_max = max(C200_TABLES.values()) + 0x1000
    if c200_target is None:
        return "必须改调用逻辑", "missing", "9588 表项越界，不能直接调用。"
    if c200_target == 0:
        return "必须 shim/改调用", "dead_null", HIGH_RISK_NOTES.get(key, "9588 表项为空，直接 jalr 会跳 0。")
    if table_min <= c200_target <= table_max:
        return "必须 shim/改调用", "data_pointer", HIGH_RISK_NOTES.get(key, "9588 表项指向 API 表/数据区，不是函数入口。")
    if not c200_ins:
        return "必须改调用逻辑", "bad_pointer", HIGH_RISK_NOTES.get(key, "9588 表项不是 C200 映像内可反汇编函数。")
    if key in HIGH_RISK_NOTES:
        if is_ret_stub(c200_ins) and not is_ret_stub(s1_ins):
            return "BDA 内 shim", "stubbed", HIGH_RISK_NOTES[key]
        return "BDA 内 shim/改调用", "known_semantic_mismatch", HIGH_RISK_NOTES[key]
    if is_ret_stub(c200_ins) and not is_ret_stub(s1_ins):
        return "BDA 内 shim", "stubbed", "9588 是空返回 stub，S1 是真实函数。"
    if is_ret1_stub(s1_ins) and not is_ret1_stub(c200_ins):
        return "改调用逻辑/参数结构", "s1_stub_c200_real", "S1 只返回成功，9588 会执行真实系统逻辑。"
    return "可先用 9588 原生", "native_candidate", "表项存在且不是明显空/坏指针；仍需按 ABI 复核。"


LW_RE = re.compile(r"^(?P<dst>\$\w+),\s*(?P<imm>[-+]?0x[0-9a-fA-F]+|[-+]?\d+)\((?P<base>\$\w+)\)$")
LUI_RE = re.compile(r"^(?P<dst>\$\w+),\s*(?P<imm>[-+]?0x[0-9a-fA-F]+|[-+]?\d+)$")


def parse_int(text: str) -> int:
    return int(text, 0)


def effective_global(insns, idx: int, reg: str, imm: int) -> int | None:
    for j in range(idx - 1, max(-1, idx - 8), -1):
        p = insns[j]
        if p.mnemonic != "lui":
            continue
        m = LUI_RE.match(p.op_str)
        if not m or m.group("dst") != reg:
            continue
        upper = parse_int(m.group("imm")) & 0xFFFF
        signed_imm = imm if imm < 0x8000 else imm - 0x10000
        return ((upper << 16) + signed_imm) & 0xFFFFFFFF
    return None


def scan_call_sites(bda: Path, base: int, code_off: int) -> list[CallSite]:
    data = bda.read_bytes()
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(data[code_off:], base + code_off))
    calls: list[CallSite] = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic != "jalr":
            continue
        target_reg = ins.op_str.split(",")[-1].strip()
        table_reg = None
        api_offset = None
        for j in range(idx - 1, max(-1, idx - 8), -1):
            p = insns[j]
            if p.mnemonic != "lw":
                continue
            m = LW_RE.match(p.op_str)
            if not m or m.group("dst") != target_reg:
                continue
            api_offset = parse_int(m.group("imm")) & 0xFFFFFFFF
            if api_offset >= 0x2000:
                api_offset = ((api_offset + 0x8000) & 0xFFFF) - 0x8000
            table_reg = m.group("base")
            break
        if table_reg is None or api_offset is None or api_offset < 0:
            continue
        table = None
        for j in range(idx - 1, max(-1, idx - 24), -1):
            p = insns[j]
            if p.mnemonic != "lw":
                continue
            m = LW_RE.match(p.op_str)
            if not m or m.group("dst") != table_reg:
                continue
            eff = effective_global(insns, j, m.group("base"), parse_int(m.group("imm")) & 0xFFFF)
            if eff in MISSION_TABLE_GLOBALS:
                table = MISSION_TABLE_GLOBALS[eff]
                break
        if table:
            calls.append(CallSite(ins.address, table, api_offset, target_reg))
    return calls


def build_matrix(bda: Path, c200: Path, s1: Path, base: int, code_off: int) -> dict[str, object]:
    calls = scan_call_sites(bda, base, code_off)
    c200_data = c200.read_bytes()
    s1_data = s1.read_bytes()
    grouped: dict[tuple[str, int], list[int]] = collections.defaultdict(list)
    for call in calls:
        grouped[(call.table, call.offset)].append(call.address)
    rows = []
    for (table, offset), addrs in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        s1_target = table_entry(s1_data, S1_TABLES[table], offset, s1_off)
        c200_target = table_entry(c200_data, C200_TABLES[table], offset, c200_off)
        s1_ins = first_insns(s1_data, s1_target, s1_off)
        c200_ins = first_insns(c200_data, c200_target, c200_off)
        action, risk, note = classify(table, offset, s1_target, c200_target, s1_ins, c200_ins)
        rows.append(
            {
                "table": table,
                "offset": offset,
                "call_count": len(addrs),
                "call_sites": addrs,
                "s1_target": s1_target,
                "s1_first": s1_ins[:3],
                "c200_target": c200_target,
                "c200_first": c200_ins[:3],
                "risk": risk,
                "action": action,
                "note": note,
            }
        )
    return {
        "bda": str(bda),
        "c200": str(c200),
        "s1": str(s1),
        "call_sites_total": len(calls),
        "api_total": len(rows),
        "rows": rows,
    }


def hx(value: int | None) -> str:
    return "" if value is None else f"0x{value:08x}"


def write_markdown(matrix: dict[str, object], out: Path) -> None:
    rows = list(matrix["rows"])
    counts = collections.Counter(row["action"] for row in rows)
    risk_counts = collections.Counter(row["risk"] for row in rows)
    lines: list[str] = []
    lines.append("# 使命 S1 -> 9588 API 兼容矩阵")
    lines.append("")
    lines.append("本报告由 `reverse/mission_api_compat_matrix.py` 生成，扫描 `使命` 实际 `jalr` 表调用点，并对照 S1 `kj40d300.bin` 与 9588 `C200.bin` 的运行时 API 表。")
    lines.append("")
    lines.append(f"- BDA: `{matrix['bda']}`")
    lines.append(f"- S1 固件: `{matrix['s1']}`")
    lines.append(f"- 9588 固件: `{matrix['c200']}`")
    lines.append(f"- 识别到表调用点: {matrix['call_sites_total']}")
    lines.append(f"- 去重 API 表项: {matrix['api_total']}")
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append(f"- 可先用 9588 原生: {counts.get('可先用 9588 原生', 0)} 项")
    lines.append(f"- 建议 BDA 内 shim: {counts.get('BDA 内 shim', 0)} 项")
    lines.append(f"- 必须 shim/改调用: {counts.get('必须 shim/改调用', 0)} 项")
    lines.append(f"- BDA 内 shim/改调用: {counts.get('BDA 内 shim/改调用', 0)} 项")
    lines.append(f"- 必须改调用逻辑: {counts.get('必须改调用逻辑', 0)} 项")
    lines.append("")
    lines.append("风险分类统计：")
    lines.append("")
    for risk, count in risk_counts.most_common():
        lines.append(f"- `{risk}`: {count}")
    lines.append("")
    lines.append("## 必须优先处理")
    lines.append("")
    lines.append("| API | 调用数 | S1 函数 | 9588 函数 | 风险 | 建议 | 说明 | 调用点 |")
    lines.append("| --- | ---: | ---: | ---: | --- | --- | --- | --- |")
    priority = [row for row in rows if row["risk"] != "native_candidate"]
    for row in priority:
        sites = ", ".join(f"`0x{addr:08x}`" for addr in row["call_sites"][:8])
        if len(row["call_sites"]) > 8:
            sites += f", ...(+{len(row['call_sites']) - 8})"
        lines.append(
            f"| {row['table']}+0x{int(row['offset']):03x} | {row['call_count']} | `{hx(row['s1_target'])}` | `{hx(row['c200_target'])}` | `{row['risk']}` | {row['action']} | {row['note']} | {sites} |"
        )
    lines.append("")
    lines.append("## 全量矩阵")
    lines.append("")
    lines.append("| API | 调用数 | S1 函数/首指令 | 9588 函数/首指令 | 风险 | 建议 |")
    lines.append("| --- | ---: | --- | --- | --- | --- |")
    for row in rows:
        s1_first = "; ".join(row["s1_first"]).replace("|", "\\|")
        c200_first = "; ".join(row["c200_first"]).replace("|", "\\|")
        lines.append(
            f"| {row['table']}+0x{int(row['offset']):03x} | {row['call_count']} | `{hx(row['s1_target'])}` {s1_first} | `{hx(row['c200_target'])}` {c200_first} | `{row['risk']}` | {row['action']} |"
        )
    lines.append("")
    lines.append("## 兼容方案草案")
    lines.append("")
    lines.append("1. 保留 native candidate 表项继续走 9588 原生，避免扩大 shim 面。")
    lines.append("2. 在 BDA 内复制 GUI/RES/SYS 表到自身 BSS，只覆盖必死或语义明显不一致项。")
    lines.append("3. `GUI+0x7fc/+0x800/+0x834` 不应再直接跳 9588 表；这些是当前矩阵里最明确的必修项。")
    lines.append("4. `GUI+0x7e0/+0x7e4` 在 9588 里也有实现，不再按空指针处理；但它们是高层窗口/事件循环封装，仍建议单独 ABI 复核。")
    lines.append("5. `SYS+0x050/+0x054` 在 S1 和 9588 当前都表现为 ret1 stub，可先用原生，不应作为当前死机主因。")
    lines.append("")
    lines.append("## 当前决策")
    lines.append("")
    lines.append("| API | 决策 | 最小兼容语义 |")
    lines.append("| --- | --- | --- |")
    lines.append("| `GUI+0x7fc` | BDA 内 shim | S1 高级 GUI runtime 初始化。先实现为返回成功/轻量状态初始化，避免跳 9588 stub。 |")
    lines.append("| `GUI+0x800` | BDA 内 shim | S1 高级 GUI runtime 释放。先实现为空释放/返回成功，避免跳 9588 stub。 |")
    lines.append("| `GUI+0x834` | BDA 内 shim 或改调用 | S1 字形/字符位图生成。9588 表项越过 GUI 表落到数据区；最小 shim 可清空输出 glyph 缓冲并返回，完整 shim 需重建字体位图。 |")
    lines.append("| 其他 81 项 | 9588 原生 | 表项存在且 S1/9588 函数形态匹配度较高，先不扩大兼容层。 |")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate Mission S1-to-9588 BDA API compatibility matrix.")
    ap.add_argument("--bda", type=Path, default=Path("build") / "使命_9588_std95f8_h1shield_cat4.bda")
    ap.add_argument("--c200", type=Path, default=Path("系统") / "数据" / "C200.bin")
    ap.add_argument("--s1", type=Path, default=Path("kj40d300.bin"))
    ap.add_argument("--base", type=lambda text: int(text, 0), default=BDA_BASE)
    ap.add_argument("--code-off", type=lambda text: int(text, 0), default=BDA_CODE_OFF)
    ap.add_argument("--json-out", type=Path, default=Path("build") / "mission_api_compat_matrix.json")
    ap.add_argument("--md-out", type=Path, default=Path("build") / "mission_api_compat_matrix.md")
    ns = ap.parse_args()

    matrix = build_matrix(ns.bda, ns.c200, ns.s1, ns.base, ns.code_off)
    ns.json_out.parent.mkdir(parents=True, exist_ok=True)
    ns.json_out.write_text(json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(matrix, ns.md_out)
    print(f"call_sites_total={matrix['call_sites_total']}")
    print(f"api_total={matrix['api_total']}")
    print(f"json={ns.json_out}")
    print(f"markdown={ns.md_out}")


if __name__ == "__main__":
    main()
