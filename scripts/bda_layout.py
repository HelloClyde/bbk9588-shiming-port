from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path

from bda_header import decoded_header_words


ENTRY_SIG = bytes.fromhex("e8 ff bd 27 10 00 bf af")
RUNTIME_ENTRY_VA = 0x81C00020
COMMON_ENTRY_OFFSET = 0x95F8


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def s16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def materialized_addr(data: bytes, off: int) -> int | None:
    if off + 8 > len(data):
        return None
    w1 = u32(data, off)
    w2 = u32(data, off + 4)
    if ((w1 >> 26) & 0x3F) != 0x0F:
        return None
    op = (w2 >> 26) & 0x3F
    if op not in {0x09, 0x0D, 0x23, 0x2B}:
        return None
    hi = (w1 & 0xFFFF) << 16
    lo = w2 & 0xFFFF
    if op != 0x0D:
        lo = s16(lo)
    return (hi + lo) & 0xFFFFFFFF


def find_entry(data: bytes) -> int | None:
    off = data.find(ENTRY_SIG)
    return off if off >= 0 else None


def header_entry(data: bytes) -> int | None:
    words = decoded_header_words(data)
    if len(words) < 6:
        return None
    entry = words[5]
    if entry < 0 or entry >= len(data) or entry % 4:
        return None
    return entry


def shell_paths(data: bytes) -> list[dict[str, int | str]]:
    out = []
    for m in re.finditer(rb"(?:[A-Za-z]:)?\\[^\x00]{0,96}?\.dlx", data, re.I):
        raw = m.group()
        start = m.start()
        idx = raw.lower().find(b"\\shell")
        if idx >= 0:
            raw = raw[idx:]
            start += idx
        out.append({"offset": start, "text_latin1": raw.decode("latin1", "replace")})
    return out


def infer_load_base(data: bytes, entry: int | None) -> int | None:
    # The common startup stub materializes the first DLX path at entry+0xb0.
    if entry is None:
        return None
    first_addr = materialized_addr(data, entry + 0xB0)
    if first_addr is None:
        return None
    paths = shell_paths(data)
    if not paths:
        return None
    # Prefer the first shell path at or after the code entry's data references.
    for p in paths:
        base = first_addr - int(p["offset"])
        if 0x81BE0000 <= base <= 0x81C00000:
            return base
    return None


def analyze(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    signature_entry = find_entry(data)
    decoded_entry = header_entry(data)
    entry = signature_entry if signature_entry is not None else decoded_entry
    base = infer_load_base(data, signature_entry)
    header_words = [u32(data, off) for off in range(0, min(0x2C, len(data)), 4)]
    bss_start = materialized_addr(data, signature_entry + 0x34) if signature_entry is not None else None
    bss_end = materialized_addr(data, signature_entry + 0x3C) if signature_entry is not None else None
    legacy_file_base = base
    runtime_entry_va = (
        RUNTIME_ENTRY_VA + (entry - COMMON_ENTRY_OFFSET)
        if entry is not None
        else None
    )
    return {
        "path": str(path),
        "size": len(data),
        "entry_offset": entry,
        "entry_source": "signature" if signature_entry is not None else ("header" if decoded_entry is not None else None),
        "runtime_entry_va": runtime_entry_va,
        "runtime_file_base": (runtime_entry_va - entry) if entry is not None and runtime_entry_va is not None else None,
        "legacy_file_base_from_dlx_refs": legacy_file_base,
        "legacy_entry_va_from_dlx_refs": (legacy_file_base + entry)
        if legacy_file_base is not None and entry is not None
        else None,
        "bss_start": bss_start,
        "bss_end": bss_end,
        "header_words": [f"0x{x:08x}" for x in header_words],
        "shell_paths": shell_paths(data)[:12],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Infer layout details from a BBK native BDA.")
    ap.add_argument("bda", type=Path)
    ns = ap.parse_args()
    print(json.dumps(analyze(ns.bda), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
