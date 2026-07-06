from __future__ import annotations

from dataclasses import dataclass
import struct


XOR_KEY = 0x44525744
CHECKSUM_OFF = 0x84
CHECKSUM_XOR_KEY = 0x322D464B
TITLE_OFFSET = 0x2C
TITLE_SIZE = 16
CATEGORY_OFFSET = 0x0C
ENCODED_WORD_END = 0x2C
U32_MIN = 0
U32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class BdaHeaderFields:
    magic: int = 0x004B4242
    word04: int = 0x5D245562
    version: int = 0x01000102
    category: int = 9
    file_size_minus_4: int = 0
    entry_offset: int = 0x95F8
    icon_start: int = 0x88
    icon0_size: int = 0
    icon1_size: int = 0
    icon2_size: int = 0
    icon3_size: int = 0

    def words(self) -> tuple[int, ...]:
        return (
            self.magic,
            self.word04,
            self.version,
            self.category,
            self.file_size_minus_4,
            self.entry_offset,
            self.icon_start,
            self.icon0_size,
            self.icon1_size,
            self.icon2_size,
            self.icon3_size,
        )


def encode_word(decoded: int) -> int:
    return decoded ^ XOR_KEY


def decode_word(encoded: int) -> int:
    return encoded ^ XOR_KEY


def validate_u32_field(name: str, value: int) -> None:
    if not isinstance(value, int):
        raise ValueError(f"header field {name} must be int, got {type(value).__name__}")
    if value < U32_MIN or value > U32_MAX:
        raise ValueError(f"header field {name}=0x{value:x} is outside u32 range")


def put_encoded_word(data: bytearray, off: int, decoded: int) -> None:
    validate_u32_field(f"word@0x{off:x}", decoded)
    struct.pack_into("<I", data, off, encode_word(decoded))


def get_decoded_word(data: bytes, off: int) -> int:
    return decode_word(struct.unpack_from("<I", data, off)[0])


def decoded_header_words(data: bytes) -> list[int]:
    limit = min(ENCODED_WORD_END, len(data) - (len(data) % 4))
    return [get_decoded_word(data, off) for off in range(0, limit, 4)]


def set_title(data: bytearray, title: str) -> None:
    encoded = title.encode("gbk")
    if len(encoded) > TITLE_SIZE:
        raise ValueError(f"title is {len(encoded)} bytes in GBK, max {TITLE_SIZE}")
    data[TITLE_OFFSET : TITLE_OFFSET + TITLE_SIZE] = encoded.ljust(TITLE_SIZE, b"\0")


def get_title(data: bytes) -> str:
    raw = data[TITLE_OFFSET : TITLE_OFFSET + TITLE_SIZE]
    return raw.split(b"\0", 1)[0].decode("gbk", "replace")


def set_category(data: bytearray, category: int) -> None:
    validate_u32_field("category", category)
    put_encoded_word(data, CATEGORY_OFFSET, category)


def get_category(data: bytes) -> int:
    return get_decoded_word(data, CATEGORY_OFFSET)


def decoded_checksum_sum(data: bytes) -> int:
    if len(data) < CHECKSUM_OFF:
        raise ValueError(f"data is too short for BDA header checksum: 0x{len(data):x}")
    buf = bytearray(data[:CHECKSUM_OFF])
    for off in range(0, ENCODED_WORD_END, 4):
        struct.pack_into("<I", buf, off, get_decoded_word(buf, off))
    return sum(buf) & 0xFFFFFFFF


def fix_header_checksum(data: bytearray) -> int:
    checksum = decoded_checksum_sum(data) ^ CHECKSUM_XOR_KEY
    data[CHECKSUM_OFF : CHECKSUM_OFF + 4] = checksum.to_bytes(4, "little")
    return checksum


def checksum_ok(data: bytes) -> bool:
    if len(data) < CHECKSUM_OFF + 4:
        return False
    expected = decoded_checksum_sum(data)
    actual = struct.unpack_from("<I", data, CHECKSUM_OFF)[0] ^ CHECKSUM_XOR_KEY
    return actual == expected


def _validate_header_fields(fields: BdaHeaderFields) -> None:
    for name, value in zip(BdaHeaderFields.__dataclass_fields__, fields.words()):
        validate_u32_field(name, value)


def write_header(data: bytearray, fields: BdaHeaderFields, title: str) -> None:
    if len(data) < CHECKSUM_OFF + 4:
        raise ValueError(f"data is too short for BDA header: 0x{len(data):x}")
    _validate_header_fields(fields)
    for idx, word in enumerate(fields.words()):
        put_encoded_word(data, idx * 4, word)
    set_title(data, title)
    data[TITLE_OFFSET + TITLE_SIZE : CHECKSUM_OFF] = b"\0" * (CHECKSUM_OFF - TITLE_OFFSET - TITLE_SIZE)
    fix_header_checksum(data)


def verify(data: bytes) -> dict[str, object]:
    words = decoded_header_words(data)
    return {
        "title": get_title(data),
        "category": words[3] if len(words) > 3 else None,
        "file_size_minus_4": words[4] if len(words) > 4 else None,
        "entry_offset": words[5] if len(words) > 5 else None,
        "icon_start": words[6] if len(words) > 6 else None,
        "icon_sizes": words[7:11],
        "checksum_ok": checksum_ok(data),
    }
