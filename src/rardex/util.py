"""Small helpers shared by every module: hex parsing/formatting and time display."""

from __future__ import annotations

import re

_HEX_NOISE = re.compile(r"0x|[\s:,\-_]", re.IGNORECASE)


def parse_hex(text: str) -> bytes:
    """Parse hex in any of the forms people paste: ``aa55``, ``aa 55``, ``AA:55``, ``0xaa,0x55``."""
    cleaned = _HEX_NOISE.sub("", text)
    if len(cleaned) % 2:
        raise ValueError(f"odd number of hex digits in {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"not valid hex: {text!r}") from exc


def hexs(data: bytes, sep: str = " ") -> str:
    """Format bytes as lowercase hex pairs, e.g. ``aa 55 01``."""
    return data.hex(sep) if sep and data else data.hex()


def printable(data: bytes) -> str:
    """ASCII rendering with dots for non-printable bytes, like the right column of ``xxd``."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)


def fmt_handle(handle: int | None) -> str:
    return "------" if handle is None else f"0x{handle:04x}"


def fmt_seconds(us: int) -> str:
    """Relative time in seconds with millisecond precision."""
    return f"{us / 1_000_000:9.3f}s"
