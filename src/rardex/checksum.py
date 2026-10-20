"""Checksums seen in small-device protocols, plus a brute-force detector.

Vendor frames often end in a 1-2 byte integrity check. Rather than guess, test every common
algorithm against every plausible covered range and keep what matches *all* frames.

How much to trust a match: a random 8-bit value matches by chance with probability 1/256 per
frame. With C (algorithm, range) combinations tried over n *distinct* frames, the expected
number of coincidental matches is about C / 256**n. ``detect`` reports that number - with
3+ distinct frames it is tiny; with one frame it is not, so collect more frames.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


def _crc_msb(width: int, poly: int, init: int, xorout: int = 0) -> Callable[[bytes], int]:
    top, mask = 1 << (width - 1), (1 << width) - 1

    def crc(data: bytes) -> int:
        reg = init
        for b in data:
            reg ^= b << (width - 8)
            for _ in range(8):
                reg = ((reg << 1) ^ poly) if reg & top else reg << 1
                reg &= mask
        return reg ^ xorout

    return crc


def _crc_lsb(width: int, poly_reflected: int, init: int, xorout: int = 0) -> Callable[[bytes], int]:
    def crc(data: bytes) -> int:
        reg = init
        for b in data:
            reg ^= b
            for _ in range(8):
                reg = (reg >> 1) ^ poly_reflected if reg & 1 else reg >> 1
        return reg ^ xorout

    return crc


def _xor8(data: bytes) -> int:
    out = 0
    for b in data:
        out ^= b
    return out


@dataclass(frozen=True)
class Algorithm:
    name: str
    width: int  # bytes
    fn: Callable[[bytes], int]
    note: str

    def __call__(self, data: bytes) -> int:
        return self.fn(data)


ALGORITHMS: dict[str, Algorithm] = {
    a.name: a
    for a in [
        Algorithm("sum8", 1, lambda d: sum(d) & 0xFF, "sum of bytes mod 256"),
        Algorithm("sum8_neg", 1, lambda d: -sum(d) & 0xFF, "two's complement: frame sums to 0"),
        Algorithm("sum8_not", 1, lambda d: ~sum(d) & 0xFF, "one's complement of sum"),
        Algorithm("xor8", 1, _xor8, "XOR of all bytes"),
        Algorithm("crc8", 1, _crc_msb(8, 0x07, 0x00), "CRC-8/SMBUS poly 0x07"),
        Algorithm("crc8_maxim", 1, _crc_lsb(8, 0x8C, 0x00), "CRC-8/MAXIM (Dallas 1-Wire)"),
        Algorithm("sum16", 2, lambda d: sum(d) & 0xFFFF, "sum of bytes mod 65536"),
        Algorithm("crc16_modbus", 2, _crc_lsb(16, 0xA001, 0xFFFF), "CRC-16/MODBUS"),
        Algorithm("crc16_arc", 2, _crc_lsb(16, 0xA001, 0x0000), "CRC-16/ARC (IBM)"),
        Algorithm("crc16_kermit", 2, _crc_lsb(16, 0x8408, 0x0000), "CRC-16/KERMIT"),
        Algorithm("crc16_ccitt_false", 2, _crc_msb(16, 0x1021, 0xFFFF), "CRC-16/CCITT-FALSE"),
        Algorithm("crc16_xmodem", 2, _crc_msb(16, 0x1021, 0x0000), "CRC-16/XMODEM"),
    ]
}


def compute(name: str, data: bytes, byteorder: str = "little") -> bytes:
    algo = ALGORITHMS[name]
    return algo(data).to_bytes(algo.width, byteorder)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Match:
    algorithm: str
    byteorder: str  # irrelevant for 1-byte checksums
    start: int  # checksum covers frame[start : len - width - trailer]
    trailer: int  # constant bytes after the checksum (e.g. an end marker)
    width: int

    def describe(self) -> str:
        span = f"frame[{self.start}:-{self.width + self.trailer}]"
        order = f", {self.byteorder}-endian" if self.width > 1 else ""
        tail = f", followed by {self.trailer} constant byte(s)" if self.trailer else ""
        return f"{self.algorithm}{order} over {span}{tail}"


@dataclass
class Detection:
    matches: list[Match]
    distinct_frames: int
    tried_by_width: dict[int, int]  # checksum width in bytes -> combinations tested

    @property
    def combinations_tried(self) -> int:
        return sum(self.tried_by_width.values())

    @property
    def expected_false_positives(self) -> float:
        if not self.distinct_frames:
            return float("inf")
        return sum(n / 256 ** (w * self.distinct_frames) for w, n in self.tried_by_width.items())


def detect(frames: list[bytes], max_start: int = 4, max_trailer: int = 2) -> Detection:
    """Find (algorithm, range) combinations that explain the checksum of every frame."""
    distinct = sorted(set(frames))
    tried: dict[int, int] = {}
    matches: list[Match] = []
    for trailer in range(max_trailer + 1):
        if trailer and len({f[-trailer:] for f in distinct}) != 1:
            continue  # trailer bytes must be constant to be a terminator
        for algo in ALGORITHMS.values():
            for order in ("little", "big") if algo.width > 1 else ("little",):
                for start in range(max_start + 1):
                    end = algo.width + trailer
                    if any(len(f) < start + end + 1 for f in distinct):
                        continue
                    tried[algo.width] = tried.get(algo.width, 0) + 1
                    if all(
                        algo(f[start : len(f) - end]).to_bytes(algo.width, order)  # type: ignore[arg-type]
                        == f[len(f) - end : len(f) - trailer]
                        for f in distinct
                    ):
                        matches.append(Match(algo.name, order, start, trailer, algo.width))
    return Detection(matches, len(distinct), tried)
