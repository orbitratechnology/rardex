"""Turn a pile of captured frames into hypotheses about their structure.

Everything here is *inference* from samples. Each finding says what evidence supports it,
so you can decide what to confirm with a controlled experiment (change one setting in the
app, capture again, see which byte moved).
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field

from . import checksum
from .util import hexs

_FORMATS = {"u8": (1, "little"), "u16le": (2, "little"), "u16be": (2, "big")}


@dataclass(frozen=True)
class LengthField:
    offset: int
    fmt: str
    adjust: int  # field value == len(frame) + adjust

    def describe(self) -> str:
        rel = "frame length" if self.adjust == 0 else f"frame length {self.adjust:+d}"
        return f"{self.fmt} at offset {self.offset} = {rel}"


@dataclass(frozen=True)
class Slider:
    offset: int
    values: list[int]  # distinct values in the order they first appear
    step: int  # every change moved the value by exactly this much, up or down

    @property
    def low(self) -> int:
        return min(self.values)

    @property
    def high(self) -> int:
        return max(self.values)


@dataclass
class Cluster:
    key: int | None  # value of the command-id byte, None when not clustered
    frames: list[bytes]
    mask: str  # "a5 5a 02 ?? ??" - constant bytes shown, varying bytes as ??
    varying: dict[int, list[int]]
    sliders: list[Slider]


@dataclass
class Report:
    frames: list[bytes]
    distinct: int
    lengths: Counter
    prefix: bytes
    suffix: bytes
    length_fields: list[LengthField]
    lengths_vary: bool
    checksum: checksum.Detection
    command_offset: int | None
    clusters: list[Cluster] = field(default_factory=list)


def common_prefix(frames: list[bytes]) -> bytes:
    return os.path.commonprefix(frames) if frames else b""  # type: ignore[return-value]


def common_suffix(frames: list[bytes]) -> bytes:
    return common_prefix([f[::-1] for f in frames])[::-1] if frames else b""


def find_length_fields(frames: list[bytes], max_offset: int = 8) -> list[LengthField]:
    found = []
    shortest = min(len(f) for f in frames)
    for offset in range(min(max_offset, shortest)):
        for fmt, (width, order) in _FORMATS.items():
            if offset + width > shortest:
                continue
            adjusts = {
                int.from_bytes(f[offset : offset + width], order) - len(f)  # type: ignore[arg-type]
                for f in frames
            }
            if len(adjusts) == 1:
                adjust = adjusts.pop()
                if -16 <= adjust <= 0:
                    found.append(LengthField(offset, fmt, adjust))
    # With short frames a u16 length has a zero high byte, so it also matches as a u8 at the
    # low byte's offset. The samples cannot tell them apart; report the u8 once.
    singles = {(lf.offset, lf.adjust) for lf in found if lf.fmt == "u8"}
    return [
        lf
        for lf in found
        if lf.fmt == "u8" or ((lf.offset if lf.fmt == "u16le" else lf.offset + 1), lf.adjust) not in singles
    ]


def _mask(frames: list[bytes]) -> tuple[str, dict[int, list[int]]]:
    length = len(frames[0])
    varying: dict[int, list[int]] = {}
    cells = []
    for i in range(length):
        values = list(dict.fromkeys(f[i] for f in frames))
        if len(values) == 1:
            cells.append(f"{values[0]:02x}")
        else:
            cells.append("??")
            varying[i] = values
    return " ".join(cells), varying


def _sliders(frames: list[bytes], offsets: list[int]) -> list[Slider]:
    """Bytes that move in equal steps between consecutive frames, like a dragged slider.

    Enums jump around (01 02 03 00), timers take arbitrary values (1e 5a 2c), but dragging
    a volume slider produces 09 0a 0b ... 10 0f 0e: every change has the same size.
    """
    out = []
    for i in offsets:
        seq = [f[i] for f in frames]
        magnitudes = {abs(b - a) for a, b in zip(seq, seq[1:]) if b != a}
        distinct = list(dict.fromkeys(seq))
        if len(distinct) >= 3 and len(magnitudes) == 1:
            out.append(Slider(i, distinct, magnitudes.pop()))
    return out


def _pick_command_offset(frames: list[bytes], start: int, skip: set[int]) -> int | None:
    shortest = min(len(f) for f in frames)
    for offset in range(start, shortest):
        if offset in skip:
            continue
        values = {f[offset] for f in frames}
        if len(values) > 1:
            return offset if len(values) <= 32 else None
    return None


def analyze(frames: list[bytes]) -> Report:
    if not frames:
        raise ValueError("no frames to analyze")
    distinct = sorted(set(frames))
    lengths = Counter(len(f) for f in frames)
    prefix, suffix = common_prefix(frames), common_suffix(frames)
    lengths_vary = len(lengths) > 1
    length_fields = find_length_fields(distinct) if lengths_vary else []
    det = checksum.detect(distinct)

    # Bytes explained by a length field or checksum are not command ids or sliders.
    explained_head: set[int] = set()
    for lf in length_fields:
        explained_head.update(range(lf.offset, lf.offset + _FORMATS[lf.fmt][0]))
    checksum_tail = max((m.width + m.trailer for m in det.matches), default=0)

    cmd = _pick_command_offset(frames, len(prefix), explained_head) if len(distinct) > 1 else None
    groups: dict[int | None, list[bytes]] = {}
    for f in frames:
        groups.setdefault(f[cmd] if cmd is not None else None, []).append(f)

    clusters = []
    for key, members in sorted(groups.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
        by_len: dict[int, list[bytes]] = {}
        for f in members:
            by_len.setdefault(len(f), []).append(f)
        for length, same in sorted(by_len.items()):
            mask, varying = _mask(same)
            candidates = [
                i for i in varying if i not in explained_head and i < length - checksum_tail
            ]
            clusters.append(Cluster(key, same, mask, varying, _sliders(same, candidates)))

    return Report(frames, len(distinct), lengths, prefix, suffix, length_fields, lengths_vary, det, cmd, clusters)


def format_report(r: Report, max_values: int = 10) -> str:
    lines = [
        f"frames: {len(r.frames)} ({r.distinct} distinct)",
        "lengths: " + ", ".join(f"{n}B x{c}" for n, c in sorted(r.lengths.items())),
    ]
    if r.prefix:
        lines.append(f"common prefix: {hexs(r.prefix)}   <- likely a sync/header marker")
    if r.suffix:
        lines.append(f"common suffix: {hexs(r.suffix)}")

    lines.append("")
    lines.append("length field:")
    if not r.lengths_vary:
        lines.append("  unknown - every frame has the same length; capture commands of different sizes")
    elif r.length_fields:
        lines += [f"  candidate: {lf.describe()}" for lf in r.length_fields]
    else:
        lines.append("  none found in the first 8 bytes")

    lines.append("")
    lines.append("checksum:")
    det = r.checksum
    if det.matches:
        for m in det.matches:
            lines.append(f"  candidate: {m.describe()}")
        lines.append(
            f"  ({det.combinations_tried} combinations tried on {det.distinct_frames} distinct frames; "
            f"expected chance matches ~{det.expected_false_positives:.2g})"
        )
        if det.expected_false_positives > 0.05:
            lines.append("  weak evidence: collect more distinct frames before trusting this")
    else:
        lines.append("  no common algorithm matched (could be absent, keyed, or cover an unusual range)")

    lines.append("")
    if r.command_offset is not None:
        lines.append(f"command id (inferred): byte at offset {r.command_offset}; frames grouped by it:")
    else:
        lines.append("frames grouped by length:")
    for c in r.clusters:
        label = f"0x{c.key:02x}" if c.key is not None else "--"
        lines.append(f"  [{label}] x{len(c.frames)}  {c.mask}")
        for offset, values in c.varying.items():
            shown = " ".join(f"{v:02x}" for v in values[:max_values])
            more = f" ... (+{len(values) - max_values})" if len(values) > max_values else ""
            lines.append(f"         offset {offset:>2}: {shown}{more}")
        for s in c.sliders:
            lines.append(
                f"         slider? offset {s.offset} moves in steps of {s.step} "
                f"within {s.low}..{s.high} (like a volume/brightness control)"
            )
    return "\n".join(lines)


def diff(a: bytes, b: bytes) -> str:
    """Two-line aligned hex diff with carets under differing bytes."""
    width = max(len(a), len(b))
    top, bottom, marks = [], [], []
    for i in range(width):
        x = f"{a[i]:02x}" if i < len(a) else "  "
        y = f"{b[i]:02x}" if i < len(b) else "  "
        top.append(x)
        bottom.append(y)
        marks.append("^^" if x != y else "  ")
    changed = [i for i in range(width) if (a[i : i + 1] != b[i : i + 1])]
    return "\n".join(
        [
            "a: " + " ".join(top),
            "b: " + " ".join(bottom),
            "   " + " ".join(marks).rstrip(),
            f"differs at offsets: {', '.join(map(str, changed)) or 'none'}",
        ]
    )
