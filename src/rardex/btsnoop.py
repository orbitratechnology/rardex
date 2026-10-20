"""Reader and writer for btsnoop captures.

btsnoop is the format Android writes when "Enable Bluetooth HCI snoop log" is on, and
the format ``btmon -w`` writes on Linux. Every record is one HCI packet exchanged between
the host (phone/PC Bluetooth stack) and the controller (the Bluetooth chip). Everything
the vendor app says to the speaker passes through here.

File layout (all integers big-endian)::

    header:  "btsnoop\\0" | version u32 (=1) | datalink u32
    record:  orig_len u32 | incl_len u32 | flags u32 | drops u32 | timestamp i64 | data

Timestamps count microseconds since 0000-01-01; ``EPOCH_DELTA_US`` converts to Unix time.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable

MAGIC = b"btsnoop\x00"
EPOCH_DELTA_US = 0x00DCDDB30F2F8000
_HEADER = struct.Struct(">8sII")
_RECORD = struct.Struct(">IIIIq")


class Datalink(IntEnum):
    H1 = 1001  # unencapsulated HCI; packet type comes from the record flags
    H4 = 1002  # HCI UART: first data byte is the packet type (Android uses this)
    BCSP = 1003
    H5 = 1004
    MONITOR = 2001  # Linux btmon; packet type and direction come from an opcode in the flags


class PacketType(IntEnum):
    COMMAND = 0x01
    ACL = 0x02
    SCO = 0x03
    EVENT = 0x04
    ISO = 0x05


class Direction(IntEnum):
    SENT = 0  # host -> controller, i.e. phone/PC -> speaker
    RECEIVED = 1  # controller -> host, i.e. speaker -> phone/PC

    @property
    def arrow(self) -> str:
        return "->" if self is Direction.SENT else "<-"

    def opposite(self) -> "Direction":
        return Direction.RECEIVED if self is Direction.SENT else Direction.SENT


# btmon (datalink 2001) opcodes carried in the low 16 bits of the flags field.
_MONITOR_OPCODES = {
    2: (PacketType.COMMAND, Direction.SENT),
    3: (PacketType.EVENT, Direction.RECEIVED),
    4: (PacketType.ACL, Direction.SENT),
    5: (PacketType.ACL, Direction.RECEIVED),
    6: (PacketType.SCO, Direction.SENT),
    7: (PacketType.SCO, Direction.RECEIVED),
    18: (PacketType.ISO, Direction.SENT),
    19: (PacketType.ISO, Direction.RECEIVED),
}


class BtsnoopError(ValueError):
    pass


@dataclass(frozen=True)
class Record:
    index: int  # 1-based record number; matches Wireshark's frame.number
    timestamp_us: int  # Unix epoch, microseconds
    direction: Direction
    packet_type: PacketType
    data: bytes  # the HCI packet without any H4 type byte
    original_length: int  # as recorded; includes the H4 type byte on H4 captures
    dropped: int = 0


@dataclass
class Capture:
    datalink: Datalink
    records: list[Record] = field(default_factory=list)
    skipped: int = 0  # records whose packet type could not be determined (e.g. btmon notes)
    truncated_tail: bool = False  # file ended mid-record (common when pulled while logging)

    @property
    def start_us(self) -> int:
        return self.records[0].timestamp_us if self.records else 0

    @property
    def duration_us(self) -> int:
        return self.records[-1].timestamp_us - self.start_us if self.records else 0


def _classify(datalink: Datalink, flags: int, data: bytes) -> tuple[PacketType, Direction, bytes] | None:
    if datalink is Datalink.H4:
        if not data:
            return None
        try:
            ptype = PacketType(data[0])
        except ValueError:
            return None
        return ptype, Direction(flags & 1), data[1:]
    if datalink is Datalink.H1:
        direction = Direction(flags & 1)
        if flags & 2:
            ptype = PacketType.COMMAND if direction is Direction.SENT else PacketType.EVENT
        else:
            ptype = PacketType.ACL
        return ptype, direction, data
    if datalink is Datalink.MONITOR:
        mapped = _MONITOR_OPCODES.get(flags & 0xFFFF)
        if mapped is None:
            return None
        return mapped[0], mapped[1], data
    return None


def parse(blob: bytes) -> Capture:
    if len(blob) < _HEADER.size:
        raise BtsnoopError("file too short for a btsnoop header")
    magic, version, datalink_raw = _HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise BtsnoopError(f"not a btsnoop file (magic {magic!r})")
    if version != 1:
        raise BtsnoopError(f"unsupported btsnoop version {version}")
    try:
        datalink = Datalink(datalink_raw)
    except ValueError as exc:
        raise BtsnoopError(f"unknown btsnoop datalink {datalink_raw}") from exc
    if datalink in (Datalink.BCSP, Datalink.H5):
        raise BtsnoopError(f"datalink {datalink.name} is not supported; capture with H4 (Android default)")

    capture = Capture(datalink)
    offset = _HEADER.size
    index = 0
    while offset < len(blob):
        if offset + _RECORD.size > len(blob):
            capture.truncated_tail = True
            break
        orig_len, incl_len, flags, drops, ts = _RECORD.unpack_from(blob, offset)
        offset += _RECORD.size
        if offset + incl_len > len(blob):
            capture.truncated_tail = True
            break
        data = blob[offset : offset + incl_len]
        offset += incl_len
        index += 1
        classified = _classify(datalink, flags, data)
        if classified is None:
            capture.skipped += 1
            continue
        ptype, direction, payload = classified
        capture.records.append(
            Record(index, ts - EPOCH_DELTA_US, direction, ptype, payload, orig_len, drops)
        )
    return capture


def load(path: str | Path) -> Capture:
    return parse(Path(path).read_bytes())


def dump(records: Iterable[Record]) -> bytes:
    """Serialize records as an H4 btsnoop file (the layout Android produces)."""
    out = bytearray(_HEADER.pack(MAGIC, 1, Datalink.H4))
    for rec in records:
        data = bytes([rec.packet_type]) + rec.data
        flags = int(rec.direction)
        if rec.packet_type in (PacketType.COMMAND, PacketType.EVENT):
            flags |= 2
        out += _RECORD.pack(len(data), len(data), flags, rec.dropped, rec.timestamp_us + EPOCH_DELTA_US)
        out += data
    return bytes(out)


def save(path: str | Path, records: Iterable[Record]) -> None:
    Path(path).write_bytes(dump(records))
