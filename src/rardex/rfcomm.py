"""RFCOMM frames (serial port emulation over classic Bluetooth, used by SPP).

Many classic-Bluetooth speakers expose their app protocol on an SPP channel instead of BLE.
In the capture that is: L2CAP (PSM 0x0003) -> RFCOMM UIH frames -> your vendor bytes.

Frame layout (TS 07.10 basic option)::

    address | control | length (1 or 2 bytes) | [credits] | information | FCS

* address: EA bit, C/R bit, then DLCI (6 bits). Server channel = DLCI >> 1.
* DLCI 0 is the multiplexer control channel; data lives on DLCI >= 2.
* With credit based flow control, UIH frames with the P/F bit set carry one credit byte.
"""

from __future__ import annotations

from dataclasses import dataclass

from .btsnoop import Direction

SABM, UA, DM, DISC, UIH = 0x2F, 0x63, 0x0F, 0x43, 0xEF
FRAME_NAMES = {SABM: "SABM", UA: "UA", DM: "DM", DISC: "DISC", UIH: "UIH"}
PF_BIT = 0x10


def _crc_step(crc: int, byte: int) -> int:
    crc ^= byte
    for _ in range(8):
        crc = (crc >> 1) ^ 0xE0 if crc & 1 else crc >> 1
    return crc


def fcs(data: bytes) -> int:
    """TS 07.10 frame check sequence (reflected CRC-8, poly x^8+x^2+x+1)."""
    crc = 0xFF
    for b in data:
        crc = _crc_step(crc, b)
    return 0xFF - crc


@dataclass(frozen=True)
class RfcommFrame:
    frame: int
    timestamp_us: int
    direction: Direction
    conn: int
    dlci: int
    kind: int  # SABM/UA/DM/DISC/UIH
    poll_final: bool
    credits: int | None
    payload: bytes
    fcs_ok: bool

    @property
    def channel(self) -> int:
        return self.dlci >> 1

    @property
    def name(self) -> str:
        return FRAME_NAMES.get(self.kind, f"0x{self.kind:02x}")

    @property
    def is_data(self) -> bool:
        return self.kind == UIH and self.dlci != 0 and bool(self.payload)


def parse(frame: int, timestamp_us: int, direction: Direction, conn: int, data: bytes) -> RfcommFrame | None:
    if len(data) < 4:
        return None
    address, control = data[0], data[1]
    dlci = address >> 2
    kind = control & ~PF_BIT & 0xFF
    pf = bool(control & PF_BIT)
    if data[2] & 1:
        length, header = data[2] >> 1, 3
    else:
        if len(data) < 5:
            return None
        length, header = (data[2] >> 1) | (data[3] << 7), 4
    credits = None
    if kind == UIH and pf and dlci != 0:
        credits = data[header]
        header += 1
    payload = data[header : header + length]
    if len(payload) != length or header + length >= len(data):
        return None
    covered = data[:2] if kind == UIH else data[: header - (1 if credits is not None else 0)]
    fcs_ok = fcs(covered) == data[header + length]
    return RfcommFrame(frame, timestamp_us, direction, conn, dlci, kind, pf, credits, payload, fcs_ok)


def build_control(dlci: int, kind: int, initiator: bool = True) -> bytes:
    """SABM/UA/DISC/DM frame (no information field), P/F bit set."""
    head = bytes([(dlci << 2) | (0x02 if initiator else 0x00) | 0x01, kind | PF_BIT, 0x01])
    return head + bytes([fcs(head)])


def build_uih(dlci: int, payload: bytes, initiator: bool = True, credits: int | None = None) -> bytes:
    """Build a UIH data frame; ``initiator`` sets the C/R bit as the connecting side does."""
    address = (dlci << 2) | (0x02 if initiator else 0x00) | 0x01
    control = UIH | (PF_BIT if credits is not None else 0)
    if len(payload) < 128:
        length = bytes([(len(payload) << 1) | 1])
    else:
        length = bytes([(len(payload) << 1) & 0xFE, len(payload) >> 7])
    head = bytes([address, control]) + length + (bytes([credits]) if credits is not None else b"")
    return head + payload + bytes([fcs(bytes([address, control]))])
