"""HCI -> L2CAP decoding: connection tracking, ACL reassembly and L2CAP channel mapping.

Layering, bottom to top::

    HCI ACL packet   handle(12b) | PB(2b) | BC(2b) | length u16 | fragment
    L2CAP PDU        length u16 | channel id u16 | payload            (may span ACL fragments)
    payload          ATT (LE, CID 0x0004), RFCOMM (PSM 0x0003), signaling, SMP, ...

LE links use fixed channel ids, so ATT is always CID 0x0004. Classic (BR/EDR) links open
dynamic channels via L2CAP signaling; we watch Connection Request/Response to learn which
dynamic CID carries which PSM (0x0003 = RFCOMM, which carries SPP serial data).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Iterator

from .btsnoop import Direction, PacketType, Record

CID_SIGNALING = 0x0001
CID_ATT = 0x0004
CID_LE_SIGNALING = 0x0005
CID_SMP = 0x0006

PSM_SDP = 0x0001
PSM_RFCOMM = 0x0003
PSM_AVCTP = 0x0017  # AVRCP: play/pause/volume, standard - no reverse engineering needed
PSM_AVDTP = 0x0019  # A2DP audio streaming
PSM_ATT = 0x001F  # GATT over classic

PSM_NAMES = {
    PSM_SDP: "SDP",
    PSM_RFCOMM: "RFCOMM",
    PSM_AVCTP: "AVCTP",
    PSM_AVDTP: "AVDTP",
    PSM_ATT: "ATT",
    0x001B: "AVCTP-browsing",
    0x0011: "HID-control",
    0x0013: "HID-interrupt",
}

# ACL handles that carry controller diagnostics instead of a device link. Seen in snoop logs
# from a Qualcomm-based Android phone: ACL traffic on 0x0EDC that no Connection Complete event
# ever opens, flowing only controller -> host, with payloads matching no protocol. That points
# to the phone's Bluetooth chip reporting about itself (inferred), so the handle is kept out of
# L2CAP decoding and counted separately unless a connection event really opens it.
DIAGNOSTIC_HANDLES = {0x0EDC}

# HCI event codes we decode.
EVT_DISCONNECTION_COMPLETE = 0x05
EVT_CONNECTION_COMPLETE = 0x03
EVT_LE_META = 0x3E
LE_CONNECTION_COMPLETE = 0x01
LE_ENHANCED_CONNECTION_COMPLETE = 0x0A
LE_ENHANCED_CONNECTION_COMPLETE_V2 = 0x29


def format_address(raw: bytes) -> str:
    """HCI carries BD_ADDRs little-endian; display them the usual way."""
    return ":".join(f"{b:02X}" for b in reversed(raw))


def parse_address(text: str) -> bytes:
    parts = bytes(int(p, 16) for p in text.split(":"))
    if len(parts) != 6:
        raise ValueError(f"not a Bluetooth address: {text!r}")
    return parts[::-1]


STATUS_CODES = {
    0x04: "page timeout (device not reachable)",
    0x05: "authentication failure",
    0x06: "PIN or key missing",
    0x08: "connection timeout",
    0x0B: "connection already exists",
    0x0D: "rejected: limited resources",
    0x0F: "rejected: unacceptable address",
    0x13: "remote user terminated",
    0x14: "remote: low resources",
    0x15: "remote: power off",
    0x16: "terminated by local host",
    0x22: "LMP response timeout",
    0x3E: "failed to establish",
}


def status_text(code: int) -> str:
    return f"0x{code:02x} {STATUS_CODES.get(code, '')}".strip()


@dataclass
class Connection:
    handle: int
    address: str
    transport: str  # "LE" or "BR/EDR"
    opened_frame: int
    closed_frame: int | None = None
    close_reason: int | None = None


@dataclass(frozen=True)
class FailedConnection:
    address: str
    transport: str
    status: int
    frame: int


@dataclass(frozen=True)
class L2capPdu:
    frame: int  # record index of the last fragment
    timestamp_us: int
    direction: Direction
    handle: int
    cid: int
    psm: int | None  # resolved for dynamic channels when the setup was captured
    payload: bytes

    @property
    def protocol(self) -> str:
        if self.cid == CID_ATT:
            return "ATT"
        if self.cid in (CID_SIGNALING, CID_LE_SIGNALING):
            return "L2CAP-SIG"
        if self.cid == CID_SMP:
            return "SMP"
        if self.psm is not None:
            return PSM_NAMES.get(self.psm, f"PSM 0x{self.psm:04x}")
        return f"CID 0x{self.cid:04x}"


class L2capDecoder:
    """Stateful decoder: feed HCI records in capture order, get complete L2CAP PDUs out."""

    def __init__(self) -> None:
        self.connections: dict[int, Connection] = {}
        self.history: list[Connection] = []
        self.failed: list[FailedConnection] = []
        self._partial: dict[tuple[int, Direction], tuple[int, bytearray]] = {}
        # (acl handle, direction the PDU travels, cid) -> psm
        self._channels: dict[tuple[int, Direction, int], int] = {}
        # (acl handle, requester's direction, requester's source cid) -> psm
        self._pending: dict[tuple[int, Direction, int], int] = {}
        self.acl_packets: dict[int, int] = {}  # per ACL handle, including diagnostic handles

    def feed(self, record: Record) -> Iterator[L2capPdu]:
        if record.packet_type is PacketType.EVENT:
            self._on_event(record)
        elif record.packet_type is PacketType.ACL:
            yield from self._on_acl(record)

    def decode(self, records: Iterable[Record]) -> Iterator[L2capPdu]:
        for record in records:
            yield from self.feed(record)

    # -- HCI events -------------------------------------------------------------------

    def _open(self, handle: int, address: bytes, transport: str, frame: int) -> None:
        conn = Connection(handle, format_address(address), transport, frame)
        self.connections[handle] = conn
        self.history.append(conn)

    def _on_event(self, record: Record) -> None:
        data = record.data
        if len(data) < 2:
            return
        code, params = data[0], data[2 : 2 + data[1]]
        if code == EVT_CONNECTION_COMPLETE and len(params) >= 9:
            if params[0] == 0:
                handle = struct.unpack_from("<H", params, 1)[0] & 0x0FFF
                self._open(handle, params[3:9], "BR/EDR", record.index)
            else:
                self.failed.append(FailedConnection(format_address(params[3:9]), "BR/EDR", params[0], record.index))
        elif code == EVT_LE_META and params:
            sub = params[0]
            if (
                sub in (LE_CONNECTION_COMPLETE, LE_ENHANCED_CONNECTION_COMPLETE, LE_ENHANCED_CONNECTION_COMPLETE_V2)
                and len(params) >= 12
            ):
                if params[1] == 0:
                    handle = struct.unpack_from("<H", params, 2)[0] & 0x0FFF
                    self._open(handle, params[6:12], "LE", record.index)
                else:
                    self.failed.append(FailedConnection(format_address(params[6:12]), "LE", params[1], record.index))
        elif code == EVT_DISCONNECTION_COMPLETE and len(params) >= 4 and params[0] == 0:
            handle = struct.unpack_from("<H", params, 1)[0] & 0x0FFF
            conn = self.connections.pop(handle, None)
            if conn:
                conn.closed_frame = record.index
                conn.close_reason = params[3]
            for key in [k for k in self._channels if k[0] == handle]:
                del self._channels[key]

    # -- ACL / L2CAP ------------------------------------------------------------------

    def _on_acl(self, record: Record) -> Iterator[L2capPdu]:
        if len(record.data) < 4:
            return
        header, length = struct.unpack_from("<HH", record.data)
        handle, pb = header & 0x0FFF, (header >> 12) & 0x3
        self.acl_packets[handle] = self.acl_packets.get(handle, 0) + 1
        if handle in DIAGNOSTIC_HANDLES and not any(c.handle == handle for c in self.history):
            return
        fragment = record.data[4 : 4 + length]
        key = (handle, record.direction)
        if pb == 0b01:  # continuation of a previous start fragment
            state = self._partial.get(key)
            if state is None:
                return  # start fragment not captured; nothing to attach to
            state[1].extend(fragment)
        else:  # 0b00 / 0b10 / 0b11: start of a new PDU
            if len(fragment) < 4:
                return
            l2cap_len = struct.unpack_from("<H", fragment)[0]
            self._partial[key] = (l2cap_len, bytearray(fragment))
        l2cap_len, buf = self._partial[key]
        if len(buf) < 4 + l2cap_len:
            return
        del self._partial[key]
        cid = struct.unpack_from("<H", buf, 2)[0]
        payload = bytes(buf[4 : 4 + l2cap_len])
        if cid == CID_SIGNALING:
            self._on_signaling(handle, record.direction, payload)
        psm = self._channels.get((handle, record.direction, cid))
        yield L2capPdu(record.index, record.timestamp_us, record.direction, handle, cid, psm, payload)

    def _on_signaling(self, handle: int, direction: Direction, payload: bytes) -> None:
        offset = 0
        while offset + 4 <= len(payload):
            code, _ident, length = struct.unpack_from("<BBH", payload, offset)
            body = payload[offset + 4 : offset + 4 + length]
            offset += 4 + length
            if code == 0x02 and len(body) >= 4:  # Connection Request: PSM, source CID
                psm, scid = struct.unpack_from("<HH", body)
                self._pending[(handle, direction, scid)] = psm
                # Traffic toward the requester is addressed to the requester's CID.
                self._channels[(handle, direction.opposite(), scid)] = psm
            elif code == 0x03 and len(body) >= 8:  # Connection Response: DCID, SCID, result
                dcid, scid, result = struct.unpack_from("<HHH", body)
                psm = self._pending.get((handle, direction.opposite(), scid))
                if psm is not None and result == 0:
                    # Traffic toward the responder is addressed to the responder's CID.
                    self._channels[(handle, direction.opposite(), dcid)] = psm


def build_acl(handle: int, cid: int, payload: bytes, max_fragment: int = 27) -> list[bytes]:
    """Wrap a payload in L2CAP + HCI ACL, fragmenting like a controller with small buffers."""
    pdu = struct.pack("<HH", len(payload), cid) + payload
    packets = []
    for i in range(0, len(pdu), max_fragment):
        pb = 0b10 if i == 0 else 0b01
        chunk = pdu[i : i + max_fragment]
        packets.append(struct.pack("<HH", handle | (pb << 12), len(chunk)) + chunk)
    return packets


def build_le_connection_complete(handle: int, address: str) -> bytes:
    params = (
        bytes([LE_CONNECTION_COMPLETE, 0x00])
        + struct.pack("<HBB", handle, 0x00, 0x00)
        + parse_address(address)
        + struct.pack("<HHHB", 0x0018, 0x0000, 0x01F4, 0x00)
    )
    return bytes([EVT_LE_META, len(params)]) + params


def build_connection_complete(handle: int, address: str) -> bytes:
    """Classic (BR/EDR) Connection Complete event for an ACL link."""
    params = struct.pack("<BH", 0x00, handle) + parse_address(address) + bytes([0x01, 0x00])
    return bytes([EVT_CONNECTION_COMPLETE, len(params)]) + params


def build_l2cap_connect(ident: int, psm: int, scid: int) -> bytes:
    """Signaling-channel Connection Request; send on CID 0x0001."""
    return struct.pack("<BBHHH", 0x02, ident, 4, psm, scid)


def build_l2cap_connect_response(ident: int, dcid: int, scid: int) -> bytes:
    return struct.pack("<BBHHHHH", 0x03, ident, 8, dcid, scid, 0, 0)


def build_disconnection_complete(handle: int, reason: int = 0x13) -> bytes:
    params = struct.pack("<BHB", 0x00, handle, reason)
    return bytes([EVT_DISCONNECTION_COMPLETE, len(params)]) + params
