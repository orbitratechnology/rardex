"""One call from a btsnoop file to the things a reverser cares about.

``decode(capture)`` runs every layer (HCI -> L2CAP -> ATT/RFCOMM/AVCTP/AVDTP) and returns a
``Session`` with the connections, the reconstructed GATT table and a list of application
"messages" in capture order: BLE writes/notifications/reads, RFCOMM serial data (including
HFP AT commands), AVRCP button/volume messages and AVDTP codec negotiation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import att, avdtp, avrcp, hfp, rfcomm, sdp
from .btsnoop import Capture, Direction
from .gatt import GattDatabase
from .hci import (
    CID_ATT,
    PSM_ATT,
    PSM_AVCTP,
    PSM_AVDTP,
    PSM_RFCOMM,
    PSM_SDP,
    Connection,
    FailedConnection,
    L2capDecoder,
    L2capPdu,
)


@dataclass(frozen=True)
class Message:
    """One unit of application data moving between the phone/PC and the device."""

    frame: int
    timestamp_us: int
    direction: Direction
    conn: int
    channel: str  # "ATT 0x0012", "RFCOMM ch1", "AVRCP", "AVDTP"
    kind: str  # WRITE, WRITE-NR, NOTIFY, READ, UIH, AT, PASS, VENDOR, SIGNAL, ...
    handle: int | None
    data: bytes
    note: str = ""  # decoded meaning for standard protocols (HFP, AVRCP, AVDTP)


@dataclass
class Session:
    capture: Capture
    connections: list[Connection]
    gatt: GattDatabase
    failed_connections: list[FailedConnection] = field(default_factory=list)
    acl_packets: dict[int, int] = field(default_factory=dict)  # per ACL handle
    att: list[att.AttPdu] = field(default_factory=list)
    rfcomm: list[rfcomm.RfcommFrame] = field(default_factory=list)
    l2cap: list[L2capPdu] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)
    at_lines: list[tuple[Message, hfp.AtLine]] = field(default_factory=list)
    avrcp: list[tuple[Message, avrcp.AvrcpMessage]] = field(default_factory=list)
    avdtp: list[tuple[Message, avdtp.AvdtpSignal]] = field(default_factory=list)
    sdp: list[tuple[Message, sdp.ServiceRecord]] = field(default_factory=list)  # message = completing response
    media_packets: int = 0  # A2DP audio packets seen (not decoded)

    def address_of(self, conn: int) -> str:
        found = [c for c in self.connections if c.handle == conn]
        return found[-1].address if found else f"conn 0x{conn:04x}"

    def select(
        self,
        handle: int | None = None,
        direction: Direction | None = None,
        channel: int | None = None,
        kinds: set[str] | None = None,
        name: str | None = None,
    ) -> list[Message]:
        out = []
        for m in self.messages:
            if handle is not None and m.handle != handle:
                continue
            if direction is not None and m.direction is not direction:
                continue
            if channel is not None and m.channel != f"RFCOMM ch{channel}":
                continue
            if kinds is not None and m.kind not in kinds:
                continue
            if name is not None and m.channel != name:
                continue
            out.append(m)
        return out


def decode(capture: Capture) -> Session:
    l2 = L2capDecoder()
    s = Session(capture, l2.history, GattDatabase(), l2.failed, l2.acl_packets)
    pending_reads: dict[tuple[int, Direction], int] = {}
    avdtp_signaling: dict[tuple[int, Direction], int] = {}  # first AVDTP CID = signaling
    at_channels: set[tuple[int, int]] = set()
    sdp_parts = sdp.SdpReassembler()
    for pdu in l2.decode(capture.records):
        s.l2cap.append(pdu)
        if pdu.cid == CID_ATT or pdu.psm == PSM_ATT:
            _on_att(s, pdu, pending_reads)
        elif pdu.psm == PSM_SDP:
            _on_sdp(s, pdu, sdp_parts)
        elif pdu.psm == PSM_RFCOMM:
            _on_rfcomm(s, pdu, at_channels)
        elif pdu.psm == PSM_AVCTP:
            msg = avrcp.parse(pdu.payload)
            if msg is not None:
                kind = "PASS" if msg.opcode == avrcp.OP_PASS_THROUGH else "VENDOR" if msg.pdu is not None else "AV/C"
                m = Message(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, "AVRCP", kind, None, pdu.payload, msg.describe())
                s.messages.append(m)
                s.avrcp.append((m, msg))
        elif pdu.psm == PSM_AVDTP:
            key = (pdu.handle, pdu.direction)
            if avdtp_signaling.setdefault(key, pdu.cid) != pdu.cid:
                s.media_packets += 1
                continue
            sig = avdtp.parse(pdu.payload)
            if sig is not None:
                m = Message(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, "AVDTP", "SIGNAL", None, pdu.payload, sig.describe())
                s.messages.append(m)
                s.avdtp.append((m, sig))
    return s


def _on_att(s: Session, pdu: L2capPdu, pending_reads: dict[tuple[int, Direction], int]) -> None:
    a = att.parse(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, pdu.payload)
    if a is None:
        return
    s.att.append(a)
    s.gatt.observe(a)
    handle = a.handle
    if a.opcode == att.Opcode.READ_REQ:
        pending_reads[(a.conn, a.direction)] = a.handle
    elif a.opcode in (att.Opcode.READ_RSP, att.Opcode.READ_BLOB_RSP):
        handle = pending_reads.pop((a.conn, a.direction.opposite()), None)
    if a.carries_data:
        s.messages.append(Message(a.frame, a.timestamp_us, a.direction, a.conn, f"ATT {_h(handle)}", a.name, handle, a.value))


def _on_sdp(s: Session, pdu: L2capPdu, parts: sdp.SdpReassembler) -> None:
    p = sdp.parse_pdu(pdu.payload)
    if p is None:
        return
    records = parts.feed((pdu.handle, pdu.direction), p, pdu.frame)
    if p.search_uuids:
        note = "search: " + ", ".join(u.name for u in p.search_uuids)
    elif records:
        note = " | ".join(r.describe() for r in records)
    elif records == []:
        note = "no matching records"
    else:
        note = p.name + (" (continued)" if p.pdu_id in (sdp.ATTR_RSP, sdp.SEARCH_ATTR_RSP) else "")
    kind = "RSP" if p.pdu_id & 1 else "REQ"
    m = Message(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, "SDP", kind, None, pdu.payload, note)
    s.messages.append(m)
    s.sdp += [(m, r) for r in records or []]


def _on_rfcomm(s: Session, pdu: L2capPdu, at_channels: set[tuple[int, int]]) -> None:
    r = rfcomm.parse(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, pdu.payload)
    if r is None:
        return
    s.rfcomm.append(r)
    if not r.is_data:
        return
    key = (r.conn, r.channel)
    if key not in at_channels and hfp.looks_like_at(r.payload):
        at_channels.add(key)
    if key in at_channels:
        lines = hfp.split_lines(r.payload, from_headset=r.direction is Direction.RECEIVED)
        note = " | ".join(f"{ln.text}" + (f"  ({d})" if (d := ln.describe()) else "") for ln in lines)
        m = Message(r.frame, r.timestamp_us, r.direction, r.conn, f"RFCOMM ch{r.channel}", "AT", None, r.payload, note)
        s.messages.append(m)
        s.at_lines += [(m, ln) for ln in lines]
    else:
        s.messages.append(Message(r.frame, r.timestamp_us, r.direction, r.conn, f"RFCOMM ch{r.channel}", "UIH", None, r.payload))


def _h(handle: int | None) -> str:
    return "0x????" if handle is None else f"0x{handle:04x}"
