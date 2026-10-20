"""One call from a btsnoop file to the things a reverser cares about.

``decode(capture)`` runs every layer (HCI -> L2CAP -> ATT/RFCOMM) and returns a ``Session``
with the connections, the reconstructed GATT table and a list of application-data
"messages" in capture order: BLE writes/notifications/reads and RFCOMM serial data.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import att, rfcomm
from .btsnoop import Capture, Direction
from .gatt import GattDatabase
from .hci import CID_ATT, PSM_ATT, PSM_RFCOMM, Connection, L2capDecoder, L2capPdu


@dataclass(frozen=True)
class Message:
    """One unit of application data moving between the app and the device."""

    frame: int
    timestamp_us: int
    direction: Direction
    conn: int
    channel: str  # "ATT 0x0012" or "RFCOMM ch1"
    kind: str  # WRITE, WRITE-NR, NOTIFY, READ, UIH, ...
    handle: int | None
    data: bytes


@dataclass
class Session:
    capture: Capture
    connections: list[Connection]
    gatt: GattDatabase
    att: list[att.AttPdu] = field(default_factory=list)
    rfcomm: list[rfcomm.RfcommFrame] = field(default_factory=list)
    l2cap: list[L2capPdu] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)

    def address_of(self, conn: int) -> str:
        found = [c for c in self.connections if c.handle == conn]
        return found[-1].address if found else f"conn 0x{conn:04x}"

    def select(
        self,
        handle: int | None = None,
        direction: Direction | None = None,
        channel: int | None = None,
        kinds: set[str] | None = None,
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
            out.append(m)
        return out


def decode(capture: Capture) -> Session:
    l2 = L2capDecoder()
    session = Session(capture, l2.history, GattDatabase())
    pending_reads: dict[tuple[int, Direction], int] = {}
    for pdu in l2.decode(capture.records):
        session.l2cap.append(pdu)
        if pdu.cid == CID_ATT or pdu.psm == PSM_ATT:
            a = att.parse(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, pdu.payload)
            if a is None:
                continue
            session.att.append(a)
            session.gatt.observe(a)
            handle = a.handle
            if a.opcode == att.Opcode.READ_REQ:
                pending_reads[(a.conn, a.direction)] = a.handle
            elif a.opcode in (att.Opcode.READ_RSP, att.Opcode.READ_BLOB_RSP):
                handle = pending_reads.pop((a.conn, a.direction.opposite()), None)
            if a.carries_data:
                session.messages.append(
                    Message(a.frame, a.timestamp_us, a.direction, a.conn, f"ATT {_h(handle)}", a.name, handle, a.value)
                )
        elif pdu.psm == PSM_RFCOMM:
            r = rfcomm.parse(pdu.frame, pdu.timestamp_us, pdu.direction, pdu.handle, pdu.payload)
            if r is None:
                continue
            session.rfcomm.append(r)
            if r.is_data:
                session.messages.append(
                    Message(r.frame, r.timestamp_us, r.direction, r.conn, f"RFCOMM ch{r.channel}", "UIH", None, r.payload)
                )
    return session


def _h(handle: int | None) -> str:
    return "0x????" if handle is None else f"0x{handle:04x}"
