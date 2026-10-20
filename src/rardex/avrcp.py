"""AVRCP over AVCTP: headset buttons and absolute volume.

Two directions matter on a headset:

* **Buttons** - the headset acts as a remote control and sends PASS THROUGH commands
  (play, pause, next, previous, volume up/down) to the phone. Each press is sent twice:
  pressed, then released.
* **Absolute volume** (AVRCP 1.4+) - the phone sends ``SetAbsoluteVolume`` (0..127) and
  the headset reports ``VOLUME_CHANGED`` events. If a headset supports this, a computer can
  set the headset's real (hardware) volume instead of scaling the audio.

Packet layout (single packet)::

    AVCTP: label(4b) type(2b) C/R(1b) IPID(1b) | PID u16 (0x110E)
    AV/C:  ctype(4b) | subunit type(5b) id(3b) | opcode | operands
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PID_AVRCP = 0x110E
BT_SIG_COMPANY = 0x001958

OP_VENDOR_DEPENDENT, OP_UNIT_INFO, OP_SUBUNIT_INFO, OP_PASS_THROUGH = 0x00, 0x30, 0x31, 0x7C

CTYPES = {
    0x0: "CONTROL",
    0x1: "STATUS",
    0x3: "NOTIFY",
    0x8: "NOT_IMPLEMENTED",
    0x9: "ACCEPTED",
    0xA: "REJECTED",
    0xC: "STABLE",
    0xD: "CHANGED",
    0xF: "INTERIM",
}

PASS_THROUGH_OPS = {
    0x41: "volume up",
    0x42: "volume down",
    0x43: "mute",
    0x44: "play",
    0x45: "stop",
    0x46: "pause",
    0x47: "record",
    0x48: "rewind",
    0x49: "fast forward",
    0x4A: "eject",
    0x4B: "next",
    0x4C: "previous",
    0x7E: "vendor unique",
}

PDU_GET_CAPABILITIES = 0x10
PDU_REGISTER_NOTIFICATION = 0x31
PDU_SET_ABSOLUTE_VOLUME = 0x50
PDUS = {
    PDU_GET_CAPABILITIES: "GetCapabilities",
    0x11: "ListPlayerApplicationSettingAttributes",
    0x20: "GetElementAttributes",
    0x30: "GetPlayStatus",
    PDU_REGISTER_NOTIFICATION: "RegisterNotification",
    0x40: "RequestContinuingResponse",
    0x41: "AbortContinuingResponse",
    PDU_SET_ABSOLUTE_VOLUME: "SetAbsoluteVolume",
    0x60: "SetAddressedPlayer",
}

EVENT_VOLUME_CHANGED = 0x0D
EVENTS = {
    0x01: "PLAYBACK_STATUS_CHANGED",
    0x02: "TRACK_CHANGED",
    0x03: "TRACK_REACHED_END",
    0x04: "TRACK_REACHED_START",
    0x05: "PLAYBACK_POS_CHANGED",
    0x06: "BATT_STATUS_CHANGED",
    0x07: "SYSTEM_STATUS_CHANGED",
    0x08: "PLAYER_APPLICATION_SETTING_CHANGED",
    0x09: "NOW_PLAYING_CONTENT_CHANGED",
    0x0A: "AVAILABLE_PLAYERS_CHANGED",
    0x0B: "ADDRESSED_PLAYER_CHANGED",
    0x0C: "UIDS_CHANGED",
    EVENT_VOLUME_CHANGED: "VOLUME_CHANGED",
}


@dataclass(frozen=True)
class AvrcpMessage:
    label: int
    is_response: bool
    ctype: int
    opcode: int
    # pass through
    operation: int | None = None
    released: bool = False
    # vendor dependent (AVRCP-specific PDUs)
    pdu: int | None = None
    params: bytes = b""
    fragmented: bool = False

    @property
    def ctype_name(self) -> str:
        return CTYPES.get(self.ctype, f"0x{self.ctype:x}")

    @property
    def event(self) -> int | None:
        if self.pdu == PDU_REGISTER_NOTIFICATION and self.params:
            return self.params[0]
        return None

    @property
    def volume(self) -> int | None:
        """0..127 from SetAbsoluteVolume or a VOLUME_CHANGED notification."""
        if self.pdu == PDU_SET_ABSOLUTE_VOLUME and self.params:
            return self.params[0] & 0x7F
        if self.event == EVENT_VOLUME_CHANGED and len(self.params) >= 2 and self.is_response:
            return self.params[1] & 0x7F
        return None

    @property
    def supported_events(self) -> list[int]:
        """Event ids listed in a GetCapabilities(events) response."""
        if self.pdu == PDU_GET_CAPABILITIES and self.is_response and len(self.params) >= 2 and self.params[0] == 0x03:
            return list(self.params[2 : 2 + self.params[1]])
        return []

    def describe(self) -> str:
        if self.fragmented:
            return "fragmented AVCTP packet (not reassembled)"
        if self.opcode == OP_PASS_THROUGH and self.operation is not None:
            name = PASS_THROUGH_OPS.get(self.operation, f"op 0x{self.operation:02x}")
            if self.is_response:
                return f"{name} {'released' if self.released else 'pressed'} -> {self.ctype_name}"
            return f"button: {name} {'released' if self.released else 'pressed'}"
        if self.opcode == OP_VENDOR_DEPENDENT and self.pdu is not None:
            name = PDUS.get(self.pdu, f"PDU 0x{self.pdu:02x}")
            detail = ""
            if self.volume is not None:
                detail = f" volume {self.volume}/127 (~{round(self.volume * 100 / 127)}%)"
            elif self.event is not None:
                detail = f" {EVENTS.get(self.event, hex(self.event))}"
            elif self.supported_events:
                detail = " events: " + ", ".join(EVENTS.get(e, hex(e)) for e in self.supported_events)
            return f"{name}{detail} [{self.ctype_name}]"
        if self.opcode in (OP_UNIT_INFO, OP_SUBUNIT_INFO):
            return ("UNIT INFO" if self.opcode == OP_UNIT_INFO else "SUBUNIT INFO") + f" [{self.ctype_name}]"
        return f"AV/C opcode 0x{self.opcode:02x} [{self.ctype_name}]"


def parse(data: bytes) -> AvrcpMessage | None:
    if len(data) < 3:
        return None
    b0 = data[0]
    label, ptype, is_response = b0 >> 4, (b0 >> 2) & 3, bool(b0 >> 1 & 1)
    if ptype != 0:  # start/continue/end fragments: rare for control traffic
        return AvrcpMessage(label, is_response, 0, 0, fragmented=True)
    if struct.unpack_from(">H", data, 1)[0] != PID_AVRCP or len(data) < 6:
        return None
    ctype, opcode, operands = data[3] & 0x0F, data[5], data[6:]
    if opcode == OP_PASS_THROUGH and operands:
        return AvrcpMessage(label, is_response, ctype, opcode, operands[0] & 0x7F, bool(operands[0] & 0x80))
    if opcode == OP_VENDOR_DEPENDENT and len(operands) >= 7:
        company = int.from_bytes(operands[:3], "big")
        if company == BT_SIG_COMPANY:
            plen = struct.unpack_from(">H", operands, 5)[0]
            return AvrcpMessage(label, is_response, ctype, opcode, pdu=operands[3], params=operands[7 : 7 + plen])
    return AvrcpMessage(label, is_response, ctype, opcode)


# -- builders (lab and tests) ---------------------------------------------------------------


def build_pass_through(label: int, op: int, released: bool, response: bool = False) -> bytes:
    ctype = 0x9 if response else 0x0
    return bytes([label << 4 | int(response) << 1]) + struct.pack(">H", PID_AVRCP) + bytes(
        [ctype, 0x48, OP_PASS_THROUGH, op | (0x80 if released else 0), 0x00]
    )


def build_vendor(label: int, ctype: int, pdu: int, params: bytes, response: bool) -> bytes:
    head = bytes([label << 4 | int(response) << 1]) + struct.pack(">H", PID_AVRCP)
    avc = bytes([ctype, 0x48, OP_VENDOR_DEPENDENT]) + BT_SIG_COMPANY.to_bytes(3, "big")
    return head + avc + bytes([pdu, 0x00]) + struct.pack(">H", len(params)) + params
