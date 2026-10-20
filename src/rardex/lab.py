"""A practice target: the fictional "RARDEX Lab RX-1" speaker.

Real speakers need real hardware. This module simulates one so you can rehearse the whole
workflow anywhere: decode a capture, infer the protocol, write a protocol file, then drive
the virtual speaker with it. The RX-1 protocol is invented for this lab; it is deliberately
shaped like what cheap BLE speakers tend to use (sync bytes, length, command id, checksum).

Spoiler warning: reading ``LabSpeaker.handle_write`` gives the answers away. Try the
exercise in ``rardex lab brief`` first.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import att, avdtp, avrcp, checksum, rfcomm
from .att import Opcode, uuid_to_le
from .btsnoop import Direction, PacketType, Record
from .hci import (
    CID_SIGNALING,
    PSM_AVCTP,
    PSM_AVDTP,
    PSM_RFCOMM,
    build_acl,
    build_connection_complete,
    build_disconnection_complete,
    build_l2cap_connect,
    build_l2cap_connect_response,
    build_le_connection_complete,
)

ADDRESS = "C0:DE:52:44:58:01"
CONN = 0x0041
SERVICE_UUID = "52440001-4c41-4221-8000-726172646578"
WRITE_UUID = "52440002-4c41-4221-8000-726172646578"
NOTIFY_UUID = "52440003-4c41-4221-8000-726172646578"
WRITE_HANDLE, NOTIFY_HANDLE, NOTIFY_CCCD = 0x0012, 0x0014, 0x0015
BATTERY_HANDLE, BATTERY_CCCD = 0x000E, 0x000F
DEVICE_NAME = b"RARDEX Lab RX-1 practice speaker"

_SYNC = b"\xa5\x5a"
_EQ = {0: "flat", 1: "bass", 2: "vocal", 3: "party"}
_LIGHT = {0: "off", 1: "solid", 2: "pulse"}

BRIEF = """\
RARDEX LAB - reverse engineer the RX-1 practice speaker
=======================================================
The file you generated is an Android-style HCI snoop log (btsnoop, H4) of the vendor app
talking to a fictional BLE speaker. During the capture the user, in order:
  opened the app, turned the speaker on, dragged the volume slider up, tried every EQ
  preset, changed the light colour a few times, set three auto-off timers, refreshed the
  status screen, then dragged the volume down a little.

Your job: work out the control protocol and write a protocol file that drives the speaker.

  1. rardex snoop info LAB          which device, which transport, how long?
  2. rardex snoop gatt LAB          which characteristic does the app write to? which notifies?
  3. rardex snoop timeline LAB      gaps between bursts are the user's separate actions
  4. rardex snoop export LAB --handle 0x0012 -o tx.txt
     rardex analyze tx.txt          prefix? length field? checksum? command ids? sliders?
  5. copy protocols/template.toml to rx1.toml and fill it in
     rardex proto build rx1.toml volume level=9 --compare <bytes from the capture>
  6. rardex ctl rx1.toml --lab volume level=20 --listen 1
                                    the virtual speaker reports what it understood
Bonus: decode the status notifications (handle 0x0014) with a [[responses]] entry, and
explain the two-byte argument of the auto-off command.

Write findings as seen (cite frame numbers) / inferred / unknown - docs/04-protocol-notebook.md.
"""


@dataclass
class LabSpeaker:
    power: bool = False
    volume: int = 8
    eq: int = 0
    light: tuple[int, int, int, int] = (0, 0, 0, 0)
    auto_off: int = 0
    battery: int = 76
    charging: bool = False
    connected: bool = False
    log: list[str] = field(default_factory=list)

    @staticmethod
    def frame(payload: bytes) -> bytes:
        length = bytes([len(payload)])
        return _SYNC + length + payload + checksum.compute("sum8_neg", length + payload)

    def status_frame(self) -> bytes:
        return self.frame(bytes([0x85, int(self.power), self.volume, self.eq, self.battery, int(self.charging)]))

    def _ack(self, cmd: int, status: int = 0) -> bytes:
        return self.frame(bytes([0x80, cmd, status]))

    def handle_write(self, uuid: str | None, data: bytes) -> list[bytes]:
        """Process one GATT write; return the notifications the speaker sends back."""
        if uuid != WRITE_UUID:
            self.log.append(f"ignored: write to {uuid} (not the control characteristic)")
            return []
        if not data.startswith(_SYNC) or len(data) < 5:
            self.log.append("dropped: missing sync bytes")
            return []
        length, payload, check = data[2], data[3:-1], data[-1:]
        if length != len(payload):
            self.log.append(f"dropped: length byte says {length}, payload has {len(payload)} bytes")
            return []
        if checksum.compute("sum8_neg", data[2:-1]) != check:
            self.log.append("dropped: bad checksum")
            return []
        cmd, args = payload[0], payload[1:]
        handler = {
            0x01: self._power,
            0x02: self._volume,
            0x03: self._eq,
            0x04: self._light,
            0x05: self._status,
            0x06: self._auto_off,
        }.get(cmd)
        if handler is None:
            self.log.append(f"nack: unknown command 0x{cmd:02x}")
            return [self._ack(cmd, 0x01)]
        return handler(cmd, args)

    def _bad(self, cmd: int, why: str) -> list[bytes]:
        self.log.append(f"nack: command 0x{cmd:02x} {why}")
        return [self._ack(cmd, 0x02)]

    def _power(self, cmd: int, args: bytes) -> list[bytes]:
        if len(args) != 1 or args[0] > 1:
            return self._bad(cmd, "expects one byte 0/1")
        self.power = bool(args[0])
        self.log.append(f"power -> {'on' if self.power else 'off'}")
        return [self._ack(cmd)]

    def _volume(self, cmd: int, args: bytes) -> list[bytes]:
        if len(args) != 1 or args[0] > 31:
            return self._bad(cmd, "expects one byte 0..31")
        self.volume = args[0]
        self.log.append(f"volume -> {self.volume}/31")
        return [self._ack(cmd)]

    def _eq(self, cmd: int, args: bytes) -> list[bytes]:
        if len(args) != 1 or args[0] not in _EQ:
            return self._bad(cmd, "expects one byte 0..3")
        self.eq = args[0]
        self.log.append(f"eq -> {_EQ[self.eq]}")
        return [self._ack(cmd)]

    def _light(self, cmd: int, args: bytes) -> list[bytes]:
        if len(args) != 4 or args[0] not in _LIGHT:
            return self._bad(cmd, "expects mode,r,g,b")
        self.light = tuple(args)  # type: ignore[assignment]
        mode, r, g, b = args
        self.log.append(f"light -> {_LIGHT[mode]} #{r:02x}{g:02x}{b:02x}")
        return [self._ack(cmd)]

    def _status(self, cmd: int, args: bytes) -> list[bytes]:
        if args:
            return self._bad(cmd, "takes no arguments")
        self.log.append("status requested")
        return [self.status_frame()]

    def _auto_off(self, cmd: int, args: bytes) -> list[bytes]:
        if len(args) != 2:
            return self._bad(cmd, "expects two bytes")
        minutes = struct.unpack("<H", args)[0]
        if minutes > 720:
            return self._bad(cmd, "accepts 0..720 minutes")
        self.auto_off = minutes
        self.log.append(f"auto-off -> {minutes} min" if minutes else "auto-off -> disabled")
        return [self._ack(cmd)]


class _CaptureWriter:
    def __init__(self, start_us: int) -> None:
        self.now = start_us
        self.records: list[Record] = []

    def wait(self, seconds: float) -> None:
        self.now += int(seconds * 1_000_000)

    def _add(self, direction: Direction, ptype: PacketType, data: bytes) -> None:
        self.now += 900  # a little link latency between packets
        self.records.append(Record(len(self.records) + 1, self.now, direction, ptype, data, len(data) + 1))

    def event(self, data: bytes) -> None:
        self._add(Direction.RECEIVED, PacketType.EVENT, data)

    def att(self, direction: Direction, pdu: bytes) -> None:
        for packet in build_acl(CONN, 0x0004, pdu):
            self._add(direction, PacketType.ACL, packet)


def generate_capture(start_us: int = 1_792_490_400_000_000) -> list[Record]:
    """Records for a realistic session between the vendor app and the RX-1."""
    spk = LabSpeaker()
    w = _CaptureWriter(start_us)
    tx, rx = Direction.SENT, Direction.RECEIVED

    w.event(build_le_connection_complete(CONN, ADDRESS))
    w.att(tx, att.build(Opcode.EXCHANGE_MTU_REQ, struct.pack("<H", 517)))
    w.att(rx, att.build(Opcode.EXCHANGE_MTU_RSP, struct.pack("<H", 247)))

    # Service discovery, the way Android's stack walks the table.
    def group_req(start: int) -> None:
        w.att(tx, att.build(Opcode.READ_BY_GROUP_TYPE_REQ, struct.pack("<HH", start, 0xFFFF), uuid_to_le("2800")))

    group_req(0x0001)
    w.att(rx, att.build(Opcode.READ_BY_GROUP_TYPE_RSP, bytes([6]), *[
        struct.pack("<HH", s, e) + uuid_to_le(u) for s, e, u in [(0x01, 0x07, "1800"), (0x08, 0x0B, "1801"), (0x0C, 0x0F, "180f")]
    ]))
    group_req(0x0010)
    w.att(rx, att.build(Opcode.READ_BY_GROUP_TYPE_RSP, bytes([20]), struct.pack("<HH", 0x10, 0x15), uuid_to_le(SERVICE_UUID)))
    group_req(0x0016)
    w.att(rx, att.build(Opcode.ERROR_RSP, bytes([Opcode.READ_BY_GROUP_TYPE_REQ]), struct.pack("<H", 0x16), b"\x0a"))

    def chars(start: int, end: int, size: int, entries: list[tuple[int, int, int, str]]) -> None:
        w.att(tx, att.build(Opcode.READ_BY_TYPE_REQ, struct.pack("<HH", start, end), uuid_to_le("2803")))
        body = [struct.pack("<HBH", d, p, v) + uuid_to_le(u) for d, p, v, u in entries]
        w.att(rx, att.build(Opcode.READ_BY_TYPE_RSP, bytes([size]), *body))

    chars(0x01, 0x07, 7, [(0x02, 0x02, 0x03, "2a00"), (0x04, 0x02, 0x05, "2a01"), (0x06, 0x02, 0x07, "2a04")])
    chars(0x08, 0x0B, 7, [(0x09, 0x20, 0x0A, "2a05")])
    chars(0x0C, 0x0F, 7, [(0x0D, 0x12, BATTERY_HANDLE, "2a19")])
    chars(0x10, 0x15, 21, [(0x11, 0x04, WRITE_HANDLE, WRITE_UUID), (0x13, 0x10, NOTIFY_HANDLE, NOTIFY_UUID)])
    for cccd in (0x0B, BATTERY_CCCD, NOTIFY_CCCD):
        w.att(tx, att.build(Opcode.FIND_INFORMATION_REQ, struct.pack("<HH", cccd, cccd)))
        w.att(rx, att.build(Opcode.FIND_INFORMATION_RSP, b"\x01", struct.pack("<H", cccd), uuid_to_le("2902")))

    # Subscribe to notifications, read the device name (long enough to be fragmented).
    for cccd in (NOTIFY_CCCD, BATTERY_CCCD):
        w.att(tx, att.build_handle_value(Opcode.WRITE_REQ, cccd, b"\x01\x00"))
        w.att(rx, att.build(Opcode.WRITE_RSP))
    w.att(tx, att.build(Opcode.READ_REQ, struct.pack("<H", 0x0003)))
    w.att(rx, att.build(Opcode.READ_RSP, DEVICE_NAME))
    w.att(tx, att.build(Opcode.READ_REQ, struct.pack("<H", BATTERY_HANDLE)))
    w.att(rx, att.build(Opcode.READ_RSP, bytes([spk.battery])))

    def send(payload: bytes, gap: float) -> None:
        w.wait(gap)
        frame = LabSpeaker.frame(payload)
        w.att(tx, att.build_handle_value(Opcode.WRITE_CMD, WRITE_HANDLE, frame))
        for reply in spk.handle_write(WRITE_UUID, frame):
            w.wait(0.02)
            w.att(rx, att.build_handle_value(Opcode.HANDLE_VALUE_NTF, NOTIFY_HANDLE, reply))

    send(b"\x05", 0.4)  # app opens: status refresh
    send(b"\x01\x01", 3.1)  # power on
    for level in range(9, 17):  # volume slider drag up
        send(bytes([0x02, level]), 2.6 if level == 9 else 0.12)
    for preset in (1, 2, 3, 0):  # every EQ preset
        send(bytes([0x03, preset]), 2.8 if preset == 1 else 1.4)
    for i, light in enumerate([(1, 255, 0, 0), (1, 0, 255, 0), (1, 0, 0, 255), (2, 255, 255, 255), (0, 0, 0, 0)]):
        send(bytes([0x04, *light]), 3.2 if i == 0 else 1.1)
    for i, minutes in enumerate((30, 90, 300)):  # auto-off timer
        send(b"\x06" + struct.pack("<H", minutes), 3.0 if i == 0 else 1.6)
    send(b"\x05", 2.9)  # status screen refresh

    w.wait(1.5)
    spk.battery -= 1
    w.att(rx, att.build_handle_value(Opcode.HANDLE_VALUE_NTF, BATTERY_HANDLE, bytes([spk.battery])))
    for level in range(15, 11, -1):  # volume slider drag down
        send(bytes([0x02, level]), 2.4 if level == 15 else 0.12)

    w.wait(2.0)
    w.event(build_disconnection_complete(CONN))
    return w.records


# -- practice headset (classic Bluetooth, standard profiles only) ---------------------------

HEADSET_ADDRESS = "C0:DE:52:44:58:02"
HEADSET_CONN = 0x000C
HEADSET_HFP_DLCI = 4  # server channel 2

HEADSET_BRIEF = """\
RARDEX LAB - audit the H-1 practice headset
===========================================
A fictional over-ear headset with no companion app: everything it does goes through
standard profiles. The capture shows a phone connecting to it, playing music, a few
headset button presses (play, next, previous, volume, a double press and a long press),
and battery reports.

  1. rardex snoop info LAB            which L2CAP protocols appear? (RFCOMM, AVDTP, AVCTP)
  2. rardex snoop timeline LAB        AT commands, AVRCP and AVDTP are decoded inline
  3. rardex snoop features LAB        the audit: codecs, absolute volume, battery, buttons
Questions:
  - Which codecs does the headset offer, and which did the phone choose?
  - Can a computer set the headset's hardware volume? What is the evidence?
  - How does it report battery, and in what steps?
  - What does a double press send? A long press?
Then compare with a capture of your own headset.
"""


def generate_headset_capture(start_us: int = 1_792_490_400_000_000) -> list[Record]:
    """A phone <-> headset session using only HFP, A2DP and AVRCP."""
    w = _CaptureWriter(start_us)
    tx, rx = Direction.SENT, Direction.RECEIVED  # tx: phone -> headset
    ident = iter(range(1, 256))

    def l2(direction: Direction, cid: int, payload: bytes) -> None:
        for packet in build_acl(HEADSET_CONN, cid, payload, max_fragment=1021):
            w._add(direction, PacketType.ACL, packet)

    def open_channel(psm: int, phone_cid: int, headset_cid: int) -> None:
        i = next(ident)
        l2(tx, CID_SIGNALING, build_l2cap_connect(i, psm, phone_cid))
        l2(rx, CID_SIGNALING, build_l2cap_connect_response(i, headset_cid, phone_cid))

    w.event(build_connection_complete(HEADSET_CONN, HEADSET_ADDRESS))

    # HFP service level connection over RFCOMM (headset = HF, phone = AG).
    open_channel(PSM_RFCOMM, 0x0040, 0x0041)
    for dlci in (0, HEADSET_HFP_DLCI):
        l2(tx, 0x0041, rfcomm.build_control(dlci, rfcomm.SABM, initiator=True))
        l2(rx, 0x0040, rfcomm.build_control(dlci, rfcomm.UA, initiator=False))

    def hf(command: str, *replies: str, gap: float = 0.03) -> None:
        w.wait(gap)
        l2(rx, 0x0040, rfcomm.build_uih(HEADSET_HFP_DLCI, f"{command}\r".encode(), initiator=False))
        for reply in replies + ("OK",):
            l2(tx, 0x0041, rfcomm.build_uih(HEADSET_HFP_DLCI, f"\r\n{reply}\r\n".encode(), initiator=True))

    hf("AT+BRSF=415", "+BRSF: 3943")  # EC/NR, 3-way, CLI, VR, volume, codec negotiation, HF indicators
    hf("AT+BAC=1,2")
    hf("AT+CIND=?", '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0,1)),("signal",(0-5)),("battchg",(0-5))')
    hf("AT+CIND?", "+CIND: 0,0,1,4,5")
    hf("AT+CMER=3,0,0,1")
    hf("AT+BIND=2")
    hf("AT+BIND?", "+BIND: 2,1")
    hf("AT+XAPL=FFFF-0001-0100,10", "+XAPL=iPhone,6")
    hf("AT+IPHONEACCEV=1,1,7")
    hf("AT+BIEV=2,80")
    hf("AT+VGS=9")

    # A2DP: discover endpoints, read capabilities, configure AAC, start streaming.
    open_channel(PSM_AVDTP, 0x0042, 0x0043)
    sbc = avdtp.capability(avdtp.CATEGORY_MEDIA_CODEC, bytes([0x00, 0x00, 0xFF, 0xFF, 0x02, 0x35]))
    aac = avdtp.capability(avdtp.CATEGORY_MEDIA_CODEC, bytes([0x00, 0x02, 0x80, 0x01, 0x8C, 0x83, 0xE8, 0x00]))
    transport, delay = avdtp.capability(0x01, b""), avdtp.capability(avdtp.CATEGORY_DELAY_REPORTING, b"")
    exchanges = [
        (avdtp.DISCOVER, b"", bytes([1 << 2, 0x08, 2 << 2, 0x08])),  # two audio sinks
        (avdtp.GET_ALL_CAPABILITIES, bytes([1 << 2]), transport + sbc + delay),
        (avdtp.GET_ALL_CAPABILITIES, bytes([2 << 2]), transport + aac + delay),
        (avdtp.SET_CONFIGURATION, bytes([2 << 2, 1 << 2]) + transport + aac, b""),
        (0x06, bytes([2 << 2]), b""),  # OPEN
    ]
    for label, (signal, command, response) in enumerate(exchanges, 1):
        w.wait(0.02)
        l2(tx, 0x0043, avdtp.build(label, 0, signal, command))
        l2(rx, 0x0042, avdtp.build(label, 2, signal, response))
    open_channel(PSM_AVDTP, 0x0044, 0x0045)  # media channel
    l2(tx, 0x0043, avdtp.build(6, 0, 0x07, bytes([2 << 2])))  # START
    l2(rx, 0x0042, avdtp.build(6, 2, 0x07, b""))

    def audio(seconds: float) -> None:
        for _ in range(int(seconds * 10)):
            w.wait(0.1)
            l2(tx, 0x0045, b"\x80\x60" + bytes(40))  # RTP header + payload (not decoded)

    # AVRCP: phone checks volume support, registers for volume changes, sets volume.
    open_channel(PSM_AVCTP, 0x0046, 0x0047)
    label = iter(range(16))

    def phone_vendor(ctype: int, pdu: int, params: bytes, reply_ctype: int, reply: bytes) -> None:
        n = next(label) % 16
        l2(tx, 0x0047, avrcp.build_vendor(n, ctype, pdu, params, response=False))
        l2(rx, 0x0046, avrcp.build_vendor(n, reply_ctype, pdu, reply, response=True))

    phone_vendor(0x1, avrcp.PDU_GET_CAPABILITIES, b"\x03", 0xC, bytes([0x03, 1, avrcp.EVENT_VOLUME_CHANGED]))
    phone_vendor(0x3, avrcp.PDU_REGISTER_NOTIFICATION, bytes([avrcp.EVENT_VOLUME_CHANGED, 0, 0, 0, 0]), 0xF, bytes([avrcp.EVENT_VOLUME_CHANGED, 0x40]))
    phone_vendor(0x0, avrcp.PDU_SET_ABSOLUTE_VOLUME, bytes([0x50]), 0x9, bytes([0x50]))
    audio(2.0)

    def button(op: int, gap: float = 2.5) -> None:
        w.wait(gap)
        n = next(label) % 16
        for released in (False, True):
            l2(rx, 0x0046, avrcp.build_pass_through(n, op, released))
            l2(tx, 0x0047, avrcp.build_pass_through(n, op, released, response=True))
            w.wait(0.08)

    button(0x46)  # pause
    button(0x44)  # play
    audio(1.0)
    button(0x4B)  # next
    button(0x4C)  # previous
    w.wait(2.0)  # volume +: headset changes its own volume and notifies the phone
    l2(rx, 0x0046, avrcp.build_vendor(1, 0xD, avrcp.PDU_REGISTER_NOTIFICATION, bytes([avrcp.EVENT_VOLUME_CHANGED, 0x58]), response=True))
    audio(1.0)
    hf("AT+BLDN", gap=2.5)  # double press: redial
    hf("AT+BVRA=1", gap=2.5)  # long press: voice assistant
    hf("AT+IPHONEACCEV=1,1,6", gap=3.0)
    hf("AT+BIEV=2,70")

    w.wait(2.0)
    w.event(build_disconnection_complete(HEADSET_CONN))
    return w.records
