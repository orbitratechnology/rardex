"""Standard-profile headsets: HFP, AVRCP, AVDTP decoding, the feature audit and BlueZ control."""

import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from rardex import avdtp, avrcp, bluez, btsnoop, hfp, lab
from rardex.features import audit, format_report
from rardex.session import decode


class HfpTest(unittest.TestCase):
    def line(self, text, from_headset=True):
        return hfp.AtLine(text, from_headset)

    def test_feature_bitmasks(self):
        self.assertEqual(
            self.line("AT+BRSF=144").describe(), "headset features: remote volume control, codec negotiation"
        )
        self.assertIn("in-band ring tone", self.line("+BRSF: 8", False).describe())

    def test_battery_reports(self):
        self.assertEqual(self.line("AT+IPHONEACCEV=2,1,6,2,0").battery_percent, 70)
        self.assertEqual(self.line("AT+IPHONEACCEV=2,1,6,2,0").describe(), "accessory report: battery 6/9 (~70%), undocked")
        self.assertEqual(self.line("AT+BIEV=2,55").battery_percent, 55)
        self.assertIsNone(self.line("AT+BIEV=1,1").battery_percent)

    def test_xapl_and_codecs(self):
        self.assertIn("vendor 0x05AC product 0x1234", self.line("AT+XAPL=05AC-1234-0100,2").describe())
        self.assertIn("battery reporting", self.line("AT+XAPL=05AC-1234-0100,2").describe())
        self.assertEqual(self.line("AT+BAC=1,2").describe(), "headset codecs: CVSD (narrowband), mSBC (wideband)")

    def test_split_and_commands(self):
        lines = hfp.split_lines(b"\r\n+VGS: 11\r\n\r\nOK\r\n", from_headset=False)
        self.assertEqual([(ln.command, ln.args) for ln in lines], [("+VGS", ["11"]), ("OK", [])])
        self.assertEqual(self.line("ATD5551234;").command, "ATD")
        self.assertTrue(hfp.looks_like_at(b"AT+BLDN\r"))
        self.assertFalse(hfp.looks_like_at(b"\xa5\x5a"))


class AvrcpTest(unittest.TestCase):
    def test_pass_through(self):
        msg = avrcp.parse(avrcp.build_pass_through(3, 0x4B, released=False))
        self.assertEqual((msg.operation, msg.released, msg.is_response), (0x4B, False, False))
        self.assertEqual(msg.describe(), "button: next pressed")
        self.assertTrue(avrcp.parse(avrcp.build_pass_through(3, 0x4B, True, response=True)).released)

    def test_absolute_volume_and_capabilities(self):
        set_vol = avrcp.parse(avrcp.build_vendor(1, 0x0, avrcp.PDU_SET_ABSOLUTE_VOLUME, b"\x7f", False))
        self.assertEqual(set_vol.volume, 127)
        caps = avrcp.parse(avrcp.build_vendor(1, 0xC, avrcp.PDU_GET_CAPABILITIES, b"\x03\x02\x01\x0d", True))
        self.assertEqual(caps.supported_events, [0x01, 0x0D])
        notify_cmd = avrcp.parse(avrcp.build_vendor(2, 0x3, avrcp.PDU_REGISTER_NOTIFICATION, b"\x0d\x00\x00\x00\x00", False))
        self.assertIsNone(notify_cmd.volume)  # the command carries an interval, not a volume

    def test_rejects_other_pids(self):
        self.assertIsNone(avrcp.parse(b"\x00\x11\x0f\x00\x48\x7c\x44\x00"))


class AvdtpTest(unittest.TestCase):
    def test_discover_and_sbc_capabilities(self):
        disc = avdtp.parse(avdtp.build(1, 2, avdtp.DISCOVER, bytes([1 << 2, 0x08, 2 << 2 | 2, 0x00])))
        self.assertEqual([(e.seid, e.in_use, e.is_sink) for e in disc.endpoints], [(1, False, True), (2, True, False)])
        sbc = avdtp.capability(avdtp.CATEGORY_MEDIA_CODEC, bytes([0x00, 0x00, 0x21, 0x15, 0x02, 0x35]))
        caps = avdtp.parse(avdtp.build(2, 2, avdtp.GET_CAPABILITIES, sbc))
        self.assertEqual(str(caps.codec), "SBC (44.1k, joint stereo, bitpool 2-53)")

    def test_vendor_codecs(self):
        ldac = bytes([0x00, 0xFF]) + struct.pack("<IH", 0x012D, 0x00AA) + b"\x3c\x07"
        self.assertEqual(avdtp.parse_codec(ldac).name, "LDAC")
        self.assertEqual(avdtp.parse_codec(bytes([0x00, 0xFF]) + struct.pack("<IH", 0x99, 0x01)).name, "vendor 0x00000099 codec 0x0001")


class HeadsetAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.session = decode(btsnoop.parse(btsnoop.dump(lab.generate_headset_capture())))
        cls.report = audit(cls.session)

    def test_profiles_and_channels(self):
        names = " ".join(self.report.profiles)
        for profile in ("HFP/HSP", "A2DP", "AVRCP"):
            self.assertIn(profile, names)
        self.assertEqual(self.report.other_channels, [])  # no vendor channel in the practice headset

    def test_a2dp(self):
        r = self.report
        self.assertEqual([e.seid for e in r.a2dp_endpoints], [1, 2])
        self.assertEqual([e.value.split(" ")[0] for e in r.a2dp_codecs], ["SBC", "AAC,"])
        self.assertEqual(r.a2dp_selected.value, "AAC")
        self.assertGreater(r.media_packets, 0)
        self.assertFalse(any(m.channel == "AVDTP" and m.data[:1] == b"\x80" for m in self.session.messages))

    def test_avrcp(self):
        r = self.report
        self.assertTrue(r.absolute_volume.value.startswith("supported"))
        self.assertEqual(
            sorted(e.value.split(",")[0] for e in r.buttons), ["next x1", "pause x1", "play x1", "previous x1"]
        )
        # The lab releases after 80 ms, plus ~0.9 ms simulated link latency per packet.
        self.assertIn("press->release 82-82 ms", r.buttons[0].value)
        self.assertIn("complete click", r.buttons_note)

    def test_hfp(self):
        r = self.report
        self.assertEqual([p for _, p, _, _ in r.battery], [80, 80, 70, 70])
        self.assertEqual([e.value.split()[0] for e in r.call_buttons], ["AT+BLDN", "AT+BVRA=1"])
        text = format_report(r)
        self.assertIn("battery source: AT+IPHONEACCEV, AT+BIEV", text)
        self.assertNotIn("AT+BIND?", text)

    def test_volume_levels_and_subscriptions(self):
        r = self.report
        self.assertEqual([v for v, _ in r.headset_volume], [88])
        self.assertEqual([v for v, _ in r.phone_volume], [80])


class RealWorldPatternsTest(unittest.TestCase):
    """Behaviors first seen in real captures (Baseus Encok D02 Pro on Android)."""

    @staticmethod
    def build(extra_records):
        from rardex.btsnoop import PacketType, Record
        from rardex.hci import build_acl, build_connection_complete

        base = 1_792_490_400_000_000
        records = [Record(1, base, btsnoop.Direction.RECEIVED, PacketType.EVENT, build_connection_complete(1, "11:22:33:44:55:66"), 0)]
        for i, (direction, ptype, data) in enumerate(extra_records, 2):
            records.append(Record(i, base + i * 1000, direction, ptype, data, 0))
        return decode(btsnoop.parse(btsnoop.dump(records)))

    def test_failed_connections_are_reported(self):
        from rardex.btsnoop import PacketType

        failed = bytes([0x03, 11, 0x04, 0, 0]) + bytes.fromhex("665544332211") + b"\x01\x00"
        s = self.build([(btsnoop.Direction.RECEIVED, PacketType.EVENT, failed)])
        self.assertEqual([(f.address, f.status) for f in s.failed_connections], [("11:22:33:44:55:66", 0x04)])

    def test_diagnostic_handle_is_not_decoded_as_l2cap(self):
        from rardex.btsnoop import PacketType

        diag = struct.pack("<HH", 0x0EDC | 0x2000, 8) + bytes.fromhex("0400ff170015320701")[:8]
        s = self.build([(btsnoop.Direction.RECEIVED, PacketType.ACL, diag)])
        self.assertEqual(s.l2cap, [])
        self.assertEqual(s.acl_packets, {0x0EDC: 1})

    def test_repeated_battery_report_is_collapsed_and_vendor_command_flagged(self):
        from rardex import rfcomm
        from rardex.btsnoop import PacketType
        from rardex.hci import CID_SIGNALING, build_acl, build_l2cap_connect, build_l2cap_connect_response

        rx, tx = btsnoop.Direction.RECEIVED, btsnoop.Direction.SENT

        def acl(direction, cid, payload):
            return (direction, PacketType.ACL, build_acl(1, cid, payload, max_fragment=1021)[0])

        def at(direction, text):
            cid = 0x40 if direction is rx else 0x41
            return acl(direction, cid, rfcomm.build_uih(6, text.encode(), initiator=direction is tx))

        s = self.build([
            acl(tx, CID_SIGNALING, build_l2cap_connect(1, 3, 0x40)),
            acl(rx, CID_SIGNALING, build_l2cap_connect_response(1, 0x41, 0x40)),
            at(rx, "AT+IPHONEACCEV=1,1,7\r"),
            at(rx, "AT+IPHONEACCEV=1,1,7\r"),
            at(tx, "\r\nOK\r\n"),
            at(tx, "\r\nOK\r\n"),
            at(rx, "AT+VDSF=1\r"),
            at(tx, "\r\n+CME ERROR: 0\r\n"),
        ])
        r = audit(s)
        self.assertEqual([p for _, p, _, _ in r.battery], [80])
        self.assertEqual([e.value for e in r.nonstandard], ["AT+VDSF=1  ->  phone: +CME ERROR: 0"])

    def test_audit_of_ble_capture_reports_no_headset_profiles(self):
        r = audit(decode(btsnoop.parse(btsnoop.dump(lab.generate_capture()))))
        self.assertIn("unknown", r.absolute_volume.value)
        self.assertTrue(any("ATT 0x0012" in e.value for e in r.other_channels))


def fake_busctl(objects):
    calls = []

    def run(args):
        calls.append(args)
        if "GetManagedObjects" in args:
            wrapped = {
                path: {iface: {k: {"type": "v", "data": v} for k, v in props.items()} for iface, props in ifaces.items()}
                for path, ifaces in objects.items()
            }
            return json.dumps({"type": "a{oa{sa{sv}}}", "data": [wrapped]})
        return ""

    return run, calls


DEV = "/org/bluez/hci0/dev_C0_DE_52_44_58_02"
OBJECTS = {
    "/org/bluez/hci0": {"org.bluez.Adapter1": {"Address": "00:11:22:33:44:55"}},
    DEV: {
        "org.bluez.Device1": {
            "Address": "C0:DE:52:44:58:02",
            "Alias": "Baseus Encok D02 Pro",
            "Connected": True,
            "UUIDs": ["0000110b-0000-1000-8000-00805f9b34fb", "0000111e-0000-1000-8000-00805f9b34fb"],
        },
        "org.bluez.Battery1": {"Percentage": 70},
    },
    DEV + "/sep1/fd0": {"org.bluez.MediaTransport1": {"Codec": 0, "State": "active", "Volume": 64}},
}


class BluezTest(unittest.TestCase):
    def test_finds_connected_headset_with_battery_and_volume(self):
        run, _ = fake_busctl(OBJECTS)
        h = bluez.Bluez(run).find(None)
        self.assertEqual((h.name, h.battery), ("Baseus Encok D02 Pro", 70))
        self.assertEqual(h.profiles, ["A2DP Sink (plays audio)", "Hands-Free (HFP)"])
        self.assertEqual(h.volume_transport["Volume"], 64)

    def test_set_volume_targets_the_transport(self):
        run, calls = fake_busctl(OBJECTS)
        bz = bluez.Bluez(run)
        bz.set_volume(bz.find("d02"), 100)
        self.assertEqual(calls[-1], ["set-property", "org.bluez", DEV + "/sep1/fd0", "org.bluez.MediaTransport1", "Volume", "q", "100"])
        with self.assertRaises(bluez.BluezError):
            bz.set_volume(bz.find("d02"), 200)

    def test_no_absolute_volume_explains_why(self):
        objs = {k: v for k, v in OBJECTS.items()}
        objs[DEV + "/sep1/fd0"] = {"org.bluez.MediaTransport1": {"Codec": 0, "State": "active"}}
        run, _ = fake_busctl(objs)
        bz = bluez.Bluez(run)
        with self.assertRaisesRegex(bluez.BluezError, "absolute volume"):
            bz.set_volume(bz.find(None), 10)

    def test_ambiguous_or_missing_device(self):
        run, _ = fake_busctl(OBJECTS)
        with self.assertRaises(bluez.BluezError):
            bluez.Bluez(run).find("no-such-headset")


class ButtonTest(unittest.TestCase):
    def test_reads_key_events_and_runs_mapping(self):
        def ev(etype, code, value):
            return bluez.INPUT_EVENT.pack(0, 0, etype, code, value)

        stream = io.BytesIO(ev(4, 4, 0x90) + ev(1, 163, 1) + ev(0, 0, 0) + ev(1, 163, 0) + ev(1, 164, 1))
        events = list(bluez.read_key_events(stream))
        self.assertEqual([(e.key, e.action) for e in events], [("KEY_NEXTSONG", "press"), ("KEY_NEXTSONG", "release"), ("KEY_PLAYPAUSE", "press")])
        spawned = []
        mapper = bluez.ButtonMapper({"key_nextsong": "notify-send 'next track'"}, spawn=spawned.append)
        for e in events:
            mapper.handle(e)
        self.assertEqual(spawned, [["notify-send", "next track"]])

    def test_finds_input_device_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for n, name in ((3, "AT Translated Set 2 keyboard"), (12, "Baseus Encok D02 Pro (AVRCP)")):
                (root / f"event{n}" / "device").mkdir(parents=True)
                (root / f"event{n}" / "device" / "name").write_text(name + "\n")
            self.assertEqual(bluez.find_input_device("D02 Pro", root), "/dev/input/event12")
            with self.assertRaises(bluez.BluezError):
                bluez.find_input_device("headphones", root)


if __name__ == "__main__":
    unittest.main()


class SdpTest(unittest.TestCase):
    # Device ID (PnP Information) response from a real Baseus Encok D02 Pro capture.
    DEVICE_ID_RSP = bytes.fromhex(
        "070000003d003a3600373600340900000a0001000a09000136000319120009020009010309020109"
        "05d609020209000a0902030902400902042801090205090001" "00"
    )

    def test_real_device_id_record(self):
        from rardex import sdp

        pdu = sdp.parse_pdu(self.DEVICE_ID_RSP)
        records = sdp.SdpReassembler().feed((1, 1), pdu, 663)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].device_id, {"vendor": 0x05D6, "product": 0x000A, "version": 0x0240, "source": 1})
        self.assertIn("Zhuhai Jieli Technology", records[0].describe())

    def test_elements_and_service_record(self):
        from rardex import sdp

        e = sdp.element
        uuid16 = lambda v: e(3, v.to_bytes(2, "big"))
        u16 = lambda v: e(1, v.to_bytes(2, "big"))
        record = e(6, u16(0x0001) + e(6, uuid16(0x111E) + uuid16(0x1203))
                   + u16(0x0004) + e(6, e(6, uuid16(0x0100)) + e(6, uuid16(0x0003) + e(1, b"\x04")))
                   + u16(0x0009) + e(6, e(6, uuid16(0x111E) + u16(0x0108)))
                   + u16(0x0100) + e(4, b"JL_HFP\x00")
                   + u16(0x0311) + u16(0x003F))
        rec = sdp.records_from_attribute_lists(e(6, record), 1, single=False)[0]
        self.assertEqual([c.name for c in rec.classes], ["Hands-Free", "Generic Audio"])
        self.assertEqual((rec.rfcomm_channel, rec.name), (4, "JL_HFP"))
        self.assertEqual(rec.describe(), "Hands-Free + Generic Audio; Hands-Free v1.8; name 'JL_HFP'; RFCOMM channel 4; features 0x003f")

    def test_continuation_is_reassembled(self):
        from rardex import sdp

        e = sdp.element
        blob = e(6, e(6, e(1, b"\x00\x01") + e(6, e(3, b"\x11\x0b"))))
        first, second = blob[:5], blob[5:]
        rsp = lambda chunk, cont: bytes([0x07, 0, 1]) + struct.pack(">H", 2 + len(chunk) + 1 + len(cont)) + struct.pack(">H", len(chunk)) + chunk + bytes([len(cont)]) + cont
        r = sdp.SdpReassembler()
        self.assertIsNone(r.feed((1, 1), sdp.parse_pdu(rsp(first, b"\x05")), 10))
        records = r.feed((1, 1), sdp.parse_pdu(rsp(second, b"")), 11)
        self.assertEqual([c.name for c in records[0].classes], ["A2DP Sink"])
        self.assertEqual(r.feed((1, 1), sdp.parse_pdu(rsp(e(6, b""), b"")), 12), [])


class DeviceIdentityTest(unittest.TestCase):
    """HCI events that identify the remote device, as seen in real captures."""

    def test_name_class_and_controller_version(self):
        from rardex.btsnoop import Capture, Datalink, PacketType, Record
        from rardex.hci import build_connection_complete, parse_address
        from rardex.session import decode, device_details

        addr = "11:22:33:44:55:66"
        raw = parse_address(addr)
        request = bytes([0x04, 10]) + raw + (0x240404).to_bytes(3, "little") + b"\x01"
        name = bytes([0x07, 255, 0x00]) + raw + b"Practice Headset".ljust(248, b"\x00")
        version = bytes([0x0C, 8, 0x00]) + struct.pack("<HBHH", 0x0001, 12, 0x05D6, 0x22BB)
        events = [request, build_connection_complete(1, addr), name, version]
        records = [Record(i, i * 1000, btsnoop.Direction.RECEIVED, PacketType.EVENT, e, 0) for i, e in enumerate(events, 1)]
        s = decode(Capture(Datalink.H4, records))
        lines = device_details(s, addr)
        self.assertIn("name 'Practice Headset'", lines[0])
        self.assertIn("Audio/Video: wearable headset; services: rendering, audio", lines[1])
        self.assertIn("Bluetooth 5.3 (LMP 12), manufacturer 0x05d6 Zhuhai Jieli Technology Co., Ltd", lines[2])

    def test_assigned_numbers(self):
        from rardex.assigned import bluetooth_version, company, device_class

        self.assertEqual(bluetooth_version(9), "Bluetooth 5.0")
        self.assertEqual(bluetooth_version(99), "LMP version 99")
        self.assertIn("look up", company(0x1234))
        self.assertEqual(device_class(0x240418), "Audio/Video: headphones; services: rendering, audio")

    def test_offload_note_when_stream_starts_without_media(self):
        from rardex import avdtp
        from rardex.btsnoop import PacketType
        from rardex.hci import build_acl, build_l2cap_connect, build_l2cap_connect_response, CID_SIGNALING

        tx, rx = btsnoop.Direction.SENT, btsnoop.Direction.RECEIVED
        acl = lambda d, cid, p: (d, PacketType.ACL, build_acl(1, cid, p, max_fragment=1021)[0])
        s = RealWorldPatternsTest.build([
            acl(tx, CID_SIGNALING, build_l2cap_connect(1, 0x19, 0x40)),
            acl(rx, CID_SIGNALING, build_l2cap_connect_response(1, 0x41, 0x40)),
            acl(tx, 0x41, avdtp.build(1, 0, avdtp.START, b"\x04")),
            acl(rx, 0x40, avdtp.build(1, 2, avdtp.START, b"")),
        ])
        self.assertIn("offloads A2DP encoding", format_report(audit(s)))
