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
        self.assertEqual(sorted(e.value for e in r.buttons), ["next x1", "pause x1", "play x1", "previous x1"])

    def test_hfp(self):
        r = self.report
        self.assertEqual([p for _, p, _, _ in r.battery], [80, 80, 70, 70])
        self.assertEqual([e.value.split()[0] for e in r.call_buttons], ["AT+BLDN", "AT+BVRA=1"])
        text = format_report(r)
        self.assertIn("battery source: AT+IPHONEACCEV, AT+BIEV", text)
        self.assertNotIn("AT+BIND?", text)

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
