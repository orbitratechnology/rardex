"""btsnoop -> HCI/L2CAP -> ATT/RFCOMM decoding."""

import struct
import unittest

from rardex import att, btsnoop, rfcomm
from rardex.btsnoop import Direction, PacketType, Record
from rardex.hci import CID_SIGNALING, L2capDecoder, build_acl, build_le_connection_complete
from rardex.session import decode

TX, RX = Direction.SENT, Direction.RECEIVED


def rec(i, direction, ptype, data, t=0):
    return Record(i, 1_700_000_000_000_000 + t, direction, ptype, data, len(data) + 1)


class BtsnoopTest(unittest.TestCase):
    def test_round_trip(self):
        records = [
            rec(1, RX, PacketType.EVENT, build_le_connection_complete(0x40, "11:22:33:44:55:66")),
            rec(2, TX, PacketType.ACL, build_acl(0x40, 4, b"\x52\x12\x00\xaa")[0], t=1500),
        ]
        cap = btsnoop.parse(btsnoop.dump(records))
        self.assertEqual(cap.datalink, btsnoop.Datalink.H4)
        self.assertEqual(cap.records, records)
        self.assertFalse(cap.truncated_tail)
        self.assertEqual(cap.duration_us, 1500)

    def test_truncated_tail_keeps_complete_records(self):
        blob = btsnoop.dump([rec(1, TX, PacketType.ACL, b"\x40\x20\x01\x00\x00")] * 2)
        cap = btsnoop.parse(blob[:-3])
        self.assertTrue(cap.truncated_tail)
        self.assertEqual(len(cap.records), 1)

    def test_rejects_other_files(self):
        with self.assertRaises(btsnoop.BtsnoopError):
            btsnoop.parse(b"PK\x03\x04" + bytes(20))

    def test_h1_and_monitor_datalinks(self):
        header = lambda dl: b"btsnoop\x00" + struct.pack(">II", 1, dl)
        body = lambda flags, data: struct.pack(">IIIIq", len(data), len(data), flags, 0, btsnoop.EPOCH_DELTA_US) + data
        h1 = btsnoop.parse(header(1001) + body(3, b"\x0e\x00") + body(0, b"\x40\x20\x00\x00"))
        self.assertEqual([r.packet_type for r in h1.records], [PacketType.EVENT, PacketType.ACL])
        mon = btsnoop.parse(header(2001) + body(5, b"\x40\x20\x00\x00") + body(12, b"note"))
        self.assertEqual(mon.records[0].direction, RX)
        self.assertEqual(mon.skipped, 1)


class L2capTest(unittest.TestCase):
    def test_reassembles_fragments(self):
        payload = bytes(range(60))
        frags = build_acl(0x41, 4, payload, max_fragment=27)
        self.assertEqual(len(frags), 3)
        out = list(L2capDecoder().decode(rec(i, RX, PacketType.ACL, f) for i, f in enumerate(frags, 1)))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].payload, payload)
        self.assertEqual(out[0].frame, 3)

    def test_orphan_continuation_is_ignored(self):
        frag = build_acl(0x41, 4, bytes(40))[1]
        self.assertEqual(list(L2capDecoder().feed(rec(1, RX, PacketType.ACL, frag))), [])

    def test_dynamic_rfcomm_channel_from_signaling(self):
        # Phone opens PSM 3 with its CID 0x0040; speaker answers with its CID 0x0070.
        req = struct.pack("<BBH", 0x02, 1, 4) + struct.pack("<HH", 0x0003, 0x0040)
        rsp = struct.pack("<BBH", 0x03, 1, 8) + struct.pack("<HHHH", 0x0070, 0x0040, 0, 0)
        to_speaker = rfcomm.build_uih(2, b"\xaa\x01", initiator=True)
        to_phone = rfcomm.build_uih(2, b"\xbb\x02", initiator=False, credits=7)
        records = [
            rec(1, TX, PacketType.ACL, build_acl(0x0B, CID_SIGNALING, req)[0]),
            rec(2, RX, PacketType.ACL, build_acl(0x0B, CID_SIGNALING, rsp)[0]),
            rec(3, TX, PacketType.ACL, build_acl(0x0B, 0x0070, to_speaker)[0]),
            rec(4, RX, PacketType.ACL, build_acl(0x0B, 0x0040, to_phone)[0]),
        ]
        cap = btsnoop.Capture(btsnoop.Datalink.H4, records)
        s = decode(cap)
        self.assertEqual([(m.channel, m.direction, m.data) for m in s.messages], [
            ("RFCOMM ch1", TX, b"\xaa\x01"),
            ("RFCOMM ch1", RX, b"\xbb\x02"),
        ])
        self.assertTrue(all(f.fcs_ok for f in s.rfcomm))
        self.assertEqual(s.rfcomm[1].credits, 7)


class RfcommTest(unittest.TestCase):
    def test_fcs_reference_value(self):
        # SABM on DLCI 0 is the first frame of every RFCOMM session: 03 3f 01 1c
        self.assertEqual(rfcomm.fcs(b"\x03\x3f\x01"), 0x1C)

    def test_two_byte_length(self):
        data = bytes(200)
        f = rfcomm.parse(1, 0, TX, 1, rfcomm.build_uih(4, data))
        self.assertEqual((f.channel, f.payload, f.fcs_ok), (2, data, True))


class AttTest(unittest.TestCase):
    def test_uuid_conversions(self):
        self.assertEqual(att.uuid_from_le(b"\xe1\xff"), "0000ffe1-0000-1000-8000-00805f9b34fb")
        vendor = "52440002-4c41-4221-8000-726172646578"
        self.assertEqual(att.uuid_from_le(att.uuid_to_le(vendor)), vendor)
        self.assertEqual(att.uuid_to_le("FFE1"), b"\xe1\xff")
        self.assertEqual(att.normalize_uuid("0xFFE1"), "0000ffe1-0000-1000-8000-00805f9b34fb")

    def test_write_and_notification(self):
        w = att.parse(1, 0, TX, 0x40, b"\x52\x12\x00\xa5\x5a")
        self.assertEqual((w.name, w.handle, w.value, w.is_write), ("WRITE-NR", 0x12, b"\xa5\x5a", True))
        n = att.parse(2, 0, RX, 0x40, b"\x1b\x14\x00\x01")
        self.assertEqual((n.name, n.handle, n.value, n.is_notification), ("NOTIFY", 0x14, b"\x01", True))

    def test_error_description(self):
        self.assertIn("Attribute Not Found", att.describe_error(b"\x10\x16\x00\x0a"))


if __name__ == "__main__":
    unittest.main()
