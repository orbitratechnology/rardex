"""Checksums, frame analysis and protocol files."""

import unittest
from pathlib import Path

from rardex import analyze, checksum
from rardex.client import FrameReassembler
from rardex.protocol import Protocol, ProtocolError

SOLUTION = Path(__file__).parent / "fixtures" / "lab_solution.toml"
TEMPLATE = Path(__file__).parents[1] / "protocols" / "template.toml"


class ChecksumTest(unittest.TestCase):
    def test_standard_check_values(self):
        # Catalogue check values: each algorithm applied to ASCII "123456789".
        expected = {
            "crc8": 0xF4,
            "crc8_maxim": 0xA1,
            "crc16_modbus": 0x4B37,
            "crc16_arc": 0xBB3D,
            "crc16_kermit": 0x2189,
            "crc16_ccitt_false": 0x29B1,
            "crc16_xmodem": 0x31C3,
        }
        for name, value in expected.items():
            with self.subTest(name):
                self.assertEqual(checksum.ALGORITHMS[name](b"123456789"), value)

    def test_detects_crc16_big_endian_after_header(self):
        frames = [b"\x7e\x10" + body for body in (b"\x01\x02", b"\x09\x00\x07", b"\x33")]
        frames = [f + checksum.compute("crc16_xmodem", f[1:], "big") for f in frames]
        det = checksum.detect(frames)
        self.assertIn(("crc16_xmodem", "big", 1), [(m.algorithm, m.byteorder, m.start) for m in det.matches])
        self.assertLess(det.expected_false_positives, 1e-4)  # ~90 one-byte combos / 256**3

    def test_terminator_after_checksum(self):
        frames = [b"\xaa" + p + bytes([checksum.ALGORITHMS["xor8"](p)]) + b"\x55" for p in (b"\x01\x05", b"\x02\x07\x09", b"\x03")]
        det = checksum.detect(frames)
        self.assertIn(("xor8", 1, 1), [(m.algorithm, m.start, m.trailer) for m in det.matches])

    def test_single_frame_is_weak_evidence(self):
        self.assertGreater(checksum.detect([b"\x01\x02\x03\x06"]).expected_false_positives, 0.1)


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.p = Protocol.load(SOLUTION)
        self.frames = [self.p.build("volume", level=v) for v in range(5, 12)]
        self.frames += [self.p.build("eq", preset=e) for e in ("bass", "vocal", "flat")]
        self.frames += [self.p.build("light", mode="solid", r=9), self.p.build("status")]

    def test_recovers_lab_framing(self):
        r = analyze.analyze(self.frames)
        self.assertEqual(r.prefix, b"\xa5\x5a")
        self.assertIn(analyze.LengthField(2, "u8", -4), r.length_fields)
        self.assertIn(("sum8_neg", 2), [(m.algorithm, m.start) for m in r.checksum.matches])
        self.assertEqual(r.command_offset, 3)
        volume = next(c for c in r.clusters if c.key == 0x02)
        self.assertEqual([(s.offset, s.step, s.low, s.high) for s in volume.sliders], [(4, 1, 5, 11)])
        eq = next(c for c in r.clusters if c.key == 0x03)
        self.assertEqual(eq.sliders, [])  # an enum, not a slider
        self.assertIn("command id (inferred): byte at offset 3", analyze.format_report(r))

    def test_constant_length_means_unknown_length_field(self):
        r = analyze.analyze(self.frames[:3])
        self.assertFalse(r.lengths_vary)
        self.assertIn("unknown - every frame has the same length", analyze.format_report(r))

    def test_diff(self):
        out = analyze.diff(b"\x01\x02\x03", b"\x01\x09\x03\x04")
        self.assertIn("differs at offsets: 1, 3", out)


class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.p = Protocol.load(SOLUTION)

    def test_build_and_identify_round_trip(self):
        frame = self.p.build("auto_off", minutes=300)
        self.assertEqual(frame.hex(" "), "a5 5a 03 06 2c 01 ca")
        self.assertEqual(self.p.identify(frame), ("auto_off", {"minutes": 300}))
        self.assertEqual(self.p.identify(self.p.build("eq", preset="party")), ("eq", {"preset": "party"}))
        self.assertEqual(self.p.framing.unwrap(frame), b"\x06\x2c\x01")

    def test_argument_validation(self):
        with self.assertRaises(ProtocolError):
            self.p.build("volume", level=32)
        with self.assertRaises(ProtocolError):
            self.p.build("volume")
        with self.assertRaises(ProtocolError):
            self.p.build("eq", preset="disco")
        with self.assertRaises(ProtocolError):
            self.p.build("volume", level=3, extra=1)
        with self.assertRaises(ProtocolError):
            self.p.build("power", on=2)

    def test_response_decoding(self):
        name, fields = self.p.decode(bytes.fromhex("a55a0685011403" "4c0011"))
        self.assertEqual(name, "status")
        self.assertEqual(fields["eq"], "party")
        self.assertEqual(fields["volume"], 20)

    def test_bad_checksum_is_not_identified(self):
        self.assertIsNone(self.p.identify(bytes.fromhex("a55a02020900")))

    def test_template_loads(self):
        t = Protocol.load(TEMPLATE)
        self.assertEqual(t.build("volume", level=3).hex(" "), "aa 55 02 02 03 07")

    def test_other_framing_options(self):
        p = Protocol.loads(
            """
            [framing]
            prefix = "7e"
            suffix = "7f"
            length = { type = "u16be", covers = "all" }
            checksum = { algorithm = "crc16_modbus", covers = "all", byteorder = "little" }
            [commands.x]
            payload = "10 {v:i16le}"
            """
        )
        frame = p.build("x", v=-2)
        self.assertEqual(frame[1:3], len(frame).to_bytes(2, "big"))
        self.assertEqual(frame[-3:-1], checksum.compute("crc16_modbus", frame[:-3]))
        self.assertEqual(p.identify(frame), ("x", {"v": -2}))


class ReassemblerTest(unittest.TestCase):
    def test_splits_and_joins_stream_chunks(self):
        p = Protocol.load(SOLUTION)
        a, b = p.build("volume", level=3), p.build("light", mode="pulse", r=1, g=2, b=3)
        stream = b"\x00junk" + a + b
        r = FrameReassembler(p.framing)
        out = []
        for i in range(0, len(stream), 3):
            out += r.feed(stream[i : i + 3])
        self.assertEqual(out, [a, b])


if __name__ == "__main__":
    unittest.main()
