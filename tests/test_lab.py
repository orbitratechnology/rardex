"""The whole workflow on the practice speaker: capture -> decode -> infer -> control."""

import asyncio
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from rardex import analyze, btsnoop, lab
from rardex.btsnoop import Direction
from rardex.cli import main
from rardex.client import SpeakerClient, make_transport
from rardex.protocol import Protocol
from rardex.session import decode

SOLUTION = Path(__file__).parent / "fixtures" / "lab_solution.toml"


def run_cli(*argv: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(list(argv))
    return out.getvalue()


class LabWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "lab.btsnoop"
        btsnoop.save(cls.path, lab.generate_capture())
        cls.session = decode(btsnoop.load(cls.path))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_connection_and_gatt_are_recovered(self):
        s = self.session
        self.assertEqual([(c.address, c.transport) for c in s.connections], [(lab.ADDRESS, "LE")])
        self.assertEqual(s.gatt.uuid_of(lab.WRITE_HANDLE), lab.WRITE_UUID)
        self.assertEqual(s.gatt.uuid_of(lab.NOTIFY_HANDLE), lab.NOTIFY_UUID)
        self.assertEqual(s.gatt.describe(lab.NOTIFY_CCCD), "CCCD of 52440003…")
        self.assertEqual(s.gatt.handle_of(lab.WRITE_UUID), lab.WRITE_HANDLE)

    def test_fragmented_read_is_reassembled_and_attributed(self):
        reads = [m for m in self.session.messages if m.kind == "READ" and m.handle == 0x0003]
        self.assertEqual(reads[0].data, lab.DEVICE_NAME)

    def test_every_captured_frame_is_explained_by_the_solution(self):
        p = Protocol.load(SOLUTION)
        for direction in (Direction.SENT, Direction.RECEIVED):
            handle = lab.WRITE_HANDLE if direction is Direction.SENT else lab.NOTIFY_HANDLE
            msgs = self.session.select(handle=handle, direction=direction)
            self.assertGreater(len(msgs), 20)
            self.assertTrue(all(p.identify(m.data) for m in msgs), direction)

    def test_analysis_of_captured_writes(self):
        frames = [m.data for m in self.session.select(handle=lab.WRITE_HANDLE)]
        r = analyze.analyze(frames)
        self.assertEqual(r.prefix, b"\xa5\x5a")
        self.assertIn(analyze.LengthField(2, "u8", -4), r.length_fields)
        self.assertEqual(r.command_offset, 3)
        volume = next(c for c in r.clusters if c.key == 0x02)
        self.assertEqual([(s.offset, s.low, s.high) for s in volume.sliders], [(4, 9, 16)])

    def test_cli_pipeline(self):
        info = run_cli("snoop", "info", str(self.path))
        self.assertIn(lab.ADDRESS, info)
        self.assertIn("ATT 0x0012", info)
        gatt = run_cli("snoop", "gatt", str(self.path))
        self.assertIn("APP WRITES HERE", gatt)
        timeline = run_cli("snoop", "timeline", str(self.path), "--writes", "--protocol", str(SOLUTION))
        self.assertIn("volume(level=9)", timeline)
        self.assertIn("pause: likely a new user action", timeline)
        frames = Path(self.tmp.name) / "tx.txt"
        run_cli("snoop", "export", str(self.path), "--handle", "0x0012", "-o", str(frames))
        self.assertIn("checksum:", run_cli("analyze", str(frames)))
        self.assertIn("27/27 frames identified", run_cli("proto", "verify", str(SOLUTION), str(frames)))
        self.assertIn("MATCH", run_cli("proto", "build", str(SOLUTION), "volume", "level=9", "--compare", "a55a020209f3"))


class LabControlTest(unittest.TestCase):
    def test_client_drives_virtual_speaker(self):
        async def scenario():
            p = Protocol.load(SOLUTION)
            speaker = lab.LabSpeaker()
            async with SpeakerClient(p, make_transport(p, lab=speaker)) as client:
                await client.send("power", on="on")
                ack = await client.wait_for("ack")
                await client.send("volume", level=21)
                await client.send("status")
                status = await client.wait_for("status")
            return speaker, ack, status

        speaker, ack, status = asyncio.run(scenario())
        self.assertEqual(ack.fields, {"command": 1, "result": "ok"})
        self.assertEqual(status.fields["volume"], 21)
        self.assertTrue(speaker.power)

    def test_wrong_uuid_or_checksum_is_rejected(self):
        speaker = lab.LabSpeaker()
        self.assertEqual(speaker.handle_write("0000ffe1-0000-1000-8000-00805f9b34fb", b"\xa5\x5a"), [])
        self.assertEqual(speaker.handle_write(lab.WRITE_UUID, bytes.fromhex("a55a02020900")), [])
        self.assertEqual(speaker.log[-1], "dropped: bad checksum")

    def test_cli_ctl_against_lab(self):
        out = run_cli("ctl", str(SOLUTION), "--lab", "--delay", "0", "eq", "preset=bass", ",", "status")
        self.assertIn("eq -> bass", out)
        self.assertIn("'eq': 'bass'", out)


if __name__ == "__main__":
    unittest.main()
