"""``rardex`` command line. Run ``rardex -h`` or ``rardex <command> -h`` for usage."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import analyze as analysis
from . import bluez, btsnoop, checksum, features, lab
from .att import describe_error, Opcode
from .btsnoop import Direction
from .client import SpeakerClient, make_transport
from .gatt import uuid_label
from .hci import DIAGNOSTIC_HANDLES, status_text
from .protocol import Protocol, ProtocolError
from .session import Message, Session, decode
from .transport import TransportError, _bleak
from .util import fmt_seconds, hexs, parse_hex, printable


def _load_session(path: str) -> Session:
    return decode(btsnoop.load(path))


def _int(text: str) -> int:
    return int(text, 0)


def _kv(pairs: list[str]) -> dict[str, str]:
    out = {}
    for p in pairs:
        key, sep, value = p.partition("=")
        if not sep:
            raise SystemExit(f"argument {p!r} must look like name=value")
        out[key] = value
    return out


# -- snoop ---------------------------------------------------------------------------------


def cmd_snoop_info(args: argparse.Namespace) -> None:
    cap = btsnoop.load(args.file)
    s = decode(cap)
    print(f"file:        {args.file}")
    print(f"datalink:    {cap.datalink.name} ({int(cap.datalink)})")
    print(f"records:     {len(cap.records)}" + (f" (+{cap.skipped} skipped)" if cap.skipped else ""))
    if cap.truncated_tail:
        print("warning:     file ends mid-record (pulled while logging?) - last record ignored")
    print(f"duration:    {cap.duration_us / 1e6:.1f}s")
    print("connections:")
    for c in s.connections or []:
        closed = ""
        if c.closed_frame:
            reason = f" ({status_text(c.close_reason)})" if c.close_reason is not None else ""
            closed = f", closed at frame {c.closed_frame}{reason}"
        print(f"  0x{c.handle:04x}  {c.address}  {c.transport}  opened at frame {c.opened_frame}{closed}")
    if not s.connections:
        print("  none opened in this capture")
    for f in s.failed_connections:
        print(f"  FAILED  {f.address}  {f.transport}  frame {f.frame}: {status_text(f.status)}")
    opened = {c.handle for c in s.connections}
    print("acl handles:")
    for handle, n in sorted(s.acl_packets.items()):
        if handle in opened:
            label = "device link"
        elif handle in DIAGNOSTIC_HANDLES:
            label = "controller diagnostics, not a device link (ignored)"
        else:
            label = "opened before logging started"
        print(f"  0x{handle:04x}  {n:>6} packets  {label}")
    if not s.acl_packets:
        print("  none")
    protocols: dict[str, int] = {}
    for pdu in s.l2cap:
        protocols[pdu.protocol] = protocols.get(pdu.protocol, 0) + 1
    print("l2cap:       " + ", ".join(f"{k} x{v}" for k, v in sorted(protocols.items(), key=lambda kv: -kv[1])))
    channels: dict[str, list[Message]] = {}
    for m in s.messages:
        channels.setdefault(m.channel, []).append(m)
    print("app data channels (most active first):")
    for name, msgs in sorted(channels.items(), key=lambda kv: -len(kv[1])):
        tx = sum(m.direction is Direction.SENT for m in msgs)
        label = s.gatt.describe(msgs[0].handle) if msgs[0].handle is not None else ""
        print(f"  {name:<14} {tx:>4} sent {len(msgs) - tx:>4} received   {label}")
    errors = [a for a in s.att if a.opcode == Opcode.ERROR_RSP]
    if errors:
        print(f"att errors:  {len(errors)} (e.g. {describe_error(errors[0].params)})")
    if s.gatt.empty and s.att:
        print("hint: no GATT discovery captured - toggle Bluetooth or re-pair before logging to get UUIDs")


def cmd_snoop_gatt(args: argparse.Namespace) -> None:
    s = _load_session(args.file)
    if s.gatt.empty:
        print("no service discovery in this capture (Android caches GATT tables).")
        print("re-capture after toggling Bluetooth off/on, or after unpairing and re-pairing the speaker.")
        return
    written = {m.handle for m in s.messages if m.kind.startswith("WRITE")}
    notified = {m.handle for m in s.messages if m.kind in ("NOTIFY", "INDICATE")}
    for svc in s.gatt.services:
        print(f"service 0x{svc.start:04x}-0x{svc.end:04x}  {uuid_label(svc.uuid)}")
        for c in svc.characteristics:
            seen = []
            if c.value_handle in written:
                seen.append("APP WRITES HERE")
            if c.value_handle in notified:
                seen.append("DEVICE NOTIFIES HERE")
            flag = f"   <- {', '.join(seen)}" if seen else ""
            print(f"  char 0x{c.value_handle:04x}  {uuid_label(c.uuid)}  [{', '.join(c.property_names)}]{flag}")
            for h, d in sorted(c.descriptors.items()):
                print(f"    desc 0x{h:04x}  {uuid_label(d)}")


def _annotate(s: Session, m: Message, proto: Protocol | None) -> str:
    if m.note:
        return m.note
    if proto is not None:
        found = proto.identify(m.data)
        if found:
            name, values = found
            return f"{name}({', '.join(f'{k}={v}' for k, v in values.items())})"
    if m.handle is not None:
        return s.gatt.describe(m.handle, compact=True)
    return ""


def cmd_snoop_timeline(args: argparse.Namespace) -> None:
    s = _load_session(args.file)
    proto = Protocol.load(args.protocol) if args.protocol else None
    kinds = None
    if args.writes:
        kinds = {"WRITE", "WRITE-NR"}
    elif args.notifications:
        kinds = {"NOTIFY", "INDICATE"}
    msgs = s.select(handle=args.handle, channel=args.channel, kinds=kinds)
    if not msgs:
        print("no matching application data")
        return
    t0, last = s.capture.start_us, None
    pad = min(args.width, max(len(m.data) for m in msgs)) * 3 + 2
    print(f"{'time':>10}  {'frame':>6}  dir  {'channel':<12} {'kind':<9} {'len':>4}  {'data':<{pad}} note")
    for m in msgs:
        if last is not None and m.timestamp_us - last >= args.gap * 1e6:
            print(f"{'':>10}  ------  (+{(m.timestamp_us - last) / 1e6:.1f}s pause: likely a new user action)")
        last = m.timestamp_us
        data = hexs(m.data[: args.width])
        if len(m.data) > args.width:
            data += " .."
        note = _annotate(s, m, proto)
        if args.ascii:
            note = f"|{printable(m.data)}|  {note}"
        print(
            f"{fmt_seconds(m.timestamp_us - t0):>10}  {m.frame:>6}  {m.direction.arrow}   "
            f"{m.channel:<12} {m.kind:<9} {len(m.data):>4}  {data:<{pad}} {note}"
        )


def cmd_snoop_features(args: argparse.Namespace) -> None:
    print(features.format_report(features.audit(_load_session(args.file))))


def cmd_snoop_export(args: argparse.Namespace) -> None:
    s = _load_session(args.file)
    if args.handle is None and args.channel is None:
        raise SystemExit("choose a channel: --handle 0x0012 (BLE) or --channel 1 (RFCOMM)")
    direction = {"tx": Direction.SENT, "rx": Direction.RECEIVED, None: None}[args.direction]
    msgs = s.select(handle=args.handle, channel=args.channel, direction=direction)
    lines = [hexs(m.data, "") for m in msgs if m.data]
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {len(lines)} frames to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


# -- analysis ------------------------------------------------------------------------------


def _read_frames(args: argparse.Namespace) -> list[bytes]:
    frames = [parse_hex(h) for h in args.hex or []]
    for name in args.files or []:
        text = sys.stdin.read() if name == "-" else Path(name).read_text()
        frames += [parse_hex(line.split("#")[0]) for line in text.splitlines() if line.split("#")[0].strip()]
    if not frames:
        raise SystemExit("no frames: pass files with one hex frame per line, '-' for stdin, or --hex")
    return frames


def cmd_analyze(args: argparse.Namespace) -> None:
    print(analysis.format_report(analysis.analyze(_read_frames(args))))


def cmd_checksum(args: argparse.Namespace) -> None:
    frames = [parse_hex(h) for h in args.frames]
    det = checksum.detect(frames)
    if not det.matches:
        print("no match. try more frames, or the checksum may be keyed / cover an unusual range.")
    for m in det.matches:
        print(m.describe())
    print(
        f"({det.combinations_tried} combinations, {det.distinct_frames} distinct frames, "
        f"~{det.expected_false_positives:.2g} chance matches expected)"
    )


def cmd_diff(args: argparse.Namespace) -> None:
    print(analysis.diff(parse_hex(args.a), parse_hex(args.b)))


# -- protocols -----------------------------------------------------------------------------


def cmd_proto_show(args: argparse.Namespace) -> None:
    p = Protocol.load(args.protocol)
    d = p.device
    print(f"{d.name}  transport={d.transport}")
    if d.transport == "ble":
        print(f"  write  {d.write_uuid} ({'with' if d.write_with_response else 'without'} response)")
        print(f"  notify {d.notify_uuid}")
    else:
        print(f"  rfcomm channel {d.channel}")
    for name, c in p.commands.items():
        params = " ".join(f"{n}=<{t}>" for n, t in c.placeholders)
        print(f"  {name} {params}".rstrip() + (f"   # {c.description}" if c.description else ""))
        for n, spec in c.args.items():
            if spec.choices:
                print(f"      {n}: {', '.join(spec.choices)}")
    for r in p.responses:
        print(f"  <- {r.name}: {', '.join(r.fields)}")


def cmd_proto_build(args: argparse.Namespace) -> None:
    p = Protocol.load(args.protocol)
    frame = p.build(args.command, **_kv(args.args))
    print(hexs(frame))
    if args.compare:
        expected = parse_hex(args.compare)
        if expected == frame:
            print("MATCH: identical to the captured frame")
        else:
            print(analysis.diff(expected, frame).replace("a: ", "captured: ").replace("b: ", "built:    "))
            raise SystemExit(1)


def cmd_proto_verify(args: argparse.Namespace) -> None:
    """Check that a protocol explains every frame captured on a channel."""
    p = Protocol.load(args.protocol)
    frames = _read_frames(args)
    unexplained = []
    for f in frames:
        found = p.identify(f)
        if found is None:
            unexplained.append(f)
    explained = len(frames) - len(unexplained)
    print(f"{explained}/{len(frames)} frames identified by {args.protocol}")
    for f in unexplained[:20]:
        try:
            payload = p.framing.unwrap(f)
            why = f"framing OK, payload {hexs(payload)} matches no command/response"
        except ProtocolError as exc:
            why = f"framing: {exc}"
        print(f"  {hexs(f)}   {why}")
    if unexplained:
        raise SystemExit(1)


# -- live device ---------------------------------------------------------------------------


async def _scan(args: argparse.Namespace) -> None:
    bleak = _bleak()
    found = await bleak.BleakScanner.discover(timeout=args.timeout, return_adv=True)
    rows = sorted(found.values(), key=lambda da: -(da[1].rssi or -999))
    for dev, adv in rows:
        name = adv.local_name or dev.name or ""
        if args.name and args.name.lower() not in name.lower():
            continue
        mfr = ",".join(f"0x{k:04x}" for k in adv.manufacturer_data)
        uuids = ",".join(uuid_label(u) for u in adv.service_uuids)
        print(f"{dev.address}  {adv.rssi:>4} dBm  {name:<28} mfr={mfr or '-'} services={uuids or '-'}")


async def _gatt(args: argparse.Namespace) -> None:
    bleak = _bleak()
    async with bleak.BleakClient(args.address, timeout=args.timeout) as client:
        for svc in client.services:
            print(f"service {uuid_label(svc.uuid)}")
            for ch in svc.characteristics:
                print(f"  char {uuid_label(ch.uuid)}  handle={ch.handle}  [{', '.join(ch.properties)}]")
                if args.read and "read" in ch.properties:
                    try:
                        value = bytes(await client.read_gatt_char(ch))
                        print(f"       value: {hexs(value)}  |{printable(value)}|")
                    except Exception as exc:  # noqa: BLE001 - report and keep enumerating
                        print(f"       read failed: {exc}")
                for d in ch.descriptors:
                    print(f"    desc {uuid_label(d.uuid)}  handle={d.handle}")


def _split_commands(tokens: list[str]) -> list[list[str]]:
    groups, current = [], []
    for t in tokens:
        if t == ",":
            if current:
                groups.append(current)
            current = []
        else:
            current.append(t)
    if current:
        groups.append(current)
    return groups


async def _ctl(args: argparse.Namespace) -> None:
    p = Protocol.load(args.protocol)
    speaker = lab.LabSpeaker() if args.lab else None
    transport = make_transport(p, args.address, speaker)

    def show(msg) -> None:
        label = f"{msg.name} {msg.fields}" if msg.name else ""
        print(f"  <- {hexs(msg.frame)}  {label}")

    # Build every frame before connecting so argument errors never leave a half-sent sequence.
    frames: list[tuple[bytes, str]] = []
    if args.raw:
        frames.append((parse_hex(args.raw), "(raw)"))
    for group in _split_commands(args.command):
        kwargs = _kv(group[1:])
        frames.append((p.build(group[0], **kwargs), f"{group[0]} {' '.join(group[1:])}".rstrip()))
    if not frames:
        raise SystemExit("nothing to send: give a command name or --raw HEX")

    async with SpeakerClient(p, transport, on_message=show) as client:
        for frame, label in frames:
            print(f"-> {hexs(frame)}  {label}")
            await client.send_raw(frame)
            await asyncio.sleep(args.delay)
        if args.listen:
            await asyncio.sleep(args.listen)
    if speaker is not None:
        print("virtual speaker log:")
        for line in speaker.log:
            print(f"  {line}")


# -- headset (Linux / BlueZ) ---------------------------------------------------------------


def cmd_headset_info(args: argparse.Namespace) -> None:
    h = bluez.Bluez().find(args.device)
    print(f"{h.name}  [{h.address}]  {'connected' if h.connected else 'not connected'}")
    print("profiles advertised:")
    for p in h.profiles:
        print(f"  {p}")
    if h.battery is not None:
        print(f"battery: {h.battery}%")
    else:
        print("battery: not reported to BlueZ (see docs/05 for how headsets report it)")
    if not h.transports:
        print("audio: no A2DP transport right now (connect it and play something)")
    for t in h.transports:
        codec = bluez.A2DP_CODECS.get(t.get("Codec"), t.get("Codec"))
        volume = f"{t['Volume']}/127" if "Volume" in t else "none (no AVRCP absolute volume)"
        print(f"audio: codec {codec}, state {t.get('State')}, hardware volume {volume}")


def cmd_headset_volume(args: argparse.Namespace) -> None:
    bz = bluez.Bluez()
    h = bz.find(args.device)
    if args.level is None:
        t = h.volume_transport
        print(f"{t['Volume']}/127 (~{round(t['Volume'] * 100 / 127)}%)" if t else "no hardware volume exposed")
        return
    level = round(args.level * 127 / 100) if args.percent else args.level
    bz.set_volume(h, level)
    print(f"hardware volume set to {level}/127")


def cmd_headset_inputs(_args: argparse.Namespace) -> None:
    for path, name in bluez.input_devices():
        print(f"{path}  {name}")


def cmd_headset_buttons(args: argparse.Namespace) -> None:
    path = args.input or bluez.find_input_device(args.name or bluez.Bluez().find(args.device).name)
    mapper = bluez.ButtonMapper(_kv(args.map or []))
    with bluez.open_input(path) as fh:
        if args.grab:
            bluez.grab(fh.fileno())
        print(f"listening on {path}; press headset buttons (Ctrl+C to stop)", flush=True)
        try:
            for event in bluez.read_key_events(fh):
                ran = mapper.handle(event)
                print(f"{event.key:<18} {event.action}" + (f"  -> ran: {ran}" if ran else ""), flush=True)
        except KeyboardInterrupt:
            pass


def cmd_lab_capture(args: argparse.Namespace) -> None:
    records = lab.generate_headset_capture() if args.headset else lab.generate_capture()
    btsnoop.save(args.output, records)
    print(f"wrote practice capture to {args.output}")
    print("next: rardex lab brief" + (" --headset" if args.headset else ""))


def cmd_lab_brief(args: argparse.Namespace) -> None:
    print(lab.HEADSET_BRIEF if args.headset else lab.BRIEF)


# -- parser --------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rardex", description="Reverse engineer and control Bluetooth speakers.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    snoop = sub.add_parser("snoop", help="decode btsnoop / HCI snoop captures").add_subparsers(dest="sub", required=True)
    p = snoop.add_parser("info", help="capture overview: devices, protocols, busiest channels")
    p.add_argument("file")
    p.set_defaults(func=cmd_snoop_info)
    p = snoop.add_parser("gatt", help="GATT table rebuilt from discovery traffic")
    p.add_argument("file")
    p.set_defaults(func=cmd_snoop_gatt)
    p = snoop.add_parser("timeline", help="application data in time order, split at pauses")
    p.add_argument("file")
    p.add_argument("--handle", type=_int, help="only this ATT handle")
    p.add_argument("--channel", type=int, help="only this RFCOMM server channel")
    p.add_argument("--writes", action="store_true", help="only app -> device writes")
    p.add_argument("--notifications", action="store_true", help="only device -> app notifications")
    p.add_argument("--gap", type=float, default=1.0, help="pause (s) that marks a new action [1.0]")
    p.add_argument("--width", type=int, default=16, help="bytes of data to show per line [16]")
    p.add_argument("--ascii", action="store_true", help="also show printable ASCII")
    p.add_argument("--protocol", help="protocol file to name known commands/responses")
    p.set_defaults(func=cmd_snoop_timeline)
    p = snoop.add_parser("features", help="headset audit: codecs, absolute volume, battery, buttons (HFP/A2DP/AVRCP)")
    p.add_argument("file")
    p.set_defaults(func=cmd_snoop_features)
    p = snoop.add_parser("export", help="write one hex frame per line for `rardex analyze`")
    p.add_argument("file")
    p.add_argument("--handle", type=_int)
    p.add_argument("--channel", type=int)
    p.add_argument("--direction", choices=["tx", "rx"], help="tx = app->device, rx = device->app")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_snoop_export)

    p = sub.add_parser("analyze", help="infer framing: prefix, length, checksum, command ids, sliders")
    p.add_argument("files", nargs="*", help="files with one hex frame per line ('-' = stdin)")
    p.add_argument("--hex", action="append", help="a frame given inline (repeatable)")
    p.set_defaults(func=cmd_analyze)
    p = sub.add_parser("checksum", help="find checksum algorithms that explain the given frames")
    p.add_argument("frames", nargs="+")
    p.set_defaults(func=cmd_checksum)
    p = sub.add_parser("diff", help="byte-level diff of two frames")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(func=cmd_diff)

    proto = sub.add_parser("proto", help="work with protocol files").add_subparsers(dest="sub", required=True)
    p = proto.add_parser("show", help="list commands in a protocol file")
    p.add_argument("protocol")
    p.set_defaults(func=cmd_proto_show)
    p = proto.add_parser("build", help="build a frame, optionally compare with a captured one")
    p.add_argument("protocol")
    p.add_argument("command")
    p.add_argument("args", nargs="*", help="name=value")
    p.add_argument("--compare", metavar="HEX", help="captured frame expected to be identical")
    p.set_defaults(func=cmd_proto_build)
    p = proto.add_parser("verify", help="check a protocol identifies every exported frame")
    p.add_argument("protocol")
    p.add_argument("files", nargs="*")
    p.add_argument("--hex", action="append")
    p.set_defaults(func=cmd_proto_verify)

    p = sub.add_parser("scan", help="list nearby BLE devices (needs rardex[ble])")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--name", help="only names containing this text")
    p.set_defaults(func=lambda a: asyncio.run(_scan(a)))
    p = sub.add_parser("gatt", help="enumerate a device's live GATT table (needs rardex[ble])")
    p.add_argument("address")
    p.add_argument("--read", action="store_true", help="also read readable characteristics")
    p.add_argument("--timeout", type=float, default=15.0)
    p.set_defaults(func=lambda a: asyncio.run(_gatt(a)))

    p = sub.add_parser("ctl", help="send commands defined in a protocol file")
    p.add_argument("protocol")
    p.add_argument("command", nargs="*", help="NAME [arg=value ...] [, NAME ...]")
    p.add_argument("--address", help="device address (overrides the protocol file)")
    p.add_argument("--lab", action="store_true", help="talk to the virtual practice speaker")
    p.add_argument("--raw", metavar="HEX", help="send these exact bytes first (replay a captured frame)")
    p.add_argument("--delay", type=float, default=0.15, help="seconds between commands [0.15]")
    p.add_argument("--listen", type=float, default=0.0, help="keep listening N seconds for notifications")
    p.set_defaults(func=lambda a: asyncio.run(_ctl(a)))

    hs = sub.add_parser("headset", help="control a connected headset via Linux BlueZ (standard profiles)").add_subparsers(
        dest="sub", required=True
    )
    p = hs.add_parser("info", help="profiles, battery, codec and hardware-volume support")
    p.add_argument("--device", help="address or name substring (default: the one connected device)")
    p.set_defaults(func=cmd_headset_info)
    p = hs.add_parser("volume", help="read or set hardware volume (AVRCP absolute volume)")
    p.add_argument("level", nargs="?", type=int, help="0..127, or 0..100 with --percent")
    p.add_argument("--percent", action="store_true")
    p.add_argument("--device")
    p.set_defaults(func=cmd_headset_volume)
    p = hs.add_parser("inputs", help="list Linux input devices (find the headset's button device)")
    p.set_defaults(func=cmd_headset_inputs)
    p = hs.add_parser("buttons", help="show headset button presses and map them to commands")
    p.add_argument("--input", help="/dev/input/eventN (default: found by headset name)")
    p.add_argument("--name", help="input device name substring (default: headset name from BlueZ)")
    p.add_argument("--device", help="headset address or name substring for BlueZ lookup")
    p.add_argument("--map", action="append", metavar="KEY=COMMAND", help='e.g. KEY_NEXTSONG="notify-send next"')
    p.add_argument("--grab", action="store_true", help="exclusive: the desktop stops seeing these buttons")
    p.set_defaults(func=cmd_headset_buttons)

    labp = sub.add_parser("lab", help="practice targets: a virtual speaker/headset and captures").add_subparsers(
        dest="sub", required=True
    )
    p = labp.add_parser("capture", help="write a practice btsnoop capture")
    p.add_argument("output")
    p.add_argument("--headset", action="store_true", help="the classic-Bluetooth headset (HFP/A2DP/AVRCP)")
    p.set_defaults(func=cmd_lab_capture)
    p = labp.add_parser("brief", help="print the exercise")
    p.add_argument("--headset", action="store_true")
    p.set_defaults(func=cmd_lab_brief)
    return ap


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except BrokenPipeError:
        # Output piped into `head` etc.; exit quietly like other Unix tools.
        sys.stdout = open(os.devnull, "w")
    except (ProtocolError, TransportError, bluez.BluezError, btsnoop.BtsnoopError, ValueError, OSError) as exc:
        raise SystemExit(f"error: {exc}") from None


if __name__ == "__main__":
    main()
