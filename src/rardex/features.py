"""Audit which standard Bluetooth features a headset uses, from a capture.

For devices without a vendor app (or alongside one), the useful question is: which of the
standard profiles does it implement, and what does it report? Every finding below cites the
frames it came from, so it counts as **seen** evidence. Anything not listed was not observed
in this capture. That makes it unknown, not unsupported.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import avrcp, hfp, sdp
from .avdtp import DISCOVER, GET_ALL_CAPABILITIES, GET_CAPABILITIES, SET_CONFIGURATION, START, Endpoint
from .btsnoop import Direction
from .session import Message, Session, device_details

FROM_HEADSET = Direction.RECEIVED  # snoop logs are recorded on the phone/PC side
HEADSET_CALL_COMMANDS = {"ATA", "AT+CHUP", "AT+BLDN", "AT+BVRA", "ATD", "AT+CKPD"}
HANDSHAKE_COMMANDS = {"AT+BRSF", "+BRSF", "AT+BAC", "AT+XAPL", "AT+BIND", "+BCS", "AT+NREC", "AT+CGMI", "AT+CGMM"}


@dataclass
class Evidence:
    value: str
    frames: list[int] = field(default_factory=list)

    def __str__(self) -> str:
        cite = ", ".join(map(str, self.frames[:6])) + (" ..." if len(self.frames) > 6 else "")
        return f"{self.value}   [frames {cite}]" if self.frames else self.value


@dataclass
class HeadsetReport:
    devices: list[str] = field(default_factory=list)
    profiles: dict[str, Evidence] = field(default_factory=dict)
    hfp: list[Evidence] = field(default_factory=list)
    nonstandard: list[Evidence] = field(default_factory=list)
    battery: list[tuple[float, int, str, int]] = field(default_factory=list)  # (t, %, source, frame)
    hfp_volume: list[Evidence] = field(default_factory=list)
    call_buttons: list[Evidence] = field(default_factory=list)
    a2dp_endpoints: list[Endpoint] = field(default_factory=list)
    a2dp_codecs: list[Evidence] = field(default_factory=list)
    a2dp_selected: Evidence | None = None
    avrcp_events: Evidence | None = None
    headset_subscribes: Evidence | None = None
    absolute_volume: Evidence = field(default_factory=lambda: Evidence("unknown (no AVRCP capability exchange captured)"))
    headset_volume: list[tuple[int, int]] = field(default_factory=list)  # (value 0..127, frame) pushed by headset
    phone_volume: list[tuple[int, int]] = field(default_factory=list)  # SetAbsoluteVolume from phone
    buttons: list[Evidence] = field(default_factory=list)
    buttons_note: str = ""
    other_channels: list[Evidence] = field(default_factory=list)
    services: list[Evidence] = field(default_factory=list)  # SDP records the headset advertises
    device_id: Evidence | None = None
    media_packets: int = 0
    stream_started: list[int] = field(default_factory=list)  # AVDTP START accepted

    @property
    def volume_steps(self) -> Counter:
        values = [v for v, _ in self.headset_volume]
        return Counter(abs(b - a) for a, b in zip(values, values[1:]) if b != a)


def _replies(lines: list[tuple[Message, hfp.AtLine]], index: int) -> list[str]:
    """The phone's answer to the headset command at ``index`` (up to OK/ERROR)."""
    channel = lines[index][0].channel
    out = []
    for m, ln in lines[index + 1 :]:
        if m.channel != channel:
            continue
        if ln.from_headset:
            break
        out.append(ln.text)
        if ln.text in ("OK", "ERROR") or ln.text.startswith("+CME ERROR"):
            break
    return out


def audit(s: Session) -> HeadsetReport:
    r = HeadsetReport(media_packets=s.media_packets)
    r.devices = [f"{c.address} ({c.transport}, handle 0x{c.handle:04x})" for c in s.connections]
    for address in dict.fromkeys(c.address for c in s.connections):
        r.devices += device_details(s, address)
    t0 = s.capture.start_us

    def seen(profile: str, frame: int) -> None:
        r.profiles.setdefault(profile, Evidence(profile)).frames.append(frame)

    # -- SDP: what the headset says it offers ----------------------------------------------
    # Phones ask for the same record several times with different attribute subsets; merge
    # answers that describe the same service classes into one record.
    merged: dict[tuple[str, ...], tuple[sdp.ServiceRecord, list[int]]] = {}
    for m, record in s.sdp:
        if m.direction is not FROM_HEADSET:
            continue  # the phone's own records (e.g. its Hands-Free AG channel)
        key = tuple(c.value for c in record.classes) or (f"frame {m.frame}",)
        if key in merged:
            merged[key][0].attributes.update(record.attributes)
            merged[key][1].append(m.frame)
        else:
            merged[key] = (sdp.ServiceRecord(dict(record.attributes), m.frame), [m.frame])
    for record, frames in merged.values():
        e = Evidence(record.describe(), sorted(set(frames)))
        if record.device_id is not None:
            r.device_id = e
        else:
            r.services.append(e)

    # -- HFP / HSP ------------------------------------------------------------------------
    nonstandard: dict[str, Evidence] = {}
    last_battery: tuple[str, float] | None = None  # (line text, time) of the previous report
    for i, (m, line) in enumerate(s.at_lines):
        cmd = line.command
        t = (m.timestamp_us - t0) / 1e6
        seen("HFP/HSP (calls, AT commands) on " + m.channel, m.frame)
        if cmd in HANDSHAKE_COMMANDS and not line.text.endswith("=?"):
            if cmd == "AT+CGMI" or not line.text.endswith("?"):
                answer = ""
                if line.from_headset and cmd in ("AT+CGMI", "AT+CGMM"):
                    reply = [x for x in _replies(s.at_lines, i) if x.startswith(cmd[2:])]
                    answer = f"  (phone: {' | '.join(reply)})" if reply else ""
                r.hfp.append(Evidence(f"{line.text}  ->  {line.describe()}{answer}", [m.frame]))
        if line.from_headset and not hfp.is_standard(cmd):
            reply = " | ".join(_replies(s.at_lines, i)) or "no reply"
            nonstandard.setdefault(line.text, Evidence(f"{line.text}  ->  phone: {reply}")).frames.append(m.frame)
        pct = line.battery_percent
        if pct is not None and line.from_headset:
            if last_battery and last_battery[0] == line.text and t - last_battery[1] < 1.0:
                continue  # the identical report sent twice in a row
            r.battery.append((t, pct, cmd, m.frame))
            last_battery = (line.text, t)
        if cmd in ("AT+VGS", "+VGS", "AT+VGM", "+VGM"):
            who = "headset" if line.from_headset else "phone"
            r.hfp_volume.append(Evidence(f"{who}: {line.describe()}", [m.frame]))
        if line.from_headset and (cmd in HEADSET_CALL_COMMANDS or cmd.startswith("ATD")):
            r.call_buttons.append(Evidence(f"{line.text}  ({line.describe()})", [m.frame]))
    r.nonstandard = list(nonstandard.values())

    # -- A2DP / AVDTP -------------------------------------------------------------------
    for m, sig in s.avdtp:
        seen("A2DP (audio streaming, AVDTP)", m.frame)
        if sig.signal == DISCOVER and m.direction is FROM_HEADSET and sig.endpoints:
            r.a2dp_endpoints = sig.endpoints
        if sig.signal in (GET_CAPABILITIES, GET_ALL_CAPABILITIES) and m.direction is FROM_HEADSET and sig.codec:
            delay = ", delay reporting" if sig.delay_reporting else ""
            value = f"{sig.codec}{delay}"
            existing = next((e for e in r.a2dp_codecs if e.value == value), None)
            if existing:
                existing.frames.append(m.frame)
            else:
                r.a2dp_codecs.append(Evidence(value, [m.frame]))
        if sig.signal == START and sig.message_type == 2:
            r.stream_started.append(m.frame)
        if sig.signal == SET_CONFIGURATION and sig.is_command and sig.codec:
            if r.a2dp_selected and r.a2dp_selected.value == str(sig.codec):
                r.a2dp_selected.frames.append(m.frame)
            else:
                r.a2dp_selected = Evidence(str(sig.codec), [m.frame])

    # -- AVRCP --------------------------------------------------------------------------
    pressed: dict[str, list[int]] = {}
    held: dict[str, list[float]] = {}  # press -> release gaps in ms, per button
    last_press: dict[str, int] = {}  # button -> timestamp of its pending press
    abs_frames: list[int] = []
    subscribed: dict[str, list[int]] = {}
    for m, msg in s.avrcp:
        seen("AVRCP (remote control)", m.frame)
        from_headset = m.direction is FROM_HEADSET
        if msg.supported_events and from_headset:
            names = [avrcp.EVENTS.get(e, hex(e)) for e in msg.supported_events]
            r.avrcp_events = Evidence(", ".join(names), [m.frame])
            if avrcp.EVENT_VOLUME_CHANGED in msg.supported_events:
                r.absolute_volume = Evidence("supported: headset advertises VOLUME_CHANGED", [m.frame])
            elif "supported" not in r.absolute_volume.value:
                r.absolute_volume = Evidence("not advertised: VOLUME_CHANGED missing from headset capabilities", [m.frame])
        if msg.pdu == avrcp.PDU_SET_ABSOLUTE_VOLUME and from_headset and msg.ctype == 0x9:
            abs_frames.append(m.frame)
        if msg.pdu == avrcp.PDU_SET_ABSOLUTE_VOLUME and not from_headset and not msg.is_response and msg.volume is not None:
            r.phone_volume.append((msg.volume, m.frame))
        if msg.event == avrcp.EVENT_VOLUME_CHANGED and from_headset and msg.ctype == 0xD and msg.volume is not None:
            r.headset_volume.append((msg.volume, m.frame))
        if msg.pdu == avrcp.PDU_REGISTER_NOTIFICATION and from_headset and not msg.is_response and msg.event is not None:
            subscribed.setdefault(avrcp.EVENTS.get(msg.event, hex(msg.event)), []).append(m.frame)
        if msg.opcode == avrcp.OP_PASS_THROUGH and not msg.is_response and from_headset:
            name = avrcp.PASS_THROUGH_OPS.get(msg.operation or 0, f"op 0x{msg.operation:02x}")
            if not msg.released:
                pressed.setdefault(name, []).append(m.frame)
                last_press[name] = m.timestamp_us
            elif name in last_press:
                held.setdefault(name, []).append((m.timestamp_us - last_press.pop(name)) / 1000)
    if abs_frames:
        r.absolute_volume = Evidence("supported: headset ACCEPTED SetAbsoluteVolume", abs_frames)
    if subscribed:
        r.headset_subscribes = Evidence(
            ", ".join(f"{name} x{len(fr)}" for name, fr in subscribed.items()), [f for fr in subscribed.values() for f in fr]
        )
    for name, frames in pressed.items():
        gaps = held.get(name)
        timing = f", press->release {min(gaps):.0f}-{max(gaps):.0f} ms" if gaps else ""
        r.buttons.append(Evidence(f"{name} x{len(frames)}{timing}", frames))
    if held and max(g for gaps in held.values() for g in gaps) < 150:
        r.buttons_note = (
            "every press is released within 150 ms: the headset sends a complete click after deciding "
            "what the gesture was (e.g. long press -> skip), so wire timing does not reflect finger timing"
        )

    # -- anything else that carries data -----------------------------------------------
    counts = Counter(m.channel for m in s.messages if m.kind in ("UIH", "WRITE", "WRITE-NR", "NOTIFY", "INDICATE"))
    for channel, n in counts.items():
        frames = [m.frame for m in s.messages if m.channel == channel][:6]
        label = "BLE GATT" if channel.startswith("ATT") else "serial data (non-AT)"
        r.other_channels.append(Evidence(f"{channel}: {n} messages, {label}", frames))
        seen(f"{label} on {channel}", frames[0])
    return r


def format_report(r: HeadsetReport) -> str:
    out = ["devices:"] + [f"  {d}" for d in r.devices or ["(connection setup not captured)"]]
    out.append("\nprofiles seen:")
    out += [f"  {e}" for e in r.profiles.values()] or ["  none"]

    out.append("\nservices the headset advertises (SDP):")
    if r.device_id:
        out.append(f"  {r.device_id}")
    out += [f"  {e}" for e in r.services]
    if not r.services and not r.device_id:
        out.append("  none captured (the phone may have cached them; re-pair while logging)")

    out.append("\nA2DP audio:")
    if r.a2dp_endpoints:
        out.append("  endpoints: " + ", ".join(f"SEID {e.seid} {'sink' if e.is_sink else 'source'}" for e in r.a2dp_endpoints))
    out += [f"  headset codec: {e}" for e in r.a2dp_codecs] or ["  codecs: unknown (capability exchange not captured)"]
    if r.a2dp_selected:
        out.append(f"  selected: {r.a2dp_selected}")
    if r.media_packets:
        out.append(f"  audio packets: {r.media_packets} (not decoded)")
    elif r.stream_started:
        out.append(
            f"  {Evidence('streaming started but no audio packets in the log: the phone probably offloads A2DP encoding to its Bluetooth chip/DSP, so audio bypasses HCI', r.stream_started)}"
        )

    out.append("\nAVRCP remote control:")
    out.append(f"  absolute (hardware) volume: {r.absolute_volume}")
    if r.avrcp_events:
        out.append(f"  headset events: {r.avrcp_events}")
    if r.headset_subscribes:
        out.append(f"  headset watches phone events: {r.headset_subscribes}")
    if r.headset_volume:
        values = [v for v, _ in r.headset_volume]
        frames = [f for _, f in r.headset_volume]
        levels = sorted(set(values))
        steps = ", ".join(f"{k} x{n}" for k, n in r.volume_steps.most_common())
        out.append(f"  {Evidence(f'headset-initiated volume changes: {len(values)}', frames)}")
        out.append(f"    levels seen ({len(levels)}): {' '.join(map(str, levels))}")
        out.append(f"    step sizes: {steps}")
    if r.phone_volume:
        shown = ", ".join(f"{v}/127 (frame {f})" for v, f in r.phone_volume[:8])
        out.append(f"  phone set volume: {shown}")
    out += [f"  button pressed: {e}" for e in r.buttons] or ["  button presses: none captured"]
    if r.buttons_note:
        out.append(f"  ({r.buttons_note})")

    out.append("\nHFP (calls, battery, call volume):")
    out += [f"  {e}" for e in r.hfp] or ["  no HFP handshake captured"]
    if r.battery:
        out.append("  battery reports: " + ", ".join(f"{p}% @{t:.0f}s (frame {f})" for t, p, _, f in r.battery[:12]))
        out.append("  battery source: " + ", ".join(dict.fromkeys(src for _, _, src, _ in r.battery)))
    else:
        out.append("  battery reports: none captured")
    seen_volume = set()
    for e in r.hfp_volume:
        if e.value not in seen_volume:
            out.append(f"  {e}")
            seen_volume.add(e.value)
    out += [f"  call button: {e}" for e in r.call_buttons]
    if r.nonstandard:
        out.append("  non-standard commands from the headset (vendor-specific, worth investigating):")
        out += [f"    {e}" for e in r.nonstandard]

    out.append("\nother data channels (possible vendor protocol):")
    out += [f"  {e}" for e in r.other_channels] or ["  none - no BLE GATT writes or non-AT serial data seen"]
    out.append("\nnot listed = not observed in this capture (unknown), not proof of absence.")
    return "\n".join(out)
