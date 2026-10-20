"""Audit which standard Bluetooth features a headset uses, from a capture.

For devices without a vendor app (or alongside one), the useful question is: which of the
standard profiles does it implement, and what does it report? Every finding below cites the
frames it came from, so it counts as **seen** evidence. Anything not listed was not observed
in this capture. That makes it unknown, not unsupported.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import avrcp, hfp
from .avdtp import DISCOVER, GET_ALL_CAPABILITIES, GET_CAPABILITIES, SET_CONFIGURATION, Endpoint
from .btsnoop import Direction
from .session import Session

FROM_HEADSET = Direction.RECEIVED  # snoop logs are recorded on the phone/PC side
HEADSET_CALL_COMMANDS = {"ATA", "AT+CHUP", "AT+BLDN", "AT+BVRA", "ATD", "AT+CKPD"}


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
    battery: list[tuple[float, int, str, int]] = field(default_factory=list)  # (t, %, source, frame)
    hfp_volume: list[Evidence] = field(default_factory=list)
    call_buttons: list[Evidence] = field(default_factory=list)
    a2dp_endpoints: list[Endpoint] = field(default_factory=list)
    a2dp_codecs: list[Evidence] = field(default_factory=list)
    a2dp_selected: Evidence | None = None
    avrcp_events: Evidence | None = None
    absolute_volume: Evidence = field(default_factory=lambda: Evidence("unknown (no AVRCP capability exchange captured)"))
    volume_changes: list[Evidence] = field(default_factory=list)
    buttons: list[Evidence] = field(default_factory=list)
    other_channels: list[Evidence] = field(default_factory=list)
    media_packets: int = 0


def audit(s: Session) -> HeadsetReport:
    r = HeadsetReport(media_packets=s.media_packets)
    r.devices = [f"{c.address} ({c.transport}, handle 0x{c.handle:04x})" for c in s.connections]
    t0 = s.capture.start_us

    def seen(profile: str, frame: int) -> None:
        r.profiles.setdefault(profile, Evidence(profile)).frames.append(frame)

    # -- HFP / HSP ------------------------------------------------------------------------
    for m, line in s.at_lines:
        cmd = line.command
        seen("HFP/HSP (calls, AT commands) on " + m.channel, m.frame)
        is_query = line.text.endswith("?")
        if cmd in ("AT+BRSF", "+BRSF", "AT+BAC", "AT+XAPL", "AT+BIND", "+BCS", "AT+NREC") and not is_query:
            r.hfp.append(Evidence(f"{line.text}  ->  {line.describe()}", [m.frame]))
        pct = line.battery_percent
        if pct is not None and line.from_headset:
            r.battery.append(((m.timestamp_us - t0) / 1e6, pct, cmd, m.frame))
        if cmd in ("AT+VGS", "+VGS", "AT+VGM", "+VGM"):
            who = "headset" if line.from_headset else "phone"
            r.hfp_volume.append(Evidence(f"{who}: {line.describe()}", [m.frame]))
        if line.from_headset and (cmd in HEADSET_CALL_COMMANDS or cmd.startswith("ATD")):
            r.call_buttons.append(Evidence(f"{line.text}  ({line.describe()})", [m.frame]))

    # -- A2DP / AVDTP -------------------------------------------------------------------
    for m, sig in s.avdtp:
        seen("A2DP (audio streaming, AVDTP)", m.frame)
        if sig.signal == DISCOVER and m.direction is FROM_HEADSET and sig.endpoints:
            r.a2dp_endpoints = sig.endpoints
        if sig.signal in (GET_CAPABILITIES, GET_ALL_CAPABILITIES) and m.direction is FROM_HEADSET and sig.codec:
            delay = ", delay reporting" if sig.delay_reporting else ""
            r.a2dp_codecs.append(Evidence(f"{sig.codec}{delay}", [m.frame]))
        if sig.signal == SET_CONFIGURATION and sig.is_command and sig.codec:
            r.a2dp_selected = Evidence(str(sig.codec), [m.frame])

    # -- AVRCP --------------------------------------------------------------------------
    pressed: dict[str, list[int]] = {}
    abs_frames: list[int] = []
    for m, msg in s.avrcp:
        seen("AVRCP (remote control)", m.frame)
        if msg.supported_events and m.direction is FROM_HEADSET:
            names = [avrcp.EVENTS.get(e, hex(e)) for e in msg.supported_events]
            r.avrcp_events = Evidence(", ".join(names), [m.frame])
            if avrcp.EVENT_VOLUME_CHANGED in msg.supported_events:
                r.absolute_volume = Evidence("supported: headset advertises VOLUME_CHANGED", [m.frame])
            elif "supported" not in r.absolute_volume.value:
                r.absolute_volume = Evidence("not advertised: VOLUME_CHANGED missing from headset capabilities", [m.frame])
        if msg.pdu == avrcp.PDU_SET_ABSOLUTE_VOLUME and m.direction is FROM_HEADSET and msg.ctype == 0x9:
            abs_frames.append(m.frame)
        if msg.volume is not None:
            who = "headset" if m.direction is FROM_HEADSET else "phone"
            r.volume_changes.append(Evidence(f"{who}: {msg.describe()}", [m.frame]))
        if msg.opcode == avrcp.OP_PASS_THROUGH and not msg.is_response and not msg.released and m.direction is FROM_HEADSET:
            name = avrcp.PASS_THROUGH_OPS.get(msg.operation or 0, f"op 0x{msg.operation:02x}")
            pressed.setdefault(name, []).append(m.frame)
    if abs_frames:
        r.absolute_volume = Evidence("supported: headset ACCEPTED SetAbsoluteVolume", abs_frames)
    r.buttons = [Evidence(f"{name} x{len(fr)}", fr) for name, fr in pressed.items()]

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

    out.append("\nA2DP audio:")
    if r.a2dp_endpoints:
        out.append("  endpoints: " + ", ".join(f"SEID {e.seid} {'sink' if e.is_sink else 'source'}" for e in r.a2dp_endpoints))
    out += [f"  headset codec: {e}" for e in r.a2dp_codecs] or ["  codecs: unknown (capability exchange not captured)"]
    if r.a2dp_selected:
        out.append(f"  selected: {r.a2dp_selected}")
    if r.media_packets:
        out.append(f"  audio packets: {r.media_packets} (not decoded)")

    out.append("\nAVRCP remote control:")
    out.append(f"  absolute (hardware) volume: {r.absolute_volume}")
    if r.avrcp_events:
        out.append(f"  headset events: {r.avrcp_events}")
    out += [f"  volume: {e}" for e in r.volume_changes[:10]]
    out += [f"  button pressed: {e}" for e in r.buttons] or ["  button presses: none captured"]

    out.append("\nHFP (calls, battery, call volume):")
    out += [f"  {e}" for e in r.hfp] or ["  no HFP handshake captured"]
    if r.battery:
        out.append("  battery reports: " + ", ".join(f"{p}% @{t:.0f}s (frame {f})" for t, p, _, f in r.battery[:12]))
        out.append("  battery source: " + ", ".join(dict.fromkeys(src for _, _, src, _ in r.battery)))
    else:
        out.append("  battery reports: none captured")
    out += [f"  {e}" for e in r.hfp_volume[:10]]
    out += [f"  call button: {e}" for e in r.call_buttons]

    out.append("\nother data channels (possible vendor protocol):")
    out += [f"  {e}" for e in r.other_channels] or ["  none - no BLE GATT writes or non-AT serial data seen"]
    out.append("\nnot listed = not observed in this capture (unknown), not proof of absence.")
    return "\n".join(out)
