"""AVDTP signaling: which audio codecs a headset supports and which one gets picked.

A2DP sets up audio over AVDTP. On the signaling channel the phone asks the headset to list
its stream endpoints (DISCOVER), asks each one for its capabilities (GET_[ALL_]CAPABILITIES),
then configures one (SET_CONFIGURATION). Audio then flows on a second L2CAP channel with
the same PSM; that media channel carries RTP and is not decoded here.

Header (single packet)::  label(4b) type(2b) msgtype(2b) | signal id (6 bits)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

DISCOVER, GET_CAPABILITIES, SET_CONFIGURATION, GET_ALL_CAPABILITIES = 0x01, 0x02, 0x03, 0x0C
SIGNALS = {
    0x01: "DISCOVER",
    0x02: "GET_CAPABILITIES",
    0x03: "SET_CONFIGURATION",
    0x04: "GET_CONFIGURATION",
    0x05: "RECONFIGURE",
    0x06: "OPEN",
    0x07: "START",
    0x08: "CLOSE",
    0x09: "SUSPEND",
    0x0A: "ABORT",
    0x0B: "SECURITY_CONTROL",
    0x0C: "GET_ALL_CAPABILITIES",
    0x0D: "DELAY_REPORT",
}
MESSAGE_TYPES = {0: "command", 1: "general reject", 2: "accept", 3: "reject"}
CATEGORY_MEDIA_CODEC = 0x07
CATEGORY_DELAY_REPORTING = 0x08

VENDOR_CODECS = {
    (0x0000004F, 0x0001): "aptX",
    (0x000000D7, 0x0024): "aptX HD",
    (0x0000012D, 0x00AA): "LDAC",
}
SBC_RATES = {0x80: 16000, 0x40: 32000, 0x20: 44100, 0x10: 48000}
SBC_MODES = {0x08: "mono", 0x04: "dual channel", 0x02: "stereo", 0x01: "joint stereo"}


@dataclass(frozen=True)
class Codec:
    name: str
    details: str = ""

    def __str__(self) -> str:
        return f"{self.name} ({self.details})" if self.details else self.name


def parse_codec(data: bytes) -> Codec:
    """Media Codec capability: media type, codec type, codec-specific information."""
    if len(data) < 2:
        return Codec("unknown")
    codec_type, info = data[1], data[2:]
    if codec_type == 0x00 and len(info) >= 4:
        rates = [f"{r / 1000:g}k" for bit, r in SBC_RATES.items() if info[0] & bit]
        modes = [m for bit, m in SBC_MODES.items() if info[0] & bit]
        return Codec("SBC", f"{'/'.join(rates)}, {', '.join(modes)}, bitpool {info[2]}-{info[3]}")
    if codec_type == 0x00:
        return Codec("SBC")
    if codec_type == 0x02:
        return Codec("AAC")
    if codec_type == 0xFF and len(info) >= 6:
        vendor, codec = struct.unpack_from("<IH", info)
        return Codec(VENDOR_CODECS.get((vendor, codec), f"vendor 0x{vendor:08x} codec 0x{codec:04x}"))
    return Codec(f"codec type 0x{codec_type:02x}")


def parse_capabilities(data: bytes) -> dict[int, bytes]:
    caps, i = {}, 0
    while i + 2 <= len(data):
        category, length = data[i], data[i + 1]
        caps[category] = data[i + 2 : i + 2 + length]
        i += 2 + length
    return caps


@dataclass(frozen=True)
class Endpoint:
    seid: int
    in_use: bool
    media_type: int  # 0 audio
    is_sink: bool


@dataclass(frozen=True)
class AvdtpSignal:
    label: int
    message_type: int
    signal: int
    payload: bytes
    endpoints: list[Endpoint] = field(default_factory=list)
    codec: Codec | None = None
    delay_reporting: bool = False

    @property
    def is_command(self) -> bool:
        return self.message_type == 0

    def describe(self) -> str:
        name = SIGNALS.get(self.signal, f"signal 0x{self.signal:02x}")
        parts = [f"{name} {MESSAGE_TYPES.get(self.message_type, '?')}"]
        if self.endpoints:
            parts.append(
                "endpoints: "
                + ", ".join(f"SEID {e.seid} {'sink' if e.is_sink else 'source'}" for e in self.endpoints)
            )
        if self.codec:
            parts.append(f"codec: {self.codec}")
        return "; ".join(parts)


def parse(data: bytes) -> AvdtpSignal | None:
    if len(data) < 2:
        return None
    label, ptype, mtype, signal = data[0] >> 4, (data[0] >> 2) & 3, data[0] & 3, data[1] & 0x3F
    if ptype != 0:
        return None  # fragmented signaling; rare for these small messages
    payload = data[2:]
    endpoints: list[Endpoint] = []
    codec = None
    delay = False
    if signal == DISCOVER and mtype == 2:
        for i in range(0, len(payload) - 1, 2):
            a, b = payload[i], payload[i + 1]
            endpoints.append(Endpoint(a >> 2, bool(a >> 1 & 1), b >> 4, bool(b >> 3 & 1)))
    caps_data = None
    if signal in (GET_CAPABILITIES, GET_ALL_CAPABILITIES) and mtype == 2:
        caps_data = payload
    elif signal == SET_CONFIGURATION and mtype == 0 and len(payload) >= 2:
        caps_data = payload[2:]  # after ACP SEID and INT SEID
    if caps_data is not None:
        caps = parse_capabilities(caps_data)
        if CATEGORY_MEDIA_CODEC in caps:
            codec = parse_codec(caps[CATEGORY_MEDIA_CODEC])
        delay = CATEGORY_DELAY_REPORTING in caps
    return AvdtpSignal(label, mtype, signal, payload, endpoints, codec, delay)


def build(label: int, message_type: int, signal: int, payload: bytes) -> bytes:
    return bytes([label << 4 | message_type, signal]) + payload


def capability(category: int, data: bytes) -> bytes:
    return bytes([category, len(data)]) + data
