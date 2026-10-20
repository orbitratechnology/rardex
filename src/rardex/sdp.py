"""SDP: the service records a classic Bluetooth device advertises.

When a phone connects, it asks the device (and the device asks the phone) which services
exist and how to reach them: profile UUIDs and versions, the L2CAP PSM or RFCOMM channel,
supported-feature bitmasks, and often a **Device ID** record (service class 0x1200). That
record carries a vendor id, which is usually the Bluetooth SIG company id of the chip/SDK
vendor. Service *names* are free text, and SDKs often leave their own prefix in them.

Wire format: PDU id | transaction id u16 | parameter length u16 | parameters. Attribute data
uses SDP "data elements": a header byte (type << 3 | size index) followed by the value.
Long responses are split across PDUs with a continuation state, so they are reassembled.
"""

from __future__ import annotations

import struct
import uuid as _uuid
from dataclasses import dataclass
from typing import Any

from .assigned import COMPANIES

SEARCH_ATTR_REQ, SEARCH_ATTR_RSP = 0x06, 0x07
ATTR_REQ, ATTR_RSP = 0x04, 0x05
PDU_NAMES = {0x01: "error", 0x02: "search req", 0x03: "search rsp", 0x04: "attribute req", 0x05: "attribute rsp", 0x06: "search+attribute req", 0x07: "search+attribute rsp"}

UUID_NAMES = {
    "0001": "SDP",
    "0003": "RFCOMM",
    "0017": "AVCTP",
    "0019": "AVDTP",
    "0100": "L2CAP",
    "1002": "Public Browse Group",
    "1101": "Serial Port (SPP)",
    "1108": "Headset",
    "110a": "A2DP Source",
    "110b": "A2DP Sink",
    "110c": "AVRCP Target",
    "110d": "A2DP",
    "110e": "AVRCP",
    "110f": "AVRCP Controller",
    "1112": "Headset AG",
    "111e": "Hands-Free",
    "111f": "Hands-Free AG",
    "112e": "Phonebook Client",
    "112f": "Phonebook Server",
    "1131": "Headset HS",
    "1132": "Message Access Server",
    "1200": "Device ID (PnP Information)",
    "1203": "Generic Audio",
}

ATTR_CLASSES, ATTR_PROTOCOLS, ATTR_PROFILES = 0x0001, 0x0004, 0x0009
ATTR_NAME, ATTR_FEATURES = 0x0100, 0x0311
ATTR_VENDOR, ATTR_PRODUCT, ATTR_VERSION, ATTR_VENDOR_SOURCE = 0x0201, 0x0202, 0x0203, 0x0205


@dataclass(frozen=True)
class Uuid:
    value: str  # "110b" for 16/32-bit SIG UUIDs, full string otherwise

    @property
    def name(self) -> str:
        return UUID_NAMES.get(self.value, self.value)


class SdpError(ValueError):
    pass


def parse_element(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode one data element; returns (python value, offset after it)."""
    if offset >= len(data):
        raise SdpError("truncated data element")
    header = data[offset]
    kind, size_index = header >> 3, header & 7
    offset += 1
    if kind == 0:
        return None, offset
    if size_index < 5:
        size = (1, 2, 4, 8, 16)[size_index]
    else:
        width = (1, 2, 4)[size_index - 5]
        if offset + width > len(data):
            raise SdpError("truncated element length")
        size = int.from_bytes(data[offset : offset + width], "big")
        offset += width
    raw = data[offset : offset + size]
    if len(raw) != size:
        raise SdpError("truncated element value")
    end = offset + size
    if kind == 1:
        return int.from_bytes(raw, "big"), end
    if kind == 2:
        return int.from_bytes(raw, "big", signed=True), end
    if kind == 3:
        if size in (2, 4):
            return Uuid(f"{int.from_bytes(raw, 'big'):04x}"), end
        return Uuid(str(_uuid.UUID(bytes=raw))), end
    if kind in (4, 8):
        return raw.rstrip(b"\x00").decode("utf-8", errors="replace"), end
    if kind == 5:
        return bool(raw[0]) if raw else False, end
    if kind in (6, 7):
        items, inner = [], offset
        while inner < end:
            value, inner = parse_element(data[:end], inner)
            items.append(value)
        return items, end
    raise SdpError(f"unknown data element type {kind}")


def _version(v: Any) -> str:
    return f"{v >> 8}.{v & 0xFF}" if isinstance(v, int) else "?"


@dataclass
class ServiceRecord:
    attributes: dict[int, Any]
    frame: int

    @property
    def classes(self) -> list[Uuid]:
        value = self.attributes.get(ATTR_CLASSES, [])
        return [u for u in value if isinstance(u, Uuid)] if isinstance(value, list) else []

    @property
    def name(self) -> str | None:
        value = self.attributes.get(ATTR_NAME)
        return value if isinstance(value, str) else None

    @property
    def profiles(self) -> list[tuple[Uuid, str]]:
        out = []
        for entry in self.attributes.get(ATTR_PROFILES, []) or []:
            if isinstance(entry, list) and entry and isinstance(entry[0], Uuid):
                out.append((entry[0], _version(entry[1]) if len(entry) > 1 else "?"))
        return out

    @property
    def protocols(self) -> list[tuple[Uuid, list[Any]]]:
        out = []
        for entry in self.attributes.get(ATTR_PROTOCOLS, []) or []:
            if isinstance(entry, list) and entry and isinstance(entry[0], Uuid):
                out.append((entry[0], entry[1:]))
        return out

    @property
    def psm(self) -> int | None:
        return next((p[0] for u, p in self.protocols if u.value == "0100" and p), None)

    @property
    def rfcomm_channel(self) -> int | None:
        return next((p[0] for u, p in self.protocols if u.value == "0003" and p), None)

    @property
    def device_id(self) -> dict[str, int] | None:
        if not any(c.value == "1200" for c in self.classes):
            return None
        keys = {"vendor": ATTR_VENDOR, "product": ATTR_PRODUCT, "version": ATTR_VERSION, "source": ATTR_VENDOR_SOURCE}
        return {k: self.attributes[a] for k, a in keys.items() if isinstance(self.attributes.get(a), int)}

    def describe(self) -> str:
        did = self.device_id
        if did is not None:
            vendor = did.get("vendor")
            source = {1: "Bluetooth SIG company id", 2: "USB vendor id"}.get(did.get("source", 0), "unknown id source")
            name = COMPANIES.get(vendor, "") if did.get("source") == 1 else ""
            parts = [f"Device ID: vendor 0x{vendor:04x} ({source}{': ' + name if name else ''})" if vendor is not None else "Device ID"]
            if "product" in did:
                parts.append(f"product 0x{did['product']:04x}")
            if "version" in did:
                parts.append(f"version 0x{did['version']:04x}")
            return ", ".join(parts)
        classes = " + ".join(c.name for c in self.classes) or "service (class not requested)"
        bits = [classes]
        if self.profiles:
            bits.append(", ".join(f"{u.name} v{v}" for u, v in self.profiles))
        if self.name:
            bits.append(f"name {self.name!r}")
        if self.rfcomm_channel is not None:
            bits.append(f"RFCOMM channel {self.rfcomm_channel}")
        elif self.psm is not None:
            bits.append(f"PSM 0x{self.psm:04x}")
        features = self.attributes.get(ATTR_FEATURES)
        if isinstance(features, int):
            bits.append(f"features 0x{features:04x}")
        return "; ".join(bits)


def records_from_attribute_lists(blob: bytes, frame: int, single: bool) -> list[ServiceRecord]:
    """``single`` for an attribute response (one record), else a list of records."""
    value, _ = parse_element(blob)
    lists = [value] if single else value
    records = []
    for attr_list in lists or []:
        if not isinstance(attr_list, list):
            continue
        pairs = dict(zip(attr_list[::2], attr_list[1::2]))
        records.append(ServiceRecord({k: v for k, v in pairs.items() if isinstance(k, int)}, frame))
    return records


@dataclass(frozen=True)
class SdpPdu:
    pdu_id: int
    transaction: int
    params: bytes

    @property
    def name(self) -> str:
        return PDU_NAMES.get(self.pdu_id, f"PDU 0x{self.pdu_id:02x}")

    @property
    def search_uuids(self) -> list[Uuid]:
        """UUIDs a search request asks for."""
        if self.pdu_id not in (0x02, SEARCH_ATTR_REQ):
            return []
        try:
            pattern, _ = parse_element(self.params)
        except SdpError:
            return []
        return [u for u in pattern if isinstance(u, Uuid)] if isinstance(pattern, list) else []

    def attribute_chunk(self) -> tuple[bytes, bytes] | None:
        """(attribute list bytes, continuation state) for attribute responses."""
        if self.pdu_id not in (ATTR_RSP, SEARCH_ATTR_RSP) or len(self.params) < 2:
            return None
        count = struct.unpack_from(">H", self.params)[0]
        chunk = self.params[2 : 2 + count]
        rest = self.params[2 + count :]
        cont = rest[1 : 1 + rest[0]] if rest else b""
        return chunk, cont


def parse_pdu(payload: bytes) -> SdpPdu | None:
    if len(payload) < 5:
        return None
    pdu_id, tid, length = struct.unpack_from(">BHH", payload)
    return SdpPdu(pdu_id, tid, payload[5 : 5 + length])


class SdpReassembler:
    """Collects continued responses per link and direction; yields complete records."""

    def __init__(self) -> None:
        self._buffers: dict[tuple[int, int], bytearray] = {}

    def feed(self, key: tuple[int, int], pdu: SdpPdu, frame: int) -> list[ServiceRecord] | None:
        """Records once a response is complete (possibly []), or None while more is expected."""
        chunk = pdu.attribute_chunk()
        if chunk is None:
            return None
        data, cont = chunk
        buf = self._buffers.setdefault(key, bytearray())
        buf += data
        if cont:
            return None
        blob = bytes(buf)
        del self._buffers[key]
        try:
            return records_from_attribute_lists(blob, frame, single=pdu.pdu_id == ATTR_RSP)
        except SdpError:
            return []


def element(kind: int, value: bytes) -> bytes:
    """Encode a data element (used by tests/lab); picks the smallest length form."""
    sizes = {1: 0, 2: 1, 4: 2, 8: 3, 16: 4}
    if kind in (1, 2, 3, 5) and len(value) in sizes:
        return bytes([kind << 3 | sizes[len(value)]]) + value
    if len(value) < 256:
        return bytes([kind << 3 | 5, len(value)]) + value
    return bytes([kind << 3 | 6]) + struct.pack(">H", len(value)) + value
