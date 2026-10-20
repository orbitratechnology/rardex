"""Rebuild a device's GATT table (services, characteristics, descriptors) from a capture.

When an app connects it usually runs service discovery: Read By Group Type (services),
Read By Type 0x2803 (characteristic declarations) and Find Information (descriptors).
Seeing those responses tells us which UUID lives at each handle, so a write to ``0x0012``
becomes "write to characteristic 0000ffe1-...". Android caches the table, so if your
capture has no discovery, toggle Bluetooth off/on (or unpair/re-pair) before recording.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .att import AttPdu, Opcode, short_uuid, uuid_from_le
from .btsnoop import Direction

UUID_PRIMARY_SERVICE = "00002800-0000-1000-8000-00805f9b34fb"
UUID_SECONDARY_SERVICE = "00002801-0000-1000-8000-00805f9b34fb"
UUID_CHARACTERISTIC = "00002803-0000-1000-8000-00805f9b34fb"
UUID_CCCD = "00002902-0000-1000-8000-00805f9b34fb"

# A small subset of Bluetooth SIG assigned numbers that show up on audio devices.
KNOWN_UUIDS = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Information",
    "180f": "Battery Service",
    "1812": "Human Interface Device",
    "184e": "Audio Stream Control",
    "1850": "Published Audio Capabilities",
    "1844": "Volume Control",
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a19": "Battery Level",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a50": "PnP ID",
    "2b29": "Client Supported Features",
    "2b2a": "Database Hash",
    "2b3a": "Server Supported Features",
    "2900": "Characteristic Extended Properties",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration (CCCD)",
    "2800": "Primary Service",
    "2803": "Characteristic Declaration",
}

# Services that update firmware. Writing to them by accident can brick a device.
FIRMWARE_UPDATE_UUIDS = {
    "0000fe59-0000-1000-8000-00805f9b34fb": "Nordic Secure DFU",
    "00001530-1212-efde-1523-785feabcd123": "Nordic Legacy DFU",
}

PROPERTY_FLAGS = [
    (0x01, "broadcast"),
    (0x02, "read"),
    (0x04, "write-no-rsp"),
    (0x08, "write"),
    (0x10, "notify"),
    (0x20, "indicate"),
    (0x40, "signed-write"),
    (0x80, "ext-props"),
]


def uuid_label(full: str, compact: bool = False) -> str:
    """Readable UUID: SIG ones by name, vendor ones in full (or abbreviated when ``compact``)."""
    short = short_uuid(full)
    if compact and len(short) > 8:
        short = short[:8] + "…"
    if full in FIRMWARE_UPDATE_UUIDS:
        return f"{short} [{FIRMWARE_UPDATE_UUIDS[full]} - do not write]"
    name = KNOWN_UUIDS.get(short)
    return f"{short} ({name})" if name else short


def property_names(props: int) -> list[str]:
    return [name for bit, name in PROPERTY_FLAGS if props & bit]


@dataclass
class Characteristic:
    declaration_handle: int
    value_handle: int
    properties: int
    uuid: str
    descriptors: dict[int, str] = field(default_factory=dict)

    @property
    def property_names(self) -> list[str]:
        return property_names(self.properties)


@dataclass
class Service:
    start: int
    end: int
    uuid: str
    characteristics: list[Characteristic] = field(default_factory=list)


@dataclass
class GattDatabase:
    services: list[Service] = field(default_factory=list)
    characteristics: dict[int, Characteristic] = field(default_factory=dict)  # by value handle
    descriptors: dict[int, str] = field(default_factory=dict)  # handle -> uuid
    _requests: dict[tuple[int, Direction], AttPdu] = field(default_factory=dict, repr=False)

    def observe(self, pdu: AttPdu) -> None:
        """Feed every ATT PDU in order; discovery responses are matched to their requests."""
        if pdu.opcode in (Opcode.READ_BY_GROUP_TYPE_REQ, Opcode.READ_BY_TYPE_REQ, Opcode.FIND_INFORMATION_REQ):
            self._requests[(pdu.conn, pdu.direction)] = pdu
            return
        request = self._requests.get((pdu.conn, pdu.direction.opposite()))
        if pdu.opcode == Opcode.READ_BY_GROUP_TYPE_RSP:
            self._on_services(pdu.params)
        elif pdu.opcode == Opcode.READ_BY_TYPE_RSP and request is not None:
            if request.opcode == Opcode.READ_BY_TYPE_REQ and len(request.params) >= 6:
                if uuid_from_le(request.params[4:]) == UUID_CHARACTERISTIC:
                    self._on_characteristics(pdu.params)
        elif pdu.opcode == Opcode.FIND_INFORMATION_RSP:
            self._on_descriptors(pdu.params)

    def _on_services(self, params: bytes) -> None:
        if not params:
            return
        size = params[0]
        for off in range(1, len(params) - size + 1, size):
            start, end = struct.unpack_from("<HH", params, off)
            uuid = uuid_from_le(params[off + 4 : off + size])
            if not any(s.start == start for s in self.services):
                self.services.append(Service(start, end, uuid))
        self.services.sort(key=lambda s: s.start)
        self._attach()

    def _on_characteristics(self, params: bytes) -> None:
        if not params:
            return
        size = params[0]
        for off in range(1, len(params) - size + 1, size):
            decl, props, value_handle = struct.unpack_from("<HBH", params, off)
            uuid = uuid_from_le(params[off + 5 : off + size])
            self.characteristics[value_handle] = Characteristic(decl, value_handle, props, uuid)
        self._attach()

    def _on_descriptors(self, params: bytes) -> None:
        if not params:
            return
        size = 2 + (2 if params[0] == 1 else 16)
        for off in range(1, len(params) - size + 1, size):
            handle = struct.unpack_from("<H", params, off)[0]
            uuid = uuid_from_le(params[off + 2 : off + size])
            if uuid == UUID_CHARACTERISTIC or handle in self.characteristics:
                continue  # declarations and values also appear in Find Information output
            self.descriptors[handle] = uuid
        self._attach()

    def _attach(self) -> None:
        for service in self.services:
            service.characteristics = sorted(
                (c for c in self.characteristics.values() if service.start <= c.value_handle <= service.end),
                key=lambda c: c.value_handle,
            )
        chars = sorted(self.characteristics.values(), key=lambda c: c.value_handle)
        for handle, uuid in self.descriptors.items():
            owner = None
            for c in chars:
                if c.value_handle < handle:
                    owner = c
            if owner is not None:
                owner.descriptors[handle] = uuid

    def service_for(self, handle: int) -> Service | None:
        return next((s for s in self.services if s.start <= handle <= s.end), None)

    def describe(self, handle: int | None, compact: bool = False) -> str:
        """Human label for a handle, e.g. ``ffe1 [write-no-rsp, notify]`` or ``CCCD of ffe1``."""
        if handle is None:
            return ""
        char = self.characteristics.get(handle)
        if char is not None:
            return f"{uuid_label(char.uuid, compact)} [{', '.join(char.property_names)}]"
        desc = self.descriptors.get(handle)
        if desc is not None:
            owner = next((c for c in self.characteristics.values() if handle in c.descriptors), None)
            of = f" of {uuid_label(owner.uuid, compact=True)}" if owner else ""
            return f"{'CCCD' if desc == UUID_CCCD else uuid_label(desc, compact)}{of}"
        return "?"

    def uuid_of(self, handle: int) -> str | None:
        char = self.characteristics.get(handle)
        return char.uuid if char else self.descriptors.get(handle)

    def handle_of(self, uuid: str) -> int | None:
        return next((h for h, c in self.characteristics.items() if c.uuid == uuid), None)

    @property
    def empty(self) -> bool:
        return not self.services and not self.characteristics
