"""ATT (Attribute Protocol) PDUs - the transport for everything GATT does on BLE.

A BLE speaker's custom control channel almost always looks like this in a capture:

* the app sends **Write Command (0x52)** or **Write Request (0x12)** to one handle,
* the speaker answers with **Handle Value Notification (0x1B)** on another handle,
* the app first enables those notifications by writing ``01 00`` to that characteristic's
  CCCD descriptor (UUID 0x2902).

Handles are per-device numbers; UUIDs are what stay stable across devices and firmware.
``gatt.GattDatabase`` maps one to the other using the discovery traffic in the capture.
"""

from __future__ import annotations

import struct
import uuid as _uuid
from dataclasses import dataclass
from enum import IntEnum

from .btsnoop import Direction


class Opcode(IntEnum):
    ERROR_RSP = 0x01
    EXCHANGE_MTU_REQ = 0x02
    EXCHANGE_MTU_RSP = 0x03
    FIND_INFORMATION_REQ = 0x04
    FIND_INFORMATION_RSP = 0x05
    FIND_BY_TYPE_VALUE_REQ = 0x06
    FIND_BY_TYPE_VALUE_RSP = 0x07
    READ_BY_TYPE_REQ = 0x08
    READ_BY_TYPE_RSP = 0x09
    READ_REQ = 0x0A
    READ_RSP = 0x0B
    READ_BLOB_REQ = 0x0C
    READ_BLOB_RSP = 0x0D
    READ_MULTIPLE_REQ = 0x0E
    READ_MULTIPLE_RSP = 0x0F
    READ_BY_GROUP_TYPE_REQ = 0x10
    READ_BY_GROUP_TYPE_RSP = 0x11
    WRITE_REQ = 0x12
    WRITE_RSP = 0x13
    PREPARE_WRITE_REQ = 0x16
    PREPARE_WRITE_RSP = 0x17
    EXECUTE_WRITE_REQ = 0x18
    EXECUTE_WRITE_RSP = 0x19
    HANDLE_VALUE_NTF = 0x1B
    HANDLE_VALUE_IND = 0x1D
    HANDLE_VALUE_CFM = 0x1E
    WRITE_CMD = 0x52
    SIGNED_WRITE_CMD = 0xD2


SHORT_NAMES = {
    Opcode.WRITE_REQ: "WRITE",
    Opcode.WRITE_CMD: "WRITE-NR",
    Opcode.HANDLE_VALUE_NTF: "NOTIFY",
    Opcode.HANDLE_VALUE_IND: "INDICATE",
    Opcode.READ_REQ: "READ-REQ",
    Opcode.READ_RSP: "READ",
    Opcode.READ_BLOB_RSP: "READ-BLOB",
}

# Opcodes whose parameters start with a handle followed by an attribute value.
_HANDLE_VALUE = {
    Opcode.WRITE_REQ,
    Opcode.WRITE_CMD,
    Opcode.HANDLE_VALUE_NTF,
    Opcode.HANDLE_VALUE_IND,
}
# Opcodes that carry only a handle.
_HANDLE_ONLY = {Opcode.READ_REQ}

ERROR_CODES = {
    0x01: "Invalid Handle",
    0x02: "Read Not Permitted",
    0x03: "Write Not Permitted",
    0x05: "Insufficient Authentication",
    0x06: "Request Not Supported",
    0x07: "Invalid Offset",
    0x0A: "Attribute Not Found",
    0x0D: "Invalid Attribute Value Length",
    0x0E: "Unlikely Error",
    0x0F: "Insufficient Encryption",
}

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def uuid_from_le(raw: bytes) -> str:
    """ATT sends UUIDs little-endian; return the canonical 128-bit string form."""
    if len(raw) == 2:
        return f"0000{struct.unpack('<H', raw)[0]:04x}{BASE_UUID_SUFFIX}"
    if len(raw) == 16:
        return str(_uuid.UUID(bytes=raw[::-1]))
    raise ValueError(f"UUID must be 2 or 16 bytes, got {len(raw)}")


def uuid_to_le(text: str) -> bytes:
    """Inverse of ``uuid_from_le``: SIG-base UUIDs shrink back to their 16-bit form."""
    full = normalize_uuid(text)
    if full.endswith(BASE_UUID_SUFFIX) and full.startswith("0000"):
        return struct.pack("<H", int(full[4:8], 16))
    return _uuid.UUID(full).bytes[::-1]


def normalize_uuid(text: str) -> str:
    """Accept ``ffe1``, ``0xFFE1`` or a full UUID; return the lowercase 128-bit form."""
    t = text.lower().removeprefix("0x")
    if len(t) == 4:
        return f"0000{t}{BASE_UUID_SUFFIX}"
    if len(t) == 8:
        return f"{t}{BASE_UUID_SUFFIX}"
    return str(_uuid.UUID(t))


def short_uuid(full: str) -> str:
    """``0000ffe1-0000-1000-8000-00805f9b34fb`` -> ``ffe1``; vendor UUIDs are returned whole."""
    if full.endswith(BASE_UUID_SUFFIX) and full.startswith("0000"):
        return full[4:8]
    return full


@dataclass(frozen=True)
class AttPdu:
    frame: int
    timestamp_us: int
    direction: Direction
    conn: int  # HCI connection handle
    opcode: int
    handle: int | None
    value: bytes  # attribute value for writes/notifications/reads; raw parameters otherwise
    params: bytes

    @property
    def name(self) -> str:
        try:
            op = Opcode(self.opcode)
        except ValueError:
            return f"OP_0x{self.opcode:02x}"
        return SHORT_NAMES.get(op, op.name)

    @property
    def is_write(self) -> bool:
        return self.opcode in (Opcode.WRITE_REQ, Opcode.WRITE_CMD)

    @property
    def is_notification(self) -> bool:
        return self.opcode in (Opcode.HANDLE_VALUE_NTF, Opcode.HANDLE_VALUE_IND)

    @property
    def carries_data(self) -> bool:
        """True for the PDUs that move application data (what you usually want to look at)."""
        return self.is_write or self.is_notification or self.opcode in (Opcode.READ_RSP, Opcode.READ_BLOB_RSP)


def parse(
    frame: int, timestamp_us: int, direction: Direction, conn: int, payload: bytes
) -> AttPdu | None:
    if not payload:
        return None
    opcode, params = payload[0], payload[1:]
    handle: int | None = None
    value = params
    if opcode in _HANDLE_VALUE and len(params) >= 2:
        handle = struct.unpack_from("<H", params)[0]
        value = params[2:]
    elif opcode in _HANDLE_ONLY and len(params) >= 2:
        handle = struct.unpack_from("<H", params)[0]
        value = b""
    elif opcode == Opcode.SIGNED_WRITE_CMD and len(params) >= 14:
        handle = struct.unpack_from("<H", params)[0]
        value = params[2:-12]  # trailing 12-byte authentication signature
    return AttPdu(frame, timestamp_us, direction, conn, opcode, handle, value, params)


def describe_error(params: bytes) -> str:
    if len(params) < 4:
        return "malformed error response"
    req, handle, code = struct.unpack_from("<BHB", params)
    try:
        req_name = Opcode(req).name
    except ValueError:
        req_name = f"0x{req:02x}"
    return f"{req_name} on 0x{handle:04x}: {ERROR_CODES.get(code, f'error 0x{code:02x}')}"


# -- builders (used by the practice lab and tests) --------------------------------------


def build(opcode: int, *parts: bytes) -> bytes:
    return bytes([opcode]) + b"".join(parts)


def build_handle_value(opcode: int, handle: int, value: bytes) -> bytes:
    return build(opcode, struct.pack("<H", handle), value)
