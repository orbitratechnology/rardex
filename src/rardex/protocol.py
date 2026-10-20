"""Declarative speaker protocols: describe the frame format once in TOML, get frame builders.

A protocol file has four parts (see ``protocols/template.toml`` for a commented example)::

    [device]      how to reach the speaker (BLE UUIDs or RFCOMM channel)
    [framing]     what wraps every command: prefix, length field, checksum, suffix
    [commands.X]  payload templates such as "02 {level:u8}"
    [[responses]] how to recognize and decode what the speaker sends back

Frame layout produced by ``Framing.wrap``::

    prefix | length? | payload | checksum? | suffix
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import checksum as checksums
from .att import normalize_uuid
from .util import parse_hex

_TYPES: dict[str, tuple[int, str, bool]] = {
    # name: (bytes, byteorder, signed)
    "u8": (1, "little", False),
    "i8": (1, "little", True),
    "u16le": (2, "little", False),
    "u16be": (2, "big", False),
    "i16le": (2, "little", True),
    "i16be": (2, "big", True),
    "u32le": (4, "little", False),
    "u32be": (4, "big", False),
    "bool": (1, "little", False),
}
_PLACEHOLDER = re.compile(r"\{(\w+)(?::(\w+))?\}")
_LENGTH_COVERS = ("payload", "payload+checksum", "all")
_CHECKSUM_COVERS = ("payload", "length+payload", "all")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class LengthSpec:
    type: str = "u8"
    covers: str = "payload"
    adjust: int = 0


@dataclass(frozen=True)
class ChecksumSpec:
    algorithm: str
    covers: str = "length+payload"
    byteorder: str = "little"


@dataclass(frozen=True)
class Framing:
    prefix: bytes = b""
    suffix: bytes = b""
    length: LengthSpec | None = None
    checksum: ChecksumSpec | None = None

    def wrap(self, payload: bytes) -> bytes:
        ck_width = checksums.ALGORITHMS[self.checksum.algorithm].width if self.checksum else 0
        length_bytes = b""
        if self.length:
            size, order, _ = _TYPES[self.length.type]
            covered = {
                "payload": len(payload),
                "payload+checksum": len(payload) + ck_width,
                "all": len(self.prefix) + size + len(payload) + ck_width + len(self.suffix),
            }[self.length.covers]
            length_bytes = _pack(covered + self.length.adjust, self.length.type, "length")
        check = b""
        if self.checksum:
            region = {
                "payload": payload,
                "length+payload": length_bytes + payload,
                "all": self.prefix + length_bytes + payload,
            }[self.checksum.covers]
            check = checksums.compute(self.checksum.algorithm, region, self.checksum.byteorder)
        return self.prefix + length_bytes + payload + check + self.suffix

    def unwrap(self, frame: bytes) -> bytes:
        """Validate a received frame and return its payload; raises ``ProtocolError``."""
        if not frame.startswith(self.prefix) or not frame.endswith(self.suffix):
            raise ProtocolError("prefix/suffix mismatch")
        body = frame[len(self.prefix) : len(frame) - len(self.suffix)]
        length_size = _TYPES[self.length.type][0] if self.length else 0
        ck_width = checksums.ALGORITHMS[self.checksum.algorithm].width if self.checksum else 0
        if len(body) < length_size + ck_width:
            raise ProtocolError("frame too short")
        payload = body[length_size : len(body) - ck_width]
        if self.wrap(payload) != frame:
            raise ProtocolError("length or checksum mismatch")
        return payload


@dataclass(frozen=True)
class ArgSpec:
    min: int | None = None
    max: int | None = None
    choices: dict[str, int] = field(default_factory=dict)
    default: int | str | None = None

    def coerce(self, name: str, raw: Any) -> int:
        if isinstance(raw, str):
            if raw in self.choices:
                return self.choices[raw]
            if raw.lower() in ("true", "on"):
                raw = 1
            elif raw.lower() in ("false", "off"):
                raw = 0
            else:
                try:
                    raw = int(raw, 0)
                except ValueError:
                    options = f" (choices: {', '.join(self.choices)})" if self.choices else ""
                    raise ProtocolError(f"{name}: cannot use {raw!r}{options}") from None
        value = int(raw)
        if self.min is not None and value < self.min or self.max is not None and value > self.max:
            raise ProtocolError(f"{name}={value} outside allowed range {self.min}..{self.max}")
        return value


@dataclass(frozen=True)
class Command:
    name: str
    template: str
    description: str = ""
    args: dict[str, ArgSpec] = field(default_factory=dict)

    @property
    def placeholders(self) -> list[tuple[str, str]]:
        return [(m.group(1), m.group(2) or "u8") for m in _PLACEHOLDER.finditer(self.template)]

    def encode(self, **kwargs: Any) -> bytes:
        out = bytearray()
        pos = 0
        for m in _PLACEHOLDER.finditer(self.template):
            out += parse_hex(self.template[pos : m.start()])
            name, typ = m.group(1), m.group(2) or "u8"
            spec = self.args.get(name, ArgSpec())
            if name in kwargs:
                raw = kwargs[name]
            elif spec.default is not None:
                raw = spec.default
            else:
                raise ProtocolError(f"command {self.name!r} needs argument {name!r}")
            value = spec.coerce(name, raw)
            if typ == "bool" and value not in (0, 1):
                raise ProtocolError(f"{name} is a bool: use 0/1, on/off or true/false")
            out += _pack(value, typ, name)
            pos = m.end()
        out += parse_hex(self.template[pos:])
        unknown = set(kwargs) - {n for n, _ in self.placeholders}
        if unknown:
            raise ProtocolError(f"command {self.name!r} has no argument(s) {', '.join(sorted(unknown))}")
        return bytes(out)

    def match(self, payload: bytes) -> dict[str, int | str] | None:
        """Inverse of ``encode``: the arguments if ``payload`` fits this template, else None."""
        values: dict[str, int | str] = {}
        offset = pos = 0
        for m in _PLACEHOLDER.finditer(self.template):
            const = parse_hex(self.template[pos : m.start()])
            if payload[offset : offset + len(const)] != const:
                return None
            offset += len(const)
            name, typ = m.group(1), m.group(2) or "u8"
            size, order, signed = _TYPES[typ]
            if offset + size > len(payload):
                return None
            value = int.from_bytes(payload[offset : offset + size], order, signed=signed)  # type: ignore[arg-type]
            names = {v: k for k, v in self.args.get(name, ArgSpec()).choices.items()}
            values[name] = names.get(value, value)
            offset += size
            pos = m.end()
        return values if payload[offset:] == parse_hex(self.template[pos:]) else None


@dataclass(frozen=True)
class Response:
    name: str
    pattern: list[int | None]  # None = wildcard byte
    fields: dict[str, tuple[str, int]]  # name -> (type, offset into the full frame)
    labels: dict[str, dict[int, str]] = field(default_factory=dict)

    def matches(self, frame: bytes) -> bool:
        return len(frame) >= len(self.pattern) and all(p is None or frame[i] == p for i, p in enumerate(self.pattern))

    def decode(self, frame: bytes) -> dict[str, int | str]:
        out: dict[str, int | str] = {}
        for name, (typ, offset) in self.fields.items():
            size, order, signed = _TYPES[typ]
            if offset + size > len(frame):
                continue
            value = int.from_bytes(frame[offset : offset + size], order, signed=signed)  # type: ignore[arg-type]
            out[name] = self.labels.get(name, {}).get(value, value)
        return out


@dataclass(frozen=True)
class Device:
    name: str = "unnamed speaker"
    transport: str = "ble"  # "ble" or "rfcomm"
    address: str | None = None
    write_uuid: str | None = None
    notify_uuid: str | None = None
    write_with_response: bool = False
    channel: int | None = None


@dataclass(frozen=True)
class Protocol:
    device: Device
    framing: Framing
    commands: dict[str, Command]
    responses: list[Response]
    source: Path | None = None

    def build(self, command: str, **kwargs: Any) -> bytes:
        try:
            cmd = self.commands[command]
        except KeyError:
            raise ProtocolError(f"unknown command {command!r}; known: {', '.join(self.commands)}") from None
        return self.framing.wrap(cmd.encode(**kwargs))

    def decode(self, frame: bytes) -> tuple[str, dict[str, int | str]] | None:
        for r in self.responses:
            if r.matches(frame):
                return r.name, r.decode(frame)
        return None

    def identify(self, frame: bytes) -> tuple[str, dict[str, int | str]] | None:
        """Name a frame: a known response, or a command whose template it fits."""
        decoded = self.decode(frame)
        if decoded:
            return decoded
        try:
            payload = self.framing.unwrap(frame)
        except ProtocolError:
            return None
        for cmd in self.commands.values():
            args = cmd.match(payload)
            if args is not None:
                return cmd.name, args
        return None

    @classmethod
    def load(cls, path: str | Path) -> "Protocol":
        path = Path(path)
        with path.open("rb") as fh:
            return cls.from_dict(tomllib.load(fh), path)

    @classmethod
    def loads(cls, text: str) -> "Protocol":
        return cls.from_dict(tomllib.loads(text))

    @classmethod
    def from_dict(cls, doc: dict[str, Any], source: Path | None = None) -> "Protocol":
        dev = dict(doc.get("device", {}))
        for key in ("write_uuid", "notify_uuid"):
            if dev.get(key):
                dev[key] = normalize_uuid(dev[key])
        device = Device(**dev)
        if device.transport not in ("ble", "rfcomm"):
            raise ProtocolError(f"device.transport must be 'ble' or 'rfcomm', not {device.transport!r}")

        fr = doc.get("framing", {})
        length = LengthSpec(**fr["length"]) if "length" in fr else None
        check = ChecksumSpec(**fr["checksum"]) if "checksum" in fr else None
        if length and (length.type not in _TYPES or length.covers not in _LENGTH_COVERS):
            raise ProtocolError(f"bad framing.length: {length}")
        if check and (check.algorithm not in checksums.ALGORITHMS or check.covers not in _CHECKSUM_COVERS):
            raise ProtocolError(f"bad framing.checksum: {check}; algorithms: {', '.join(checksums.ALGORITHMS)}")
        framing = Framing(parse_hex(fr.get("prefix", "")), parse_hex(fr.get("suffix", "")), length, check)

        commands = {}
        for name, spec in doc.get("commands", {}).items():
            args = {k: ArgSpec(**v) for k, v in spec.get("args", {}).items()}
            cmd = Command(name, spec["payload"], spec.get("description", ""), args)
            for _, typ in cmd.placeholders:
                if typ not in _TYPES:
                    raise ProtocolError(f"command {name!r}: unknown type {typ!r}; use one of {', '.join(_TYPES)}")
            commands[name] = cmd

        responses = []
        for spec in doc.get("responses", []):
            pattern = [None if tok == "??" else int(tok, 16) for tok in spec["match"].split()]
            fields = {}
            for fname, where in spec.get("fields", {}).items():
                typ, _, offset = where.partition("@")
                if typ not in _TYPES or not offset:
                    raise ProtocolError(f"response {spec['name']!r}: field {fname!r} must look like 'u8@4'")
                fields[fname] = (typ, int(offset, 0))
            labels = {k: {int(n, 0): s for n, s in v.items()} for k, v in spec.get("labels", {}).items()}
            responses.append(Response(spec["name"], pattern, fields, labels))
        return cls(device, framing, commands, responses, source)


def _pack(value: int, typ: str, name: str) -> bytes:
    size, order, signed = _TYPES[typ]
    try:
        return value.to_bytes(size, order, signed=signed)  # type: ignore[arg-type]
    except OverflowError:
        raise ProtocolError(f"{name}={value} does not fit in {typ}") from None
