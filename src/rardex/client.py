"""High-level speaker control: a ``Protocol`` plus a ``Transport``.

    proto = Protocol.load("protocols/my-speaker.toml")
    async with SpeakerClient(proto, BleTransport(addr, proto.device.write_uuid,
                                                 proto.device.notify_uuid)) as spk:
        await spk.send("volume", level=12)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable

from . import checksum as checksums
from .protocol import Framing, Protocol, _TYPES
from .transport import BleTransport, LabTransport, RfcommTransport, Transport, TransportError


@dataclass(frozen=True)
class Incoming:
    frame: bytes
    name: str | None  # matching [[responses]] entry, if any
    fields: dict[str, int | str]


class FrameReassembler:
    """Split a byte stream (RFCOMM) into frames using the protocol's prefix and length field.

    BLE notifications are already message-sized, but serial streams can split or merge frames.
    Without both a prefix and a length field there is no reliable boundary, so data is passed
    through unchanged.
    """

    def __init__(self, framing: Framing) -> None:
        self.framing = framing
        self.buffer = bytearray()

    @property
    def can_split(self) -> bool:
        return bool(self.framing.prefix) and self.framing.length is not None

    def feed(self, data: bytes) -> list[bytes]:
        if not self.can_split:
            return [data]
        self.buffer += data
        frames = []
        fr, length = self.framing, self.framing.length
        assert length is not None
        size, order, _ = _TYPES[length.type]
        ck = checksums.ALGORITHMS[fr.checksum.algorithm].width if fr.checksum else 0
        while True:
            start = self.buffer.find(fr.prefix)
            if start < 0:
                # Keep a tail that could be the first bytes of a prefix split across reads.
                del self.buffer[: max(0, len(self.buffer) - (len(fr.prefix) - 1))]
                break
            del self.buffer[:start]
            head = len(fr.prefix) + size
            if len(self.buffer) < head:
                break
            covered = int.from_bytes(self.buffer[len(fr.prefix) : head], order) - length.adjust  # type: ignore[arg-type]
            total = {
                "payload": head + covered + ck + len(fr.suffix),
                "payload+checksum": head + covered + len(fr.suffix),
                "all": covered,
            }[length.covers]
            if total < head:
                del self.buffer[: len(fr.prefix)]  # impossible length: resync past this prefix
                continue
            if len(self.buffer) < total:
                break
            frames.append(bytes(self.buffer[:total]))
            del self.buffer[:total]
        return frames


class SpeakerClient:
    def __init__(
        self,
        protocol: Protocol,
        transport: Transport,
        on_message: Callable[[Incoming], None] | None = None,
    ) -> None:
        self.protocol = protocol
        self.transport = transport
        self.on_message = on_message
        self.received: asyncio.Queue[Incoming] = asyncio.Queue()
        self._reassembler = FrameReassembler(protocol.framing)
        transport.on_receive = self._on_receive

    def _on_receive(self, data: bytes) -> None:
        chunks = self._reassembler.feed(data) if isinstance(self.transport, RfcommTransport) else [data]
        for frame in chunks:
            decoded = self.protocol.decode(frame)
            msg = Incoming(frame, decoded[0] if decoded else None, decoded[1] if decoded else {})
            self.received.put_nowait(msg)
            if self.on_message:
                self.on_message(msg)

    async def __aenter__(self) -> "SpeakerClient":
        await self.transport.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.transport.disconnect()

    async def send(self, command: str, **kwargs: Any) -> bytes:
        frame = self.protocol.build(command, **kwargs)
        await self.transport.write(frame)
        return frame

    async def send_raw(self, frame: bytes) -> None:
        await self.transport.write(frame)

    async def wait_for(self, name: str | None = None, timeout: float = 2.0) -> Incoming:
        """Wait for the next incoming frame (optionally one matching a named response)."""
        async with asyncio.timeout(timeout):
            while True:
                msg = await self.received.get()
                if name is None or msg.name == name:
                    return msg


def make_transport(protocol: Protocol, address: str | None = None, lab=None) -> Transport:
    """Build the transport a protocol file asks for; ``lab`` selects the practice speaker."""
    dev = protocol.device
    if lab is not None:
        return LabTransport(lab, dev.write_uuid)
    address = address or dev.address
    if not address:
        raise TransportError("no device address: pass --address or set device.address in the protocol file")
    if dev.transport == "rfcomm":
        if dev.channel is None:
            raise TransportError("rfcomm protocols need device.channel")
        return RfcommTransport(address, dev.channel)
    if not dev.write_uuid:
        raise TransportError("ble protocols need device.write_uuid")
    return BleTransport(address, dev.write_uuid, dev.notify_uuid, dev.write_with_response)
