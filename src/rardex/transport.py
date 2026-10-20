"""Ways to move bytes to and from a speaker.

* ``BleTransport``    - GATT write/notify via ``bleak`` (Linux/BlueZ, macOS, Windows).
* ``RfcommTransport`` - classic Bluetooth serial port (SPP) via Linux RFCOMM sockets.
* ``LabTransport``    - the in-process practice speaker from ``rardex.lab``; no radio needed.

All transports are async and deliver incoming data to ``on_receive``.
"""

from __future__ import annotations

import asyncio
import socket
from abc import ABC, abstractmethod
from typing import Callable

from .att import normalize_uuid

Receiver = Callable[[bytes], None]


class TransportError(RuntimeError):
    pass


class Transport(ABC):
    def __init__(self) -> None:
        self.on_receive: Receiver | None = None

    def _deliver(self, data: bytes) -> None:
        if self.on_receive is not None:
            self.on_receive(data)

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def write(self, data: bytes) -> None: ...


def _bleak():
    try:
        import bleak
    except ImportError:
        raise TransportError("BLE needs the optional dependency: pip install 'rardex[ble]'") from None
    return bleak


class BleTransport(Transport):
    def __init__(
        self,
        address: str,
        write_uuid: str,
        notify_uuid: str | None = None,
        with_response: bool = False,
        timeout: float = 15.0,
    ) -> None:
        super().__init__()
        self.address = address
        self.write_uuid = normalize_uuid(write_uuid)
        self.notify_uuid = normalize_uuid(notify_uuid) if notify_uuid else None
        self.with_response = with_response
        self.timeout = timeout
        self._client = None

    async def connect(self) -> None:
        bleak = _bleak()
        self._client = bleak.BleakClient(self.address, timeout=self.timeout)
        await self._client.connect()
        if self.notify_uuid:
            await self._client.start_notify(self.notify_uuid, lambda _char, data: self._deliver(bytes(data)))

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None

    async def write(self, data: bytes) -> None:
        if self._client is None:
            raise TransportError("not connected")
        limit = self._client.mtu_size - 3
        if len(data) > limit:
            raise TransportError(
                f"{len(data)}-byte frame exceeds the {limit}-byte ATT payload for this connection; "
                "check how the vendor app splits long frames in your capture"
            )
        await self._client.write_gatt_char(self.write_uuid, data, response=self.with_response)


class RfcommTransport(Transport):
    def __init__(self, address: str, channel: int, timeout: float = 15.0) -> None:
        super().__init__()
        self.address = address
        self.channel = channel
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._reader: asyncio.Task | None = None

    async def connect(self) -> None:
        if not hasattr(socket, "AF_BLUETOOTH"):
            raise TransportError("RFCOMM sockets need Linux with BlueZ (Python built with Bluetooth support)")
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.settimeout(self.timeout)
        try:
            await asyncio.to_thread(sock.connect, (self.address, self.channel))
        except OSError as exc:
            sock.close()
            raise TransportError(f"RFCOMM connect to {self.address} channel {self.channel} failed: {exc}") from exc
        sock.setblocking(False)
        self._sock = sock
        self._reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._sock is not None
        while True:
            data = await loop.sock_recv(self._sock, 4096)
            if not data:
                break
            self._deliver(data)

    async def disconnect(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    async def write(self, data: bytes) -> None:
        if self._sock is None:
            raise TransportError("not connected")
        await asyncio.get_running_loop().sock_sendall(self._sock, data)


class LabTransport(Transport):
    """Talks to ``rardex.lab.LabSpeaker`` as if it were over GATT."""

    def __init__(self, speaker, write_uuid: str | None) -> None:
        super().__init__()
        self.speaker = speaker
        self.write_uuid = normalize_uuid(write_uuid) if write_uuid else None

    async def connect(self) -> None:
        self.speaker.connected = True

    async def disconnect(self) -> None:
        self.speaker.connected = False

    async def write(self, data: bytes) -> None:
        for reply in self.speaker.handle_write(self.write_uuid, data):
            self._deliver(reply)
