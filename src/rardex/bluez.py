"""Control a connected headset through Linux's Bluetooth stack (BlueZ) - no vendor app needed.

A headset like the Baseus Encok D02 Pro exposes only standard profiles, and BlueZ already
speaks them. This module reads and drives what BlueZ exposes on D-Bus (via ``busctl``,
so there is no Python dependency):

* ``org.bluez.Device1``         name, connection state, advertised profile UUIDs
* ``org.bluez.Battery1``        battery %, when the headset reports it (HFP) and the audio
                                server forwards it to BlueZ
* ``org.bluez.MediaTransport1`` the A2DP stream: codec, state and, when the headset supports
                                AVRCP absolute volume, a ``Volume`` property (0..127)

Headset buttons arrive in two ways. AVRCP buttons (play/pause/next/volume) become key events
on a Linux input device that BlueZ creates; ``ButtonReader`` reads those. Call buttons
(answer/redial/voice assistant) are HFP AT commands that the audio server or telephony stack
handles, and they don't appear here.
"""

from __future__ import annotations

import fcntl
import json
import os
import shlex
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

Runner = Callable[[list[str]], str]

PROFILE_UUIDS = {
    "0000110a": "A2DP Source",
    "0000110b": "A2DP Sink (plays audio)",
    "0000110c": "AVRCP Target",
    "0000110e": "AVRCP Controller (buttons)",
    "0000110f": "AVRCP Controller",
    "00001108": "Headset (HSP)",
    "00001131": "Headset HS (HSP)",
    "0000111e": "Hands-Free (HFP)",
    "0000111f": "Hands-Free Audio Gateway",
    "00001101": "Serial Port (SPP) - possible vendor channel",
    "00001200": "PnP Information (vendor/product ids)",
    "00001800": "Generic Access (BLE)",
    "00001801": "Generic Attribute (BLE)",
    "0000180f": "Battery Service (BLE)",
    "0000180a": "Device Information (BLE)",
}
A2DP_CODECS = {0x00: "SBC", 0x01: "MPEG-1,2", 0x02: "AAC", 0xFF: "vendor (aptX/LDAC/...)"}


class BluezError(RuntimeError):
    pass


def busctl(args: list[str]) -> str:
    try:
        done = subprocess.run(["busctl", "--system", *args], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        raise BluezError("busctl not found: this needs Linux with systemd and BlueZ") from None
    if done.returncode != 0:
        err = done.stderr.strip()
        if "Failed to connect to bus" in err:
            raise BluezError("cannot reach the system D-Bus: this needs a Linux machine with BlueZ (bluetoothd) running")
        if "org.bluez was not provided" in err or "ServiceUnknown" in err:
            raise BluezError("BlueZ is not running: start it with `sudo systemctl start bluetooth`")
        raise BluezError(err or f"busctl {' '.join(args)} failed")
    return done.stdout


def unwrap(value: Any) -> Any:
    """busctl --json encodes variants as {"type": sig, "data": value}; strip that recursively."""
    if isinstance(value, dict):
        if set(value) == {"type", "data"} and isinstance(value["type"], str):
            return unwrap(value["data"])
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
    return value


def profile_name(uuid: str) -> str:
    return PROFILE_UUIDS.get(uuid.lower()[:8], uuid)


@dataclass
class Headset:
    path: str
    address: str
    name: str
    connected: bool
    uuids: list[str]
    battery: int | None = None
    transports: list[dict[str, Any]] = field(default_factory=list)  # MediaTransport1 props + "path"

    @property
    def profiles(self) -> list[str]:
        return [profile_name(u) for u in self.uuids]

    @property
    def volume_transport(self) -> dict[str, Any] | None:
        return next((t for t in self.transports if "Volume" in t), None)


class Bluez:
    def __init__(self, run: Runner = busctl) -> None:
        self.run = run

    def objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        out = self.run(["--json=short", "call", "org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects"])
        data = unwrap(json.loads(out))
        return data[0] if isinstance(data, list) else data

    def devices(self) -> list[Headset]:
        objs = self.objects()
        found = []
        for path, ifaces in objs.items():
            dev = ifaces.get("org.bluez.Device1")
            if dev is None:
                continue
            h = Headset(
                path,
                dev.get("Address", "?"),
                dev.get("Alias") or dev.get("Name") or "",
                bool(dev.get("Connected")),
                list(dev.get("UUIDs", [])),
                ifaces.get("org.bluez.Battery1", {}).get("Percentage"),
            )
            for tpath, tifaces in objs.items():
                t = tifaces.get("org.bluez.MediaTransport1")
                if t is not None and tpath.startswith(path + "/"):
                    h.transports.append({"path": tpath, **t})
            found.append(h)
        return found

    def find(self, query: str | None) -> Headset:
        """Match by address or name substring; with no query, the single connected device."""
        devs = self.devices()
        if query:
            q = query.lower()
            matches = [d for d in devs if d.address.lower() == q or q in d.name.lower()]
        else:
            matches = [d for d in devs if d.connected]
        if len(matches) != 1:
            names = ", ".join(f"{d.name} [{d.address}]" for d in (matches or devs)) or "none"
            raise BluezError(f"need exactly one matching device, found {len(matches)}: {names}")
        return matches[0]

    def set_volume(self, headset: Headset, level: int) -> None:
        t = headset.volume_transport
        if t is None:
            raise BluezError(
                "no hardware volume: the A2DP transport has no Volume property. The headset did not "
                "advertise AVRCP absolute volume (or audio isn't streaming), so use the system volume instead."
            )
        if not 0 <= level <= 127:
            raise BluezError("volume must be 0..127")
        self.run(["set-property", "org.bluez", t["path"], "org.bluez.MediaTransport1", "Volume", "q", str(level)])


# -- buttons: Linux input events ----------------------------------------------------------

EV_KEY = 1
EVIOCGRAB = 0x40044590  # _IOW('E', 0x90, int)
INPUT_EVENT = struct.Struct("llHHi")  # struct input_event on 64-bit Linux
KEYS = {
    113: "KEY_MUTE",
    114: "KEY_VOLUMEDOWN",
    115: "KEY_VOLUMEUP",
    163: "KEY_NEXTSONG",
    164: "KEY_PLAYPAUSE",
    165: "KEY_PREVIOUSSONG",
    166: "KEY_STOPCD",
    168: "KEY_REWIND",
    200: "KEY_PLAYCD",
    201: "KEY_PAUSECD",
    208: "KEY_FASTFORWARD",
}
VALUES = {0: "release", 1: "press", 2: "repeat"}


def input_devices(root: Path = Path("/sys/class/input")) -> list[tuple[str, str]]:
    """(/dev/input/eventN, device name) for every event device."""
    out = []
    for ev in sorted(root.glob("event*"), key=lambda p: int(p.name[5:] or 0)):
        try:
            name = (ev / "device" / "name").read_text().strip()
        except OSError:
            continue
        out.append((f"/dev/input/{ev.name}", name))
    return out


def find_input_device(name: str, root: Path = Path("/sys/class/input")) -> str:
    """BlueZ names the AVRCP input device after the headset; match on that."""
    devs = input_devices(root)
    matches = [path for path, n in devs if name.lower() in n.lower()]
    if len(matches) != 1:
        listing = "\n  ".join(f"{p}  {n}" for p, n in devs) or "(none readable)"
        raise BluezError(
            f"{len(matches)} input devices match {name!r}; press a headset button once so BlueZ "
            f"creates it, or pass --device. Available:\n  {listing}"
        )
    return matches[0]


@dataclass(frozen=True)
class KeyEvent:
    code: int
    value: int  # 0 release, 1 press, 2 repeat

    @property
    def key(self) -> str:
        return KEYS.get(self.code, f"KEY_{self.code}")

    @property
    def action(self) -> str:
        return VALUES.get(self.value, str(self.value))


def read_key_events(stream) -> Iterator[KeyEvent]:
    """Yield key events from an evdev stream (a /dev/input/eventN file object)."""
    while True:
        chunk = stream.read(INPUT_EVENT.size)
        if len(chunk) < INPUT_EVENT.size:
            return
        _sec, _usec, etype, code, value = INPUT_EVENT.unpack(chunk)
        if etype == EV_KEY:
            yield KeyEvent(code, value)


class ButtonMapper:
    """Run a command per key press, e.g. {"KEY_NEXTSONG": "notify-send next"}."""

    def __init__(self, mapping: dict[str, str], spawn: Callable[[list[str]], Any] = subprocess.Popen) -> None:
        self.mapping = {k.upper(): v for k, v in mapping.items()}
        self.spawn = spawn

    def handle(self, event: KeyEvent) -> str | None:
        if event.value != 1:
            return None
        cmd = self.mapping.get(event.key)
        if cmd:
            self.spawn(shlex.split(cmd))
        return cmd


def grab(fd: int) -> None:
    """Take the device exclusively so the desktop doesn't also act on remapped buttons."""
    fcntl.ioctl(fd, EVIOCGRAB, 1)


def open_input(path: str):
    if not os.access(path, os.R_OK):
        raise BluezError(f"cannot read {path}: run with sudo or add yourself to the 'input' group")
    return open(path, "rb", buffering=0)
