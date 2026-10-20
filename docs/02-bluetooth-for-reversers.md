# 2. Bluetooth for reverse engineers

You only need enough of the stack to know where the vendor's bytes live and what is
already standard (and so needs no reverse engineering at all).

## Two radios, several jobs

A typical speaker chip implements both flavors of Bluetooth:

| | Classic (BR/EDR) | Low Energy (LE) |
|---|---|---|
| Audio | **A2DP** streams music | LE Audio on newer devices |
| Remote control | **AVRCP**: play/pause/next, absolute volume | - |
| Calls | **HFP** (also carries battery level to phones via AT commands) | - |
| Vendor app channel | **SPP** = a serial port over **RFCOMM** | **GATT** characteristics |

**Check what is standard before reversing anything.** Play/pause/skip and usually volume
are AVRCP, so any OS can already send them (`playerctl`, media keys, `bluetoothctl`).
Battery is often exposed through the standard Battery Service (`0x180F`) or HFP. What the
vendor app adds, and what you will be reverse engineering, is the rest: EQ presets, lights,
party/stereo pairing, auto-off timers, voice prompts, button mapping, firmware updates.

## The stack, and where the capture sits

```
 vendor app          "set EQ to bass"
 OS Bluetooth stack  GATT write / RFCOMM socket write      <- the "host"
 ───────── HCI ─────────────────────────────────────────    <- btsnoop records here
 Bluetooth chip      link layer, encryption, radio         <- the "controller"
 ~~~~~~~~~ air ~~~~~~~~~~
 speaker
```

The HCI snoop log records every packet between the phone's Bluetooth stack and its
Bluetooth chip. Link-layer encryption happens *below* that line, inside the chip, so the
log shows plaintext even when the link is encrypted. (If the vendor adds its own encryption
inside the app, the payloads will look random. See "When payloads look random" below.)

Inside the log, rardex peels these layers:

```
HCI ACL      connection handle, fragment            (rardex.hci)
L2CAP        channel id (CID), reassembled PDU       (rardex.hci)
  CID 0x0004 ............ ATT  -> GATT reads/writes/notifications   (rardex.att, rardex.gatt)
  PSM 0x0003 (dynamic) .. RFCOMM -> SPP serial bytes                (rardex.rfcomm)
  PSM 0x0019 / 0x0017 ... A2DP audio / AVRCP control (standard; skip)
```

## BLE GATT in five minutes

- A device exposes a table of **attributes**, each with a **handle** (a 16-bit number,
  specific to that device and firmware) and a **type** (a UUID, stable across devices).
- Attributes are grouped into **services**, which contain **characteristics**, which can
  have **descriptors**.
- 16-bit UUIDs like `180f` are Bluetooth SIG assigned numbers on the base UUID
  `0000xxxx-0000-1000-8000-00805f9b34fb`. Vendors usually define their own 128-bit UUIDs.
- Characteristic **properties** say what the app may do: `read`, `write`,
  `write-no-rsp`, `notify`, `indicate`.
- To receive notifications, the app writes `01 00` to the characteristic's **CCCD**
  descriptor (UUID `2902`). You will see this right after connecting.

ATT opcodes you will see in timelines:

| Opcode | rardex name | Meaning |
|---|---|---|
| `0x52` | `WRITE-NR` | Write Command: no acknowledgement (most common for control) |
| `0x12` | `WRITE` | Write Request: speaker answers `0x13` Write Response |
| `0x1B` | `NOTIFY` | Handle Value Notification: speaker -> app |
| `0x1D` | `INDICATE` | Like notify, but acknowledged |
| `0x0A`/`0x0B` | `READ-REQ`/`READ` | Read a value |
| `0x02`/`0x03` | | MTU exchange: sets the maximum PDU size |
| `0x10`/`0x08`/`0x04` | | Service discovery (rardex uses these to name handles) |

The default ATT MTU is 23 bytes, which leaves 20 bytes of payload per write. Apps that send
longer frames either negotiate a bigger MTU (look for `0x02`/`0x03` early in the capture)
or split frames themselves.

**Handles vs UUIDs:** your notes and protocol files should use UUIDs. Handles can change
between firmware versions. `rardex snoop gatt` maps one to the other from discovery traffic,
but Android caches discovery results. To get discovery into a capture, toggle Bluetooth
off/on, or unpair and re-pair, while logging is enabled.

## Classic SPP / RFCOMM in five minutes

- **SDP** (Service Discovery Protocol) lists a device's classic services. Serial Port
  Profile is UUID `00001101-0000-1000-8000-00805f9b34fb`. Its record contains an RFCOMM
  **server channel** number (1-30).
- RFCOMM is a byte *stream*, like TCP: there are no message boundaries. Vendors therefore
  frame their messages, typically as sync bytes + length. rardex's `FrameReassembler` uses
  your protocol file's prefix and length field to split the stream again.
- In a capture the channel shows up as `RFCOMM chN`. rardex learns it from the L2CAP
  connection setup, so **start logging before the app connects**.

## Common vendor frame shapes

Small-device protocols are usually some subset of:

```
[sync/prefix] [length] [sequence] [command id] [arguments...] [checksum/CRC] [end marker]
```

- **Prefix** constant bytes such as `aa 55`, `a5 5a`, `7e`, `ff`, or an ASCII tag.
- **Length** of the payload (or of the whole frame), 1-2 bytes, sometimes ± a constant.
- **Sequence numbers** increment per message. If present, replaying an old frame verbatim
  may be ignored: you must generate frames with fresh numbers.
- **Command id**: a byte with few distinct values that groups frames by action.
- **Arguments**: little-endian is most common for multi-byte numbers; booleans as 00/01;
  colors as R G B.
- **Integrity**: sum/XOR/CRC-8/CRC-16 over some range. `rardex checksum` brute-forces the
  common ones.

## When payloads look random

If frames on the vendor channel show no constant prefix, no repeating structure, and every
byte varies even between identical actions, the app probably encrypts or obfuscates at the
application layer. Captures alone won't get you further. Understanding how the app builds
those frames is a static-analysis job on the app (see the primer), and the payoff and effort
change considerably. Note it in your notebook as "payload encoding: unknown, high entropy".
