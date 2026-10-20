# 3. Playbook: reverse engineering your speaker

The steps below take a speaker you own from "the vendor app can do X" to "my script can do
X". Practice once on the virtual speaker first (`rardex lab brief`). It runs the same
workflow with no hardware.

## 0. Ground rules

- **Your device, your data.** The aim is interoperability with hardware you own.
- **Prefer replay over invention.** Send frames you have seen the app send, then vary
  arguments *within ranges you observed*. Don't sweep unknown command ids or out-of-range
  arguments at a device you can't afford to lose. Small speakers rarely validate input
  carefully, and an unknown command may be "factory reset" or "enter update mode".
- **Never write to firmware-update services.** `rardex snoop gatt` labels the common ones
  (`do not write`). If the app's update screen appears in a capture, leave those frames alone.
- **Keep vendor material local.** Notes and your own protocol file are yours to share.
  Decompiled vendor code and their firmware are not.

## 1. Identify the target

Record in your notebook:

- Brand, model, hardware revision, and firmware version (the app's "about" screen).
- The vendor app's name and version.
- The speaker's Bluetooth name and address (`bluetoothctl devices` or the phone's settings).
- Optional: the **FCC ID** printed on the label. The public FCC filing often includes
  internal photos showing which Bluetooth chip it uses, which hints at what to expect.

## 2. Look from the outside (no app involved)

On a Linux machine with Bluetooth (or macOS/Windows for BLE):

```sh
pip install -e '.[ble]'          # adds bleak for live BLE access
rardex scan --name <part-of-name>
rardex gatt AA:BB:CC:DD:EE:FF --read
```

`gatt --read` shows every service. It also reads the standard Device Information strings
(model, firmware revision), which are harmless reads. Look for vendor 128-bit services and
characteristics with `write-no-rsp`/`write` and `notify`. Those are your candidates.

If BLE shows nothing interesting, the control channel is probably classic SPP:

```sh
bluetoothctl info AA:BB:CC:DD:EE:FF     # look for 00001101-... (Serial Port) in UUIDs
sdptool browse AA:BB:CC:DD:EE:FF        # look for "RFCOMM" "Channel: N"
```

## 3. Plan the capture like an experiment

Write the script *before* recording. The aim is captures where each action is easy to find
and one variable changes at a time:

1. Start logging **before** opening the app (so connection setup and discovery are included).
2. Open the app, wait 5 s, and do nothing else. This is the startup/handshake sequence.
3. One action at a time, with **3+ seconds** between actions. Write down the order.
4. Toggle each switch both ways. Pick each preset once, then once more in a different order.
5. Move sliders slowly to both ends: you want to capture the minimum and the maximum.
6. For colors, pick pure red, green, blue, white, then off.
7. Close the app and stop logging.

## 4. Capture on Android (HCI snoop log)

1. Enable Developer options: *Settings → About phone →* tap *Build number* seven times.
2. *Developer options → Enable Bluetooth HCI snoop log*. If the options are
   *Disabled / Enabled filtered / Enabled*, choose **Enabled**. "Filtered" can drop or
   truncate the payloads you need.
3. Turn Bluetooth **off and on** so logging starts. To capture GATT discovery, also *forget*
   the speaker and pair again.
4. Run your script from step 3.
5. Pull the log with a bug report: `adb bugreport bugreport.zip`, then extract the zip and
   look for `btsnoop_hci.log` (often `FS/data/misc/bluetooth/logs/`; the exact path varies
   by vendor and Android version).
6. Turn snoop logging off again when you're done.

What else in the bug report is useful (and what isn't):

- **Useful:** the main `bugreport-*.txt` section `DUMP OF SERVICE bluetooth_manager`. This
  is Android's own view of each device: bonded devices, profile states, the A2DP codec
  configuration and the codecs it could select, AVRCP absolute-volume state, and the battery
  level the phone last received. It's a good cross-check for `rardex snoop features`.
  Extract it with
  `unzip -p bugreport.zip 'bugreport-*.txt' | sed -n '/DUMP OF SERVICE bluetooth_manager/,/^DUMP OF SERVICE /p' > bt-dumpsys.txt`.
  It names *every* paired device (and what you were playing), so review it before sharing.
  Fields that pay off:
  - `remote_info:LMP-SUBVERSION-MANUFACTURER` (decimal) in `shim::record`: the device chip's
    Bluetooth version and SIG company id;
  - `BTAudio Media Key Events`: `key=` is the AVRCP operation id in decimal (68 play,
    70 pause, 75 next, 76 previous);
  - `AvrcpVolumeManager`: whether absolute volume is on (`AbsVol`) and every volume change;
  - `A2DP <codec> State` and `A2dpOffloadEnabled`: the codec config, and whether audio
    bypasses the snoop log;
  - `Link Key Types` / `SecureConn`: how the device paired.

  To line it up with a capture, find one event in both (a media key press is ideal) and
  compute the clock offset. On the phone used in chapter 5 the offset was zero; check it
  before relying on that.
- **Rarely useful:** per-HAL debug files such as `...IBluetoothHci_default.txt`. These are
  vendor driver dumps and are often empty, or only say that a dump directory doesn't exist.
  An empty dump means "not collected", not "nothing happened".

Alternatives:

- **Linux host:** `sudo btmon -w capture.btsnoop` records the BlueZ stack, for example
  while you test your own tool. rardex reads this format too.
- **iOS:** Apple supports Bluetooth logging through a logging profile plus a sysdiagnose,
  which produces a PacketLogger (`.pklg`) file. rardex doesn't read `.pklg`; open it in
  Wireshark or PacketLogger instead.
- **Cross-check with Wireshark/TShark** whenever something looks off:
  `tshark -r btsnoop_hci.log -Y btatt -T fields -e frame.number -e btatt.opcode -e btatt.handle -e btatt.value`

## 5. Decode

```sh
sha256sum btsnoop_hci.log                    # record it in the notebook
rardex snoop info btsnoop_hci.log            # devices, protocols, busiest data channels
rardex snoop gatt btsnoop_hci.log            # BLE: which UUID is behind each handle
rardex snoop timeline btsnoop_hci.log --gap 2
```

`info` lists "app data channels" by activity. Usually one channel carries nearly all the
writes. That one is the control channel. Match the timeline's pauses to your script:
burst 1 is startup, burst 2 is the first action, and so on.

## 6. Infer the structure

```sh
rardex snoop export btsnoop_hci.log --handle 0x0012 --direction tx -o tx.txt   # BLE
rardex snoop export btsnoop_hci.log --channel 1 --direction tx -o tx.txt       # RFCOMM
rardex analyze tx.txt
```

`analyze` reports, each with its evidence:

- **common prefix**: sync bytes.
- **length field**: needs commands of different lengths to be identifiable.
- **checksum**: candidates plus the expected number of chance matches.
- **command id**: the first varying byte with few distinct values; frames are grouped by it.
- **per-group masks** (`a5 5a 02 02 ?? ??`): the `??` are arguments.
- **sliders**: arguments that moved in equal steps, like a dragged volume slider.

Then confirm with targeted comparisons:

```sh
rardex diff "a5 5a 02 03 01 fa" "a5 5a 02 03 02 f9"     # only the setting you changed should move
rardex checksum <frame> <frame> <frame> ...             # with frames from different commands
```

Write each finding in the notebook as seen/derived/inferred/unknown. For each inference,
plan a capture that would contradict it if it were wrong, then run that capture.

Do the same for the `rx` direction to learn the speaker's replies (acks, status).

## 7. Write the protocol file and prove it

```sh
cp protocols/template.toml protocols/<brand>-<model>.toml
# edit device / framing / commands / responses

rardex proto show   protocols/<x>.toml
rardex proto build  protocols/<x>.toml volume level=9 --compare "<frame from the capture>"
rardex proto verify protocols/<x>.toml tx.txt         # aim for N/N identified
rardex snoop timeline btsnoop_hci.log --protocol protocols/<x>.toml   # the capture, named
```

## 8. Talk to the speaker

Start with an exact replay of a harmless captured frame, such as one volume step:

```sh
rardex ctl protocols/<x>.toml --address AA:BB:CC:DD:EE:FF --raw "<captured volume frame>" --listen 2
```

If the speaker reacts, switch to generated frames:

```sh
rardex ctl protocols/<x>.toml --address AA:BB:CC:DD:EE:FF volume level=12 , eq preset=bass --listen 2
```

From Python:

```python
import asyncio
from rardex.protocol import Protocol
from rardex.client import SpeakerClient, make_transport

async def main():
    proto = Protocol.load("protocols/x.toml")
    async with SpeakerClient(proto, make_transport(proto, "AA:BB:CC:DD:EE:FF")) as spk:
        await spk.send("volume", level=12)
        print(await spk.wait_for("ack"))

asyncio.run(main())
```

## Troubleshooting

| Symptom | Likely cause / next step |
|---|---|
| `snoop info` shows no ATT/RFCOMM data | Logging was in *filtered* mode, or Bluetooth wasn't restarted after enabling it |
| `snoop gatt` is empty | Android used its GATT cache: forget and re-pair while logging |
| Reads show handle `0x????` | The read request isn't in the capture (logging started mid-exchange) |
| No `RFCOMM chN`, only `CID 0x00xx` | The connection was set up before logging started: reconnect while logging |
| Replayed frame is ignored | The app first sends a startup/handshake sequence: replay that first. The device may also need notifications enabled first, or a write *with* response (`write_with_response = true`), or frames may carry a sequence number |
| `proto verify` explains some frames but not all | The unexplained ones are your next lead: different framing, a second channel, or a command you haven't modelled yet |
| Payloads look random | Application-layer encryption; see chapter 2 |
