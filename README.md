# rardex

**Reverse engineer your Bluetooth speaker or headphones, then control them with your own software.**

The vendor app can set the EQ, change the lights or set an auto-off timer, and your laptop
can't. Or, as with app-less headphones like the Baseus Encok D02 Pro, everything goes through
standard profiles, and the question is which of them the device actually implements. rardex
helps with both, on hardware you own:

1. **Decode** the phone's Bluetooth HCI snoop log (btsnoop): HCI → L2CAP → ATT/GATT and
   RFCOMM/SPP, including fragment reassembly and GATT handle → UUID mapping.
2. **Infer** the frame format from samples: sync prefix, length field, checksum
   (brute-forced against 12 common algorithms, with odds of a chance match), command ids,
   argument bytes and slider-like controls.
3. **Describe** the protocol in a small TOML file, then prove it: rebuild captured frames
   byte for byte and check that it identifies every frame in a capture.
4. **Control** the speaker over BLE (via `bleak`) or classic RFCOMM, from the CLI or Python.
5. **Audit headsets**: decode SDP service records (including the Device ID vendor), HFP AT
   commands (battery, call buttons, call volume, vendor-specific commands), AVRCP (buttons,
   absolute volume levels) and A2DP codec negotiation. `snoop features` produces a report
   citing frame numbers. On Linux, `rardex headset` reads battery and codec, sets hardware
   volume through BlueZ, and remaps headset buttons to your own commands.

Pure Python 3.11+, no required dependencies. A built-in **practice speaker** lets you run
the whole workflow without hardware.

## Learn

The `docs/` folder is a short course. It distills the method of two reverse engineering
projects, [REA](https://github.com/morluto/rea) and
[leanrea](https://github.com/aicodeking/leanrea), and applies it to Bluetooth devices.

1. [Reverse engineering primer](docs/01-reverse-engineering-primer.md): evidence
   discipline (seen / derived / inferred / unknown), cheapest-inventory-first, diff before
   decode, and proving a rebuild against the original.
2. [Bluetooth for reverse engineers](docs/02-bluetooth-for-reversers.md): what's standard
   (A2DP/AVRCP), where vendor bytes live (GATT or SPP), and common frame shapes.
3. [Speaker playbook](docs/03-speaker-playbook.md): capture plan, Android HCI snoop
   logging, decode → infer → verify → control, and troubleshooting.
4. [Protocol notebook template](docs/04-protocol-notebook.md): where findings and their
   evidence go.
5. [Target: Baseus Encok D02 Pro](docs/05-baseus-encok-d02-pro.md): a worked dossier for
   an app-less headset, covering what's established, what's unknown, a capture plan, and Linux control.

## Baseus Encok D02 Pro quick start

```sh
rardex lab capture --headset h.btsnoop && rardex snoop features h.btsnoop   # rehearse (no hardware)
# then, with the real headset: capture per docs/05, and
rardex snoop features btsnoop_hci.log     # codecs, absolute volume, battery, button evidence
rardex headset info                        # Linux: profiles, battery, codec, hardware volume
rardex headset buttons --map KEY_NEXTSONG="playerctl next"
```

## Try it in two minutes (no hardware)

```sh
pip install -e .                      # or: export PYTHONPATH=src and use python -m rardex
rardex lab capture lab.btsnoop        # practice capture: app <-> fictional RX-1 speaker
rardex lab brief                      # the exercise
rardex snoop info lab.btsnoop
rardex snoop gatt lab.btsnoop
rardex snoop export lab.btsnoop --handle 0x0012 -o tx.txt
rardex analyze tx.txt
```

`analyze` on the practice capture:

```text
common prefix: a5 5a   <- likely a sync/header marker
length field:
  candidate: u8 at offset 2 = frame length -4
checksum:
  candidate: sum8_neg over frame[2:-1]
  candidate: sum8_not over frame[0:-1]
  (60 combinations tried on 22 distinct frames; expected chance matches ~2.5e-52)
command id (inferred): byte at offset 3; frames grouped by it:
  [0x02] x12  a5 5a 02 02 ?? ??
         offset  4: 09 0a 0b 0c 0d 0e 0f 10
         slider? offset 4 moves in steps of 1 within 9..16 (like a volume/brightness control)
  ...
```

Then write `rx1.toml` from [`protocols/template.toml`](protocols/template.toml) and drive
the virtual speaker:

```sh
rardex proto verify rx1.toml tx.txt                  # "27/27 frames identified"
rardex ctl rx1.toml --lab volume level=20 , eq preset=party , status
```

(A worked solution is in `tests/fixtures/lab_solution.toml`. Try the exercise first.)

## Use it on your speaker

```sh
pip install -e '.[ble]'
rardex scan --name JBL                               # find it
rardex gatt AA:BB:CC:DD:EE:FF --read                 # its live GATT table
# capture with Android's HCI snoop log while using the vendor app (see the playbook)
rardex snoop info btsnoop_hci.log
rardex snoop timeline btsnoop_hci.log --gap 2
rardex snoop export btsnoop_hci.log --handle 0x0012 --direction tx -o tx.txt
rardex analyze tx.txt
rardex proto build protocols/mine.toml volume level=9 --compare "<captured frame>"
rardex ctl protocols/mine.toml --address AA:BB:CC:DD:EE:FF volume level=12 --listen 2
```

## Commands

| Command | Purpose |
|---|---|
| `snoop info FILE` | Connections (incl. failed), device name/class/chip version, ACL handles, protocols, busiest channels |
| `snoop gatt FILE` | GATT table rebuilt from discovery; marks where the app writes / device notifies |
| `snoop timeline FILE` | App data in time order, split at pauses; `--protocol` names known frames |
| `snoop features FILE` | Headset audit: profiles, A2DP codecs, absolute volume, battery, buttons (cites frames) |
| `snoop export FILE` | One hex frame per line (`--handle`, `--channel`, `--direction tx/rx`) |
| `analyze [FILES]` | Prefix, length field, checksum, command ids, per-command masks, sliders |
| `checksum HEX...` | Which algorithm/range explains these frames, with false-match odds |
| `diff A B` | Byte-level diff of two frames |
| `proto show/build/verify` | Inspect a protocol file, build frames (`--compare`), check coverage |
| `scan`, `gatt ADDR` | Live BLE discovery and GATT enumeration (needs `rardex[ble]`) |
| `ctl PROTO CMD k=v [, CMD ...]` | Send commands (`--address`, `--raw HEX`, `--listen`, `--lab`) |
| `headset info/volume/inputs/buttons` | Linux/BlueZ: battery, codec, hardware volume, button remapping |
| `lab capture/brief [--headset]` | Practice capture and exercise (BLE speaker, or classic headset) |

Input formats: btsnoop H4 (Android), H1, and Linux `btmon -w` monitor captures.

## Layout

```
src/rardex/
  btsnoop.py   btsnoop reader/writer          hci.py      HCI events, ACL/L2CAP reassembly
  att.py       ATT PDUs and UUIDs             gatt.py     GATT table from discovery traffic
  rfcomm.py    RFCOMM frames (SPP)            session.py  all layers -> app-data messages
  hfp.py       HFP/HSP AT commands            avrcp.py    AVRCP buttons, absolute volume
  avdtp.py     A2DP codec negotiation         features.py headset feature audit
  sdp.py       service records, Device ID (vendor), reassembly
  assigned.py  verified SIG company ids, Bluetooth versions, Class of Device
  checksum.py  checksum zoo + detector        analyze.py  frame-structure inference
  protocol.py  TOML protocol files            client.py   SpeakerClient, stream reassembly
  transport.py BLE / RFCOMM / lab transports  bluez.py    Linux headset control (D-Bus, evdev)
  lab.py       practice speaker/headset       cli.py      the rardex command
protocols/template.toml   start here for your speaker
docs/                     the course
tests/                    python -m unittest discover -s tests
```

## Responsible use

Use this with devices you own, to make them work with your software. Prefer replaying
observed frames over guessing new ones, and don't write to firmware-update services
(`snoop gatt` labels common ones). Keep captures private: HCI logs can contain addresses
and traffic from every Bluetooth device the phone talked to, so `.gitignore` excludes them.

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests
```

The tests cover each decoding layer (with reference values such as the RFCOMM FCS and
standard CRC check values), the full lab workflows from capture to control, and the BlueZ
and evdev code against simulated `busctl` output and input events. They don't exercise live
BLE, RFCOMM or BlueZ, because those need real hardware.

## License

MIT
