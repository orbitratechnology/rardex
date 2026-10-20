# 5. Target: Baseus Encok D02 Pro (over-ear headphones)

This is a worked target file. It records what is established about the D02 Pro, what
isn't, and how to turn the unknowns into evidence with your own unit. Labels follow
chapter 1: **seen**, **derived**, **inferred**, **unknown**.

## What is established

| # | Claim | Label | Evidence |
|---|---|---|---|
| 1 | Bluetooth 5.0, 10 m range, 450 mAh / 3.7 V battery, 40 h music, 300 h standby, USB-C, 3.5 mm AUX | seen | Polish user manual (Magnum RF distributor), "Parametry produktu" ([PDF][manual]) |
| 2 | Retail listings disagree on the version (5.0 vs 5.3) and model code (NGD02-C01, NGD02-C02, NGTD010302) | seen | [baltrade][baltrade], [pccomponentes][pcc], [arqoob][arqoob], [e-katalog][ekatalog] |
| 3 | No companion app is mentioned in the manual | seen | [manual][manual]: covers only pairing, LEDs, buttons, multipoint and AUX |
| 4 | Pairing may ask for PIN `0000` | seen | manual, step 4 of "Przed pierwszym użyciem" |
| 5 | Multifunction button: short press = answer/end call, 2 s hold = reject, double press = redial last number, 1 s hold = voice assistant | seen | manual, "Tryb rozmowy" and "Wskazówki" |
| 6 | Volume and track buttons on the left ear cup | seen | retailer descriptions ([homescreen][homescreen]) |
| 7 | Two phones at once (multipoint), via a manual re-pair sequence | seen | manual, "Podłączenie dwóch telefonów" |
| 8 | Bluetooth chip vendor | **unknown** | no FCC ID or chip found in public listings |
| 9 | There is no proprietary control protocol | **inferred** | follows from #3, but a hidden factory/update channel could still exist: check with recon below |

[manual]: https://www.mediaexpert.pl/products/files/29/2967622/instrukcja-obslugi-BASEUS-Encok-D02-Pro.pdf
[baltrade]: https://shop.baltrade.eu/4006,Baseus_D02_Pro_Bluetooth_5_0_Headphones_with_Microphone_NGD02_C01
[pcc]: https://www.pccomponentes.fr/auriculares-baseus-encok-d02-pro-sans-fil-bluetooth-5-3-avec-cable-reduction-de-bruit-blancs
[arqoob]: https://arqoob.com/product/id/39059
[ekatalog]: https://e-katalog.pl/BASEUS-ENCOK-D02-PRO.htm
[homescreen]: https://homescreen.pl/en/over-ear-headphones/22496-baseus-encok-wireless-headphone-d02-pro-white-6953156229501.html

## What that means for "our own software"

With no app, there are no vendor bytes to decode. Everything the D02 Pro can be told or
can tell you goes through standard profiles, and those are what your software drives:

| Feature | Profile | Your software can... | Status for the D02 Pro |
|---|---|---|---|
| Music + codec | A2DP | see which codecs it offers and which was chosen | **unknown**, capture |
| Hardware volume | AVRCP absolute volume | set the headset's own volume (0-127) instead of scaling audio | **unknown**, capture or `headset info` |
| Play/pause/next/prev/vol buttons | AVRCP pass-through | see every press; remap to any command | expected (row 6); verify |
| Call buttons (answer/redial/assistant) | HFP AT commands | see them in captures; remapping needs your own HFP stack | seen in manual (row 5) |
| Battery level | HFP (Apple `XAPL`/`IPHONEACCEV` or `BIEV`) | read battery % on your computer | **unknown**, capture |
| Call volume / mic | HFP `VGS`/`VGM` | read/set | **unknown** |

## Step 1: Recon from Linux (5 minutes, read-only)

```sh
bluetoothctl info <ADDR>       # UUIDs = advertised profiles; Modalias = vendor/product ids
sdptool browse <ADDR>          # every classic service record, incl. any extra RFCOMM channels
rardex scan --name D02         # does it also advertise BLE? (needs: pip install -e '.[ble]')
rardex headset info            # profiles, battery, codec, hardware volume as BlueZ sees them
```

What to look for:

- **Modalias** (from the Device ID / PnP record, e.g. `bluetooth:vXXXXpYYYYdZZZZ`): the
  vendor id is a Bluetooth SIG company identifier. Look it up in the SIG's assigned numbers
  to identify the **chip vendor** (row 8). That is an inference about the chip, not proof.
- **Extra services**: a Serial Port (`00001101`) record, an unnamed RFCOMM channel, or a
  BLE service that isn't standard. Many cheap headsets keep a factory-test or firmware-update
  channel even without an app. Record it, but **don't send it anything**: this is exactly
  where a wrong byte can brick the headset.

## Step 2: Capture plan (Android, about 3 minutes)

Enable the HCI snoop log as described in chapter 3. Then:

1. **Forget** the D02 Pro in Bluetooth settings and turn Bluetooth off and on. This puts
   the pairing, SDP, HFP handshake and codec negotiation into the log.
2. Pair again. Wait 10 s (HFP handshake and battery report).
3. Play music for 10 s.
4. Press each ear-cup button **once**, waiting 3 s between presses and noting the order:
   volume+, volume−, next, previous, play/pause.
5. Move the **phone's** volume slider up and down slowly. If the headset supports absolute
   volume, this shows up as AVRCP `SetAbsoluteVolume`.
6. Hold the multifunction button 1 s (voice assistant), then cancel it on the phone.
7. Optional, **in airplane mode**: double-press (redial). The `AT+BLDN` is still sent, but no
   call is placed.
8. Leave it connected for a few minutes so that a later battery report is captured.
9. Pull the log (`adb bugreport`) and run:

```sh
rardex snoop info btsnoop_hci.log
rardex snoop features btsnoop_hci.log     # the audit: codecs, absolute volume, battery, buttons
rardex snoop timeline btsnoop_hci.log --gap 2
```

`snoop features` cites frame numbers for every finding. Copy them into the table above,
converting **unknown** rows to **seen**. Rehearse first on the practice headset:

```sh
rardex lab capture --headset headset.btsnoop && rardex lab brief --headset
rardex snoop features headset.btsnoop
```

## Step 3: Control it from Linux

```sh
rardex headset info                                  # battery %, codec, hardware volume support
rardex headset volume                                # read hardware volume (if supported)
rardex headset volume 40 --percent                   # set it
rardex headset inputs                                # find "<name> (AVRCP)"-style button device
rardex headset buttons                               # watch presses live
rardex headset buttons --grab \
  --map KEY_NEXTSONG="playerctl next" \
  --map KEY_PREVIOUSSONG="notify-send 'D02 Pro' 'previous pressed'"
```

Notes and limits:

- **Battery** reaches `headset info` only if the audio server (PipeWire/PulseAudio)
  handles the headset's HFP battery reports and forwards them to BlueZ. On some BlueZ
  versions that needs `Experimental = true` in `/etc/bluetooth/main.conf`. If the capture
  shows battery reports but `headset info` doesn't, this is the gap.
- **Hardware volume** exists only if the capture shows the headset advertising
  `VOLUME_CHANGED` or accepting `SetAbsoluteVolume`. Otherwise the volume buttons on the
  ear cup still work, but a computer can only scale the audio it sends.
- **Buttons**: `--grab` takes the input device exclusively, so the desktop stops reacting
  and only your mapping runs. The buttons may arrive as `KEY_PLAYCD`/`KEY_PAUSECD`
  rather than `KEY_PLAYPAUSE`. Run without `--map` first to see the actual key names.
- **Call buttons** are HFP, not input events. They go to the telephony/audio stack, so
  `headset buttons` can't see them.
- Live control was written against BlueZ's documented D-Bus API but has not yet been run
  against this headset. Expect to adjust it after your first `headset info`.
