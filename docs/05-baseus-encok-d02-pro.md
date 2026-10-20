# 5. Target: Baseus Encok D02 Pro (over-ear headphones)

This is a worked target file. It records what is established about the D02 Pro, how it was
established, and what is still open. Labels follow chapter 1: **seen**, **derived**,
**inferred**, **unknown**. Captures are referred to by letter; they stay private.

| Capture | Recorded | SHA-256 (prefix) | What happened |
|---|---|---|---|
| A | 00:56, 485 s | `ecad15cb…` | 5 failed connection attempts, then one session (pairing handshake, codec setup) |
| B | 01:06, 135 s | `335da6f2…` | 4 failed attempts (`0x04 page timeout`), no session: headset switched off to charge (confirmed by owner) |
| C | 01:08, 356 s | `e1470bf6…` | session, link lost (`0x08 connection timeout`), reconnect; buttons and volume used |

All three are Android HCI snoop logs (btsnoop H4) and include about 2,900 ACL packets on
handle `0x0edc` that are not the headset (see "Decoder lessons" below).

## Summary

The D02 Pro is a **JieLi-based** headset that speaks only standard profiles: A2DP 1.3
(SBC + AAC), AVRCP 1.5 with **hardware (absolute) volume in 17 steps**, and Hands-Free 1.8
with **Apple-style battery reporting in 10% steps**. It advertises **no serial-port or
vendor service**, so there is no hidden classic control channel to reverse. Your own
software controls it through those standard profiles, and on Linux `rardex headset` does that.

## Findings

| # | Claim | Label | Evidence |
|---|---|---|---|
| 1 | No companion app; manual covers pairing, LEDs, buttons, multipoint, AUX only | seen | [user manual][manual] |
| 2 | Firmware declares **vendor 0x05D6 = Zhuhai Jieli Technology Co., Ltd**, product 0x000A, version 0x0240 | seen | SDP Device ID record, C frames 663, 3528 (`snoop features`); company id checked against the [Bluetooth SIG list][sig] |
| 3 | SDK service names `JL_A2DP` and `JL_HFP` | seen | SDP, C frame 744 |
| 4 | The Bluetooth chip/SDK is JieLi | inferred | #2 + #3 (declared ids and SDK naming; not a die photo) |
| 5 | Exactly four classic services: A2DP Sink 1.3, AVRCP 1.5 Controller, AVRCP 1.5 Target, Hands-Free 1.8 (RFCOMM ch 4) | seen | full SDP browse, C frame 744 |
| 6 | No Serial Port / vendor service is advertised over classic Bluetooth | seen | #5 lists every record with an L2CAP protocol; none is SPP or vendor |
| 7 | No BLE advertising from the headset observed | unknown (not observed) | 0 matches in 599 LE advertising reports across A-C; scans are partial |
| 8 | A2DP codecs: SBC (all rates/modes, **max bitpool 38**) and AAC; phone chose **AAC** | seen | AVDTP, C frames 384, 397, 345, 3366 |
| 9 | Hardware volume (AVRCP absolute volume) is supported | seen | headset ACCEPTED SetAbsoluteVolume, C frames 569, 1579, 1593, 1609, 3606 |
| 10 | Headset volume buttons change the **headset's own volume** in steps of 8 on a 0-127 scale: **17 levels** (0, 8 … 120, 127) | seen / derived | 72 VOLUME_CHANGED notifications from the headset, C; step sizes 8×66, 7×2 |
| 11 | Volume buttons do **not** send key presses (no AVRCP volume up/down pass-through) | seen in C | 0 volume pass-through commands vs 72 VOLUME_CHANGED |
| 12 | Track/playback buttons send AVRCP pass-through **play, pause, next, previous** (play and pause are separate commands, not one toggle) | seen | C: play ×4, pause ×4, next ×8, previous ×5 |
| 13 | The headset subscribes to the phone's PLAYBACK_STATUS_CHANGED, presumably to choose play vs pause | seen / inferred | C, 24 RegisterNotification commands from the headset |
| 14 | Next/previous are **long presses of the volume buttons** | seen | confirmed by the owner; in C, 11 of 13 skips have no volume change in the 2 s before them, so a long press sends only the skip |
| 14a | Long volume− = previous, long volume+ = next | inferred (weak) | the volume was stepping *down* just before the first two "previous" presses (C, 99.6 s → 100.9 s, 105.0 s → 106.4 s) |
| 15 | HFP features: EC/NR, 3-way, caller ID, voice recognition, remote volume, codec negotiation (CVSD + mSBC wideband), eSCO S4; **no HF indicators** | seen | `AT+BRSF=671`, `AT+BAC=1,2`; SDP features 0x003f; A frame 3666, C frame 354 |
| 16 | The headset does its own echo cancelling / noise reduction | inferred | `AT+NREC=0` (asks the phone to turn off its own); BRSF EC/NR bit |
| 17 | Battery is reported only via Apple's `AT+IPHONEACCEV` (0-9, ~10% steps), each report sent twice | seen | A frame 3737/3738; C frames 488/489, 1017, 3572/3575 |
| 18 | `AT+XAPL=ABCD-1234-0100,10` uses placeholder vendor/product ids | inferred | literal `ABCD-1234`; real ids come from #2 |
| 19 | The headset asks the phone's manufacturer (`AT+CGMI?`) on every connection | seen | A frame 3710, C frames 447, 3526 |
| 20 | Vendor command `AT+VDSF=1`, rejected by the phone (`+CME ERROR: 0`) | seen; meaning **unknown** | A frame 3745, C frames 500, 3589; no public documentation found |
| 21 | Call volume reported as speaker 12/15, mic 15/15 | seen | `AT+VGS=12`, `AT+VGM=15` |
| 22 | Every button event is sent as a complete click: press and release only 14-93 ms apart, even for long presses | seen | C, all 21 presses (`snoop features`: press->release timing) |
| 23 | The headset recognizes the gesture (short vs long press) itself and sends the result | inferred | #22: a held button cannot produce a 14 ms press on the wire |
| 24 | Battery went from 0/9 to 7/9 between A and C because it was charged while switched off | seen | owner confirmed; B's page timeouts match the headset being off |

[manual]: https://www.mediaexpert.pl/products/files/29/2967622/instrukcja-obslugi-BASEUS-Encok-D02-Pro.pdf
[sig]: https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml

### Open questions

- **Battery accuracy**: after charging (#24) it read 7/9, then 6/9 after 26 s and 5/9 after
  about 3.5 min, too fast for a 450 mAh pack at listening load. That suggests a voltage-based
  estimate that sags after charging (inferred). A long listening session would show the real
  discharge curve; treat early readings after a charge as optimistic.
- **Which volume button skips which way** (#14a): one long press of volume+ with a pause, then
  volume−, in a capture or under `rardex headset buttons`, settles it.
- **`AT+VDSF=1`**: what does the JieLi firmware expect? It is likely meant for a particular
  phone brand (see #19). It is harmless to ignore, and nothing should be sent back to it blindly.
- **BLE** (#7): run `rardex scan` near the headset to settle it.

## What this means for your own software

| Feature | Works? | How |
|---|---|---|
| Hardware volume | yes (#9, #10) | `rardex headset volume 64`; prefer multiples of 8, the headset's own steps |
| Battery level | yes, 10% steps (#17) | `rardex headset info`, if the audio server forwards Apple battery reports to BlueZ |
| Play/pause/next/previous buttons | yes (#12) | `rardex headset buttons --map ...` (BlueZ turns them into key events) |
| Long-press volume (next/previous) as custom actions | yes, cleanly (#14, #22) | they arrive as next/previous keys with no stray volume step first |
| Short-press volume as custom actions | no (#11) | they change the headset volume itself; Linux sees a transport `Volume` change, not a key |
| Custom gestures (double/triple press, hold durations) | no (#23) | the headset decides the gesture; software only sees the result |
| Call buttons | partly | HFP AT commands to the phone/audio stack; not visible to `headset buttons` |
| Audio quality | AAC if available (#8) | on Linux, AAC needs an AAC-capable audio server build; otherwise SBC at bitpool ≤ 38 |
| EQ / ANC / settings | no evidence of any | no vendor channel (#6); nothing to control beyond the above |

## Control it from Linux

```sh
rardex headset info                                  # battery %, codec, hardware volume
rardex headset volume 64                             # 0..127; the headset steps by 8
rardex headset volume 50 --percent
rardex headset inputs                                # find its AVRCP input device
rardex headset buttons                               # watch presses live
rardex headset buttons --grab \
  --map KEY_NEXTSONG="playerctl next" \
  --map KEY_PREVIOUSSONG="playerctl previous" \
  --map KEY_PLAYCD="playerctl play" --map KEY_PAUSECD="playerctl pause"
```

- BlueZ usually maps AVRCP play/pause to `KEY_PLAYCD`/`KEY_PAUSECD`, not `KEY_PLAYPAUSE`.
  Run without `--map` first and use the names it prints.
- Battery reaches `headset info` only if the audio server (PipeWire/PulseAudio) handles
  Apple's `AT+XAPL`/`AT+IPHONEACCEV` and forwards the level to BlueZ. On some BlueZ
  versions that needs `Experimental = true` in `/etc/bluetooth/main.conf`.
- The live control code was written against BlueZ's documented D-Bus API and tested against
  simulated output, not yet against this headset.

## Reproduce the analysis

```sh
rardex snoop info     capture.log    # connections, failed attempts, ACL handles
rardex snoop features capture.log    # everything in the findings table, with frame numbers
rardex snoop timeline capture.log --gap 2
```

## Decoder lessons from these captures

Real captures exposed three things that the synthetic tests had not:

1. **Controller diagnostics on ACL handle 0x0EDC.** About half of every capture was ACL
   traffic on a handle that no connection event ever opened, flowing only controller → host,
   with payloads that match no protocol. Decoding it as L2CAP produced hundreds of fake
   "channels". rardex now counts it separately (`snoop info` → `acl handles`).
2. **Failed connections hide in plain sight.** Capture B looked empty. In fact it held four
   `Connection Complete` events with status `0x04 page timeout`. rardex used to ignore failed
   events; `snoop info` now lists them. This is the primer's rule in action: no data is
   **unknown**, not "nothing happened".
3. **Devices repeat themselves.** The headset sends each battery report twice, and phones ask
   for the same SDP record several times with different attributes. The audit now collapses
   identical repeats and merges partial SDP answers, so counts reflect behavior rather than
   retransmissions.
