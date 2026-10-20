# 5. Target: Baseus Encok D02 Pro (over-ear headphones)

This is a worked target file. It records what is established about the D02 Pro, how it was
established, and what is still open. Labels follow chapter 1: **seen**, **derived**,
**inferred**, **unknown**. Sources are referred to by letter; they stay private.

| Source | Recorded | SHA-256 (prefix) | What it is |
|---|---|---|---|
| A | 00:56, 485 s | `ecad15cb…` | HCI snoop log: 5 failed connection attempts, then one session |
| B | 01:06, 135 s | `335da6f2…` | HCI snoop log: 4 failed attempts (`0x04 page timeout`); headset was off for charging (confirmed by owner) |
| C | 01:08, 356 s | `e1470bf6…` | HCI snoop log: session, link lost (`0x08 connection timeout`), reconnect; buttons and volume used |
| D | 01:13:29 | (text) | Android `dumpsys bluetooth_manager` from the same bug report as C, so it overlaps C in time |

A-C are Android HCI snoop logs (btsnoop H4) from a Qualcomm-based phone. They include about
2,900 ACL packets on handle `0x0edc` that are not the headset (see "Decoder lessons").

## Summary

The D02 Pro runs a **JieLi Bluetooth 5.3 chip**: both its radio and its firmware report vendor
0x05D6, independently. It speaks only standard profiles: A2DP 1.3 (SBC + AAC), AVRCP 1.5
with **hardware (absolute) volume in 17 steps**, and Hands-Free 1.8 with **Apple-style battery
reporting in 10% steps**. It advertises **no serial-port or vendor service**, so there is no
hidden classic control channel to reverse. Your own software controls it through those
standard profiles, and on Linux `rardex headset` does that. Android's own records (D) agree
with every capture finding they overlap.

## Findings

| # | Claim | Label | Evidence |
|---|---|---|---|
| 1 | No companion app; manual covers pairing, LEDs, buttons, multipoint, AUX only | seen | [user manual][manual] |
| 2 | Firmware declares **vendor 0x05D6 = Zhuhai Jieli Technology Co., Ltd**, product 0x000A, version 0x0240 | seen | SDP Device ID record, C frames 663, 3528; company id checked against the [Bluetooth SIG list][sig] |
| 3 | SDK service names `JL_A2DP` and `JL_HFP` | seen | SDP, C frame 744 |
| 4 | The **radio chip** reports **Bluetooth 5.3** (LMP 12), manufacturer **0x05D6**, subversion 0x22BB | seen | Read Remote Version Information: A frame 3420, C frames 220, 3206; D `remote_info:12-08891-01494` (decimal) |
| 5 | The Bluetooth chip/SDK is JieLi | inferred (strong) | two independent sources: the controller's link layer (#4) and the host firmware's SDP record (#2, #3) |
| 6 | Bluetooth 5.3, not 5.0 as the manual says | seen | #4; some listings already said 5.3; the manual may describe an earlier revision |
| 7 | Exactly four classic services: A2DP Sink 1.3, AVRCP 1.5 Controller, AVRCP 1.5 Target, Hands-Free 1.8 (RFCOMM ch 4) | seen | full SDP browse, C frame 744; D `sdp_uuids:4` |
| 8 | No Serial Port / vendor service is advertised over classic Bluetooth | seen | #7 lists every record with an L2CAP protocol; none is SPP or vendor |
| 9 | No BLE advertising from the headset observed | unknown (not observed) | 0 matches in 599 LE advertising reports across A-C; scans are partial |
| 10 | Class of Device 0x240404: Audio/Video, wearable headset; services rendering + audio | seen | Connection Request, C frames 195, 3168; D `cod:2400-4-4` |
| 11 | The headset initiates the connection to the phone | seen | incoming Connection Request events (C); D "Remote initiated" |
| 12 | Pairing is "Just Works": unauthenticated combination key, no Secure Connections | seen | D `bredr_linkkey_type:UNAUTH_COMB`, `SecureConn:F` |
| 13 | EDR at 2 Mbps only (no 3 Mbps) | seen | D `Support 3Mbps: false`; peer LMP features byte 3 = 0xfa (3 Mbps bit clear) |
| 14 | A2DP codecs: SBC (all rates/modes, **max bitpool 38**) and AAC; phone chose **AAC** | seen | AVDTP, C frames 384, 397, 345, 3366; D `Current Codec: AAC` |
| 15 | AAC runs at 44.1 kHz / 16-bit / stereo, variable bitrate, 660-byte MTU | seen | D "A2DP AAC State" |
| 16 | No AVDTP delay reporting (affects video lip-sync compensation) | seen | no delay-reporting capability in C; D `Delay Reporting: 0` |
| 17 | Hardware volume (AVRCP absolute volume) is supported | seen | headset ACCEPTED SetAbsoluteVolume, C frames 569, 1579, 1593, 1609, 3606; D `AbsVol: true` |
| 18 | Headset volume buttons change the **headset's own volume** in steps of 8 on a 0-127 scale: **17 levels** (0, 8 … 120, 127) | seen / derived | 72 VOLUME_CHANGED notifications in C, steps 8×66, 7×2; D shows the same 56→0→56 run |
| 19 | Volume changes do **not** send key presses (no AVRCP volume up/down pass-through) | seen in C | 0 volume pass-through commands vs 72 VOLUME_CHANGED |
| 20 | Skip and playback controls send AVRCP pass-through **play, pause, next, previous** (separate play and pause, not a toggle) | seen | C: play ×4, pause ×4, next ×8, previous ×5; D media key log (ids 68/70/75/76) |
| 21 | Button layout: Up short = volume+, Up long = **next**; Down short = volume−, Down long = **previous** | seen | owner; consistent with C (skips arrive as pass-through, volume changes as VOLUME_CHANGED, 11 of 13 skips have no volume step in the 2 s before) |
| 22 | The capture alone could not tell which button a skip came from | method note | the volume fell before the 01:10:18 "previous" and rose before the 01:13:02 one: that is just whatever the user did last. An early guess (Down long = previous) turned out right, and a later "contradicted" reading of the same data was wrong; neither had discriminating evidence |
| 23 | Every button event is sent as a complete click: press and release only 14-93 ms apart | seen | C, all 21 presses |
| 24 | The headset recognizes the gesture (short vs long press) itself and sends the result | inferred | #23: a held button cannot produce a 14 ms press on the wire |
| 25 | The headset subscribes to the phone's PLAYBACK_STATUS_CHANGED, presumably to choose play vs pause | seen / inferred | C, 24 RegisterNotification commands; D registered notifications: "Play Status" |
| 26 | HFP features: EC/NR, 3-way, caller ID, voice recognition, remote volume, codec negotiation (CVSD + mSBC wideband), eSCO S4; **no HF indicators**, no super-wideband | seen | `AT+BRSF=671`, `AT+BAC=1,2`; SDP features 0x003f; D WBS event |
| 27 | The headset does its own echo cancelling / noise reduction | inferred | `AT+NREC=0` (asks the phone to turn off its own); BRSF EC/NR bit |
| 28 | Battery is reported only via Apple's `AT+IPHONEACCEV` (0-9, ~10% steps), each report sent twice | seen | A frame 3737/3738; C frames 488/489, 1017, 3572/3575 |
| 29 | Battery jumped from 0/9 to 7/9 between A and C because it was charged while switched off | seen | owner confirmed; B's page timeouts match the headset being off |
| 29a | The phone shows the D02 Pro's battery percentage | seen | owner |
| 29b | That percentage comes from `AT+IPHONEACCEV`, so it moves in ~10% steps | inferred | it is the only battery report in A-C (#26: no HF indicators; D: BLE Battery profile not used, policy `BATTERY=-1`) |
| 30 | `AT+XAPL=ABCD-1234-0100,10` uses placeholder vendor/product ids | inferred | literal `ABCD-1234`; the real ids are #2 and #4 |
| 31 | The headset asks the phone's manufacturer (`AT+CGMI?`) on every connection | seen | A frame 3710, C frames 447, 3526 |
| 32 | Vendor command `AT+VDSF=1`, rejected by the phone (`+CME ERROR: 0`) | seen; meaning **unknown** | A frame 3745, C frames 500, 3589; no public documentation found |
| 33 | Android treats `AT+CGMI?`, `AT+XAPL`, `AT+IPHONEACCEV` ×2 and `AT+VDSF` as non-standard (5 "unknown AT" events) | inferred | D logs 5 `EVENT_TYPE_UNKNOWN_AT` at 01:12:19.174-.880, one-to-one and in order with those commands in C |
| 34 | Call volume: speaker 12/15, mic 15/15 | seen | `AT+VGS=12`, `AT+VGM=15`; D `mSpeakerVolume: 12`, `mMicVolume: 15` |
| 35 | This phone offloads A2DP encoding to its Bluetooth chip, so audio never appears in the snoop log | seen | D `A2dpOffloadEnabled: true`, "Stream sink offloaded"; C has 5 accepted AVDTP STARTs and 0 audio packets |

[manual]: https://www.mediaexpert.pl/products/files/29/2967622/instrukcja-obslugi-BASEUS-Encok-D02-Pro.pdf
[sig]: https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml

### Cross-check: capture vs Android's own records

Android's `dumpsys` (D) and capture C share a clock: the first "play" in C (01:12:43.487)
precedes Android's media-key log entry by 34 ms. With the clocks aligned:

- all **8 media key events** in D match C's AVRCP pass-through operations exactly, in order
  (D logs the AVRCP operation id in decimal: 68 play, 70 pause, 75 next, 76 previous);
- the **volume run** in D (56, 48 … 0 … 48, 56) is identical to C's VOLUME_CHANGED sequence;
- D's controller identity (`remote_info:12-08891-01494`) equals C's Read Remote Version event.

What neither source could settle is which button skips which way (#22). The owner's direct
description (#21) did.

### Open questions

- **Battery accuracy**: after charging (#29) it read 7/9, then 6/9 after 26 s and 5/9 after
  about 3.5 min. That suggests a voltage-based estimate that sags after charging (inferred).
- **The 01:11:13 link loss** (C): audio had paused at 01:11:01.9 and the link went to sniff mode
  at 01:11:08.9. After the 5 s supervision timeout the headset had gone silent. Was it switched
  off or out of range? Unknown.
- **`AT+VDSF=1`**: what does the JieLi firmware expect? It is likely meant for a particular
  phone brand (see #31). It is harmless to ignore, and nothing should be sent back to it blindly.
- **BLE** (#9): run `rardex scan` near the headset to settle it.

## What this means for your own software

| Feature | Works? | How |
|---|---|---|
| Hardware volume | yes (#17, #18) | `rardex headset volume 64`; prefer multiples of 8, the headset's own steps |
| Battery level | yes, 10% steps (#28, #29b) | Android already shows it; on Linux `rardex headset info`, if the audio server forwards Apple battery reports to BlueZ |
| Play/pause/next/previous | yes (#20) | `rardex headset buttons --map ...` (BlueZ turns them into key events) |
| Up long (next) / Down long (previous) as custom actions | yes, cleanly (#21, #23) | they arrive as next/previous keys with no stray volume step first |
| Up short (volume+) / Down short (volume−) as custom actions | no (#19) | they change the headset volume itself; Linux sees a transport `Volume` change, not a key |
| Custom gestures (double/triple press, hold durations) | no (#24) | the headset decides the gesture; software only sees the result |
| Call buttons | partly | HFP AT commands to the phone/audio stack; not visible to `headset buttons` |
| Audio quality | AAC 44.1 kHz VBR if available (#14, #15) | on Linux, AAC needs an AAC-capable audio server build; otherwise SBC at bitpool ≤ 38 |
| Video lip-sync | no delay reports (#16) | the player must assume a default Bluetooth latency |
| EQ / ANC / settings | no evidence of any | no vendor channel (#8); nothing to control beyond the above |

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
rardex snoop info     capture.log    # devices (name, class, chip), failed attempts, ACL handles
rardex snoop features capture.log    # everything in the findings table, with frame numbers
rardex snoop timeline capture.log --gap 2
```

## Decoder lessons from these captures

Real captures exposed things that the synthetic tests had not:

1. **Controller diagnostics on ACL handle 0x0EDC.** About half of every capture was ACL
   traffic on a handle that no connection event ever opened, flowing only controller → host,
   with payloads that match no protocol. Decoding it as L2CAP produced hundreds of fake
   "channels". rardex now counts it separately (`snoop info` → `acl handles`). The phone's
   controller is Qualcomm (D: manufacturer 29 = 0x001D, verified in the SIG list; its bug
   report lists `vendor.qti` HALs), so this is seen for that platform. Whether other
   chipsets use the same handle is unknown.
2. **Failed connections hide in plain sight.** Capture B looked empty. In fact it held four
   `Connection Complete` events with status `0x04 page timeout`. rardex used to ignore failed
   events; `snoop info` now lists them. This is the primer's rule in action: no data is
   **unknown**, not "nothing happened".
3. **Devices repeat themselves.** The headset sends each battery report twice, and phones ask
   for the same SDP record several times with different attributes. The audit now collapses
   identical repeats and merges partial SDP answers, so counts reflect behavior rather than
   retransmissions.
4. **Missing audio isn't missing streaming.** The phone offloads A2DP to its chip (#35), so the
   log shows the stream starting but never the audio. The audit now says so instead of
   staying silent.
5. **A second source confirms, but only discriminating evidence decides.** Lining up Android's
   `dumpsys` with the capture confirmed most findings independently. For the button layout,
   though, "which volume step came just before the skip" was read first as support for a
   guess and then as its refutation. Both readings were overconfident, because that evidence
   can't tell the buttons apart (#22). A direct, controlled observation settled it (#21).
6. **Derived claims inherit their premises.** A timing test was designed from a first, mistaken
   description of the buttons. When the owner corrected the description, the test lost its
   meaning and was dropped instead of being kept as a "finding".
