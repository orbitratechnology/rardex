# 4. Protocol notebook (template)

Copy this file to `notes/<brand>-<model>.md` and keep it next to your protocol file. Every
line in the protocol file should trace back to a row here.

## Target

| | |
|---|---|
| Device | brand, model, hardware revision |
| Firmware | version (from app "about" screen) |
| Vendor app | name, version, platform |
| Bluetooth name / address | |
| Control channel | e.g. BLE write `...` / notify `...`, or RFCOMM channel N |

## Captures

| File | SHA-256 | Date | What was done (script) |
|---|---|---|---|
| `captures/01-startup.log` | `…` | | open app, wait 10 s, close |
| `captures/02-volume.log` | `…` | | volume 0 → max slowly, then back to 10 |

## Findings

Label: **seen** (cite file + frame number), **derived** (computed from seen), **inferred**
(hypothesis that fits), **unknown** (not established). Never write "absent" for something
you simply did not observe.

| # | Claim | Label | Evidence | How to confirm / falsify |
|---|---|---|---|---|
| 1 | Every app→speaker frame starts with `a5 5a` | seen | 02-volume.log, all 27 writes | - |
| 2 | Byte 2 = payload length | inferred | `analyze`: u8 at offset 2 = len−4 across 4 lengths | capture a command with a new length |
| 3 | Last byte = −sum(bytes 2..n−2) mod 256 | derived | `analyze`: 22 distinct frames, ~1e-50 chance matches | `proto verify` on every capture |
| 4 | Command `02` sets volume, arg range 0..31 | inferred (range unknown above 16) | frames 38–53: 09→10 while slider moved | capture slider at the maximum |
| 5 | Speaker acks with `80 <cmd> <status>` | seen | rx frames 37, 39, … | - |

## Open questions

- What are the startup frames for? Are they required before other commands work?
- What does status byte N mean? (Change one setting, refresh status, diff.)

## Protocol file status

`rardex proto verify protocols/<x>.toml captures/*-tx.txt` → `N/N identified`
