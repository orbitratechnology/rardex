# 1. Reverse engineering primer

Reverse engineering means working out how something works from the thing itself, without
its source or documentation. For a Bluetooth speaker, "the thing" is the conversation
between the vendor app and the speaker, plus the app that produces it. The goal of this
project is **interoperability**: controlling hardware you own with software you wrote.

This chapter distills the method from two reference projects and applies it to devices:

- **[REA (Reverse Engineer Anything)](https://github.com/morluto/rea)** is a large MCP
  toolkit (Ghidra/Hopper/IDA, JADX, TShark, Frida and more) built around one core idea:
  every conclusion carries its **evidence**, its **provenance** and its **limitations**.
- **[leanrea](https://github.com/aicodeking/leanrea)** is an 8 KB skill file that argues
  the same results come faster from plain CLI tools, a routing table and a list of traps.
  Its benchmark shows fewer turns and tokens at about the same accuracy.

They disagree about tooling and agree about method. The method is what you need.

## The ten rules

### 1. Label every claim: seen, inferred or unknown

This is the most important habit, and both projects insist on it. REA's guidelines say to
"distinguish observations, derivations, inferences, and unknowns". leanrea says "a fact you
did not find is **unknown**, not 'absent'".

| Label | Meaning | Example |
|---|---|---|
| **seen** | Observed directly; cite where | "frame 38 writes `a5 5a 02 02 09 f3` to handle 0x0012" |
| **derived** | Computed from what was seen | "`f3` = −(02+02+09) mod 256" |
| **inferred** | A hypothesis that fits the evidence | "byte 4 is the volume level" |
| **unknown** | Not established either way | "is 31 the maximum volume?" |

Inferences turn into facts through **controlled experiments**: change exactly one thing,
capture again, and see which byte moved. Use `docs/04-protocol-notebook.md` to keep track.

### 2. Static reading is not observed behavior

Reading code tells you what *could* happen. A capture tells you what *did* happen, under
the conditions you recorded. REA keeps the two apart: its static tools "read the supplied
files without running the application". For devices the order is: **capture first** (what
the app actually sends), then **read the app** to explain or confirm what you saw.

### 3. Route first, then take the cheapest inventory

leanrea's first rule is to identify the target (`file`, magic bytes) and run the cheapest
complete inventory before reading any code. For a speaker the inventory is:

1. What advertises? (`rardex scan`, `bluetoothctl`)
2. Which services exist? (`rardex gatt ADDR --read`, `sdptool browse ADDR`)
3. Which channels does the app actually use? (`rardex snoop info capture.log`)

Most of the time that third command alone tells you where to look: one handle carries
nearly all the writes.

### 4. Work on a copy and record identities

REA preserves the caller's inputs and records digests. leanrea says "work on a copy". Keep
the original capture untouched, note its SHA-256 (`sha256sum btsnoop_hci.log`) in your
notebook, and record the app and firmware versions. Protocols change between firmware
releases, and you will want to know which version your notes describe.

### 5. Slice, don't read

leanrea: "never `cat` a big or minified file". A full HCI log has thousands of packets,
most of them audio, acknowledgements and housekeeping. Filter to the channel that matters
(`timeline --handle 0x0012`, `export --direction tx`) and to the moment that matters (the
pauses between your actions).

### 6. Diff before you decode

"Diff the inventories before you diff any code" (leanrea). For protocols, diff frames
before trying to understand them. Two frames that differ only in the setting you changed
give you that setting's byte for free: `rardex diff <frame-a> <frame-b>`.

### 7. Equivalent explanations exist: choose the simplest, then test

On the practice target, `rardex analyze` finds two checksum explanations:
`sum8_neg over frame[2:-1]` and `sum8_not over frame[0:-1]`. They always agree because the
sync bytes `a5 + 5a = ff`. Neither is "the" answer from these samples alone. Pick the
simpler one, note the alternative, and move on. They produce identical bytes, so for
interoperability the difference does not matter.

### 8. Know how much your evidence is worth

A 1-byte checksum matches a random frame 1 time in 256. Test enough algorithm/range
combinations against a single frame and something will "match". `rardex checksum` reports
the expected number of chance matches so you can see when you need more distinct frames.
REA makes a similar point about captures: a bounded query "must not be used to infer
whole-capture absence".

### 9. Rebuild, then prove the rebuild against the original

leanrea: "write the minimal reimplementation, then test it against the original (same
inputs, same outputs)". REA's DX-Ball showcase reconstructs a function and checks it against
3,205 original cases. Here the equivalents are:

- `rardex proto build x.toml volume level=9 --compare <captured frame>`: byte-identical?
- `rardex proto verify x.toml frames.txt`: does your model explain *every* captured frame?

A protocol file that explains 100% of a capture is a strong result. At 95%, the remaining
5% is where the next thing to learn is.

### 10. Batch your probes; stop when the question is answered

leanrea measured that turns cost more than bytes. Run one recon command that answers
several questions, look, then go deeper only where needed. Stop when every question has
evidence. Re-verifying what you have already seen is a cost, not progress.

## Static analysis of the vendor app (optional, for confirmation)

When the capture leaves questions open (what is the full range of an argument? what is that
mystery command at startup?), the app that you have installed is the best documentation of
the protocol. leanrea's router covers the standard approach for Android: decompile with
`jadx` and search with `rg -uu` for the characteristic UUID you found, or for the constant
sync bytes. The code near those hits usually names the commands. Keep this local and use it
to understand behavior; don't redistribute decompiled vendor code.

## Where REA and leanrea fit

If you want an agent to drive heavyweight engines (Ghidra, JADX, TShark) with structured
evidence, REA has workflows for APKs, packet captures and firmware. If you'd rather use
plain tools with a short checklist, leanrea's `SKILL.md` is worth reading in full. This
project follows the leanrea approach for the Bluetooth-specific part: a few focused
commands, pure Python, no services to run.
