"""HFP/HSP AT commands - the text protocol headsets use for calls, volume and battery.

Hands-Free Profile runs over an RFCOMM channel as plain text: the headset (HF) sends
``AT...\\r`` commands, the phone (AG, audio gateway) answers ``\\r\\n+XYZ: ...\\r\\n`` and
``\\r\\nOK\\r\\n``. The first exchange (the Service Level Connection) is a feature handshake:
both sides announce supported features as bitmasks in ``AT+BRSF`` / ``+BRSF``.

Most headsets without an app report their battery here, through one of two mechanisms:

* Apple's accessory extension: ``AT+XAPL=VID-PID-VER,features`` then
  ``AT+IPHONEACCEV=n,key,value,...`` (key 1 = battery level 0..9).
* HFP 1.7+ HF indicators: ``AT+BIND=...`` then ``AT+BIEV=2,<0..100>`` (indicator 2 = battery).
"""

from __future__ import annotations

from dataclasses import dataclass

# AT+BRSF=<n> sent by the headset (HFP 1.7/1.8 HF supported features).
HF_FEATURES = [
    "EC/NR function",
    "three-way calling",
    "caller ID",
    "voice recognition",
    "remote volume control",
    "enhanced call status",
    "enhanced call control",
    "codec negotiation",
    "HF indicators",
    "eSCO S4 settings",
    "enhanced voice recognition status",
    "voice recognition text",
]

# +BRSF: <n> sent by the phone (AG supported features).
AG_FEATURES = [
    "three-way calling",
    "EC/NR function",
    "voice recognition",
    "in-band ring tone",
    "attach number to voice tag",
    "reject a call",
    "enhanced call status",
    "enhanced call control",
    "extended error codes",
    "codec negotiation",
    "HF indicators",
    "eSCO S4 settings",
    "enhanced voice recognition status",
    "voice recognition text",
]

# AT+XAPL features bitmask (Apple accessory design guidelines).
XAPL_FEATURES = {1: "battery reporting", 2: "docked or powered", 3: "Siri status", 4: "noise reduction status"}

CODECS = {1: "CVSD (narrowband)", 2: "mSBC (wideband)", 3: "LC3-SWB (super-wideband)"}

HF_INDICATORS = {1: "enhanced safety", 2: "battery level"}

COMMANDS = {
    "AT+BRSF": "feature exchange",
    "AT+BAC": "available codecs",
    "AT+BCS": "codec selection",
    "AT+CIND": "indicators",
    "AT+CMER": "indicator events on/off",
    "AT+CHLD": "call hold/multiparty",
    "AT+CLIP": "caller ID on/off",
    "AT+CCWA": "call waiting on/off",
    "AT+NREC": "noise reduction/echo cancel",
    "AT+CGMI": "asks the phone's manufacturer",
    "AT+CGMM": "asks the phone's model",
    "AT+VGS": "speaker volume (0-15)",
    "AT+VGM": "mic gain (0-15)",
    "AT+BVRA": "voice assistant",
    "AT+BLDN": "redial last number",
    "ATA": "answer call",
    "AT+CHUP": "hang up / reject",
    "ATD": "dial",
    "AT+CKPD": "HSP button press",
    "AT+XAPL": "Apple accessory identification",
    "AT+IPHONEACCEV": "Apple accessory battery/dock report",
    "AT+BIND": "HF indicators supported",
    "AT+BIEV": "HF indicator value",
    "AT+BIA": "indicator activation",
    "AT+CLCC": "list current calls",
    "AT+COPS": "network operator",
    "AT+CNUM": "subscriber number",
    "AT+BTRH": "response and hold",
    "AT+CMEE": "extended errors on/off",
}


def bits(value: int, names: list[str]) -> list[str]:
    return [name for i, name in enumerate(names) if value >> i & 1]


@dataclass(frozen=True)
class AtLine:
    text: str
    from_headset: bool  # True for HF -> AG commands, False for AG -> HF responses

    @property
    def command(self) -> str:
        """``AT+VGS=7`` -> ``AT+VGS``; ``+VGS: 7`` -> ``+VGS``; ``ATA`` -> ``ATA``."""
        t = self.text.strip()
        for sep in ("=?", "=", "?", ":"):
            if sep in t:
                return t.split(sep, 1)[0].strip()
        return "ATD" if t.startswith("ATD") else t

    @property
    def args(self) -> list[str]:
        t = self.text.strip()
        for sep in ("=", ":"):
            if sep in t:
                rest = t.split(sep, 1)[1].strip()
                return [a.strip() for a in rest.split(",")] if rest and rest != "?" else []
        return []

    def describe(self) -> str:
        """Plain-language meaning, with bitmasks and values expanded."""
        cmd, args = self.command, self.args
        try:
            if cmd == "AT+BRSF" and args:
                return "headset features: " + ", ".join(bits(int(args[0]), HF_FEATURES))
            if cmd == "+BRSF" and args:
                return "phone features: " + ", ".join(bits(int(args[0]), AG_FEATURES))
            if cmd == "AT+BAC":
                return "headset codecs: " + ", ".join(CODECS.get(int(a), a) for a in args)
            if cmd in ("AT+BCS", "+BCS") and args:
                return "codec selected: " + CODECS.get(int(args[0]), args[0])
            if cmd in ("AT+VGS", "+VGS") and args:
                return f"speaker volume {args[0]}/15"
            if cmd in ("AT+VGM", "+VGM") and args:
                return f"mic gain {args[0]}/15"
            if cmd == "AT+XAPL" and len(args) == 2:
                ident = args[0].split("-")
                feats = [n for b, n in XAPL_FEATURES.items() if int(args[1]) >> b & 1]
                who = f"vendor 0x{ident[0]} product 0x{ident[1]} version {ident[2]}" if len(ident) == 3 else args[0]
                return f"Apple accessory id: {who}; supports {', '.join(feats) or 'nothing'}"
            if cmd == "AT+IPHONEACCEV" and args:
                out = []
                pairs = args[1 : 1 + 2 * int(args[0])]
                for key, val in zip(pairs[::2], pairs[1::2]):
                    if key == "1":
                        out.append(f"battery {val}/9 (~{(int(val) + 1) * 10}%)")
                    elif key == "2":
                        out.append("docked" if val == "1" else "undocked")
                return "accessory report: " + ", ".join(out)
            if cmd == "AT+BIND" and args and args != ["?"]:
                return "HF indicators: " + ", ".join(HF_INDICATORS.get(int(a), a) for a in args)
            if cmd == "AT+BIEV" and len(args) == 2:
                if args[0] == "2":
                    return f"battery {args[1]}%"
                return f"indicator {HF_INDICATORS.get(int(args[0]), args[0])} = {args[1]}"
            if cmd == "AT+BVRA" and args:
                return "voice assistant " + ("start" if args[0] == "1" else "stop")
            if cmd == "AT+NREC" and args == ["0"]:
                return "asks the phone to turn off its echo cancel/noise reduction (headset does its own)"
            if cmd == "AT+CKPD":
                return "HSP button press"
        except (ValueError, IndexError):
            return COMMANDS.get(cmd, "")
        return COMMANDS.get(cmd, "")

    @property
    def battery_percent(self) -> int | None:
        """Battery level if this line reports one (rounded to the reporting scheme's step)."""
        cmd, args = self.command, self.args
        try:
            if cmd == "AT+BIEV" and len(args) == 2 and args[0] == "2":
                return int(args[1])
            if cmd == "AT+IPHONEACCEV" and args:
                pairs = args[1 : 1 + 2 * int(args[0])]
                for key, val in zip(pairs[::2], pairs[1::2]):
                    if key == "1":
                        return (int(val) + 1) * 10
        except ValueError:
            return None
        return None


# Result codes and commands defined by HFP/HSP (or Apple's published extension). Anything else
# a headset sends is vendor-specific and worth a closer look.
STANDARD = set(COMMANDS) | {
    "OK", "ERROR", "RING", "+CME ERROR", "+BRSF", "+CIND", "+CIEV", "+CHLD", "+CLIP", "+CCWA",
    "+VGS", "+VGM", "+BSIR", "+BVRA", "+BCS", "+BIND", "+BIEV", "+XAPL", "+CLCC", "+COPS",
    "+CNUM", "+BTRH", "+CGMI", "+CGMM", "AT+CGMR", "+CGMR",
}


def is_standard(command: str) -> bool:
    return command in STANDARD or command.startswith("ATD")


def looks_like_at(data: bytes) -> bool:
    """HFP traffic is ASCII starting with ``AT`` (headset) or ``\\r\\n`` (phone)."""
    return data[:2].upper() == b"AT" or data.startswith(b"\r\n")


def split_lines(data: bytes, from_headset: bool) -> list[AtLine]:
    text = data.decode("ascii", errors="replace")
    parts = text.replace("\r\n", "\r").replace("\n", "\r").split("\r")
    return [AtLine(p.strip(), from_headset) for p in parts if p.strip()]
