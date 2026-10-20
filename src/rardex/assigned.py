"""Bluetooth SIG assigned numbers that rardex reports: company ids, LMP versions, device class.

Company ids are listed only after checking them against the SIG's published list
(bitbucket.org/bluetooth-SIG/public, assigned_numbers/company_identifiers). An id that isn't
here is printed raw for you to look up; don't add entries from memory.
"""

from __future__ import annotations

COMPANIES = {
    0x000A: "Qualcomm Technologies International, Ltd. (QTIL)",
    0x001D: "Qualcomm",
    0x05D6: "Zhuhai Jieli Technology Co., Ltd",
}

# LMP / HCI version numbers -> Bluetooth Core specification version.
LMP_VERSIONS = {
    0: "1.0b",
    1: "1.1",
    2: "1.2",
    3: "2.0+EDR",
    4: "2.1+EDR",
    5: "3.0+HS",
    6: "4.0",
    7: "4.1",
    8: "4.2",
    9: "5.0",
    10: "5.1",
    11: "5.2",
    12: "5.3",
    13: "5.4",
}

MAJOR_CLASSES = {
    0: "Miscellaneous",
    1: "Computer",
    2: "Phone",
    3: "Network access point",
    4: "Audio/Video",
    5: "Peripheral",
    6: "Imaging",
    7: "Wearable",
    8: "Toy",
    9: "Health",
    31: "Uncategorized",
}
AUDIO_VIDEO_MINOR = {
    0: "uncategorized",
    1: "wearable headset",
    2: "hands-free",
    4: "microphone",
    5: "loudspeaker",
    6: "headphones",
    7: "portable audio",
    8: "car audio",
    9: "set-top box",
    10: "HiFi audio",
    14: "video monitor",
    15: "video display and loudspeaker",
    16: "video conferencing",
    18: "gaming/toy",
}
SERVICE_BITS = {
    13: "limited discoverable",
    16: "positioning",
    17: "networking",
    18: "rendering",
    19: "capturing",
    20: "object transfer",
    21: "audio",
    22: "telephony",
    23: "information",
}


def company(cid: int) -> str:
    name = COMPANIES.get(cid)
    return f"0x{cid:04x} {name}" if name else f"0x{cid:04x} (look up in the SIG company list)"


def bluetooth_version(lmp: int) -> str:
    return f"Bluetooth {LMP_VERSIONS[lmp]}" if lmp in LMP_VERSIONS else f"LMP version {lmp}"


def device_class(cod: int) -> str:
    """Class of Device, e.g. 0x240404 -> 'Audio/Video: wearable headset; services: rendering, audio'."""
    major = (cod >> 8) & 0x1F
    minor = (cod >> 2) & 0x3F
    kind = MAJOR_CLASSES.get(major, f"major class {major}")
    if major == 4:
        kind += ": " + AUDIO_VIDEO_MINOR.get(minor, f"minor {minor}")
    services = [name for bit, name in SERVICE_BITS.items() if cod >> bit & 1]
    return kind + (f"; services: {', '.join(services)}" if services else "")
