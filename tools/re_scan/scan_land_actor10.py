#!/usr/bin/env python3
"""Hourly slot objects and CInGameIdler[4] country path."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IB_SPAN = 0x4000000
CAI = 0x02710C90


def slot(data, ib, sections, vt, i):
    off = rva_to_off(sections, vt + i * 8)
    va = struct.unpack_from("<Q", data, off)[0]
    return va - ib if ib <= va < ib + IB_SPAN else 0


def main():
    data, ib, sections = load_pe(EXE)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    print("== CCountryAI slots of hourly interest ==")
    for i in (1, 2, 12, 14, 16, 17, 110, 145):
        rva = slot(data, ib, sections, CAI, i)
        print(f"  [{i:3d}] +0x{i*8:x} 0x{rva:08x} {hexdump(data, sections, rva, 16) if rva else ''}")

    print("\n== hourly slot call windows ==")
    for rva in (0x001DF219, 0x001DF234, 0x001DF3E5, 0x001DF48C, 0x001DF4D6, 0x001DF944, 0x001DFED5):
        print(f"\n0x{rva:08x}")
        print(hexdump(data, sections, rva - 24, 48))

    print("\n== CInGameIdler[4] 0x00dc44c0 and call to 0x00f3eae0 ==")
    print(hexdump(data, sections, 0x00DC44C0, 64))
    print("call site 0x00dc5f41")
    print(hexdump(data, sections, 0x00DC5F20, 64))
    print("0x00f3eae0 prologue")
    print(hexdump(data, sections, 0x00F3EAE0, 80))

    print("\n== CCountryAI[110] if any ==")
    rva = slot(data, ib, sections, CAI, 110)
    print(hex(rva), hexdump(data, sections, rva, 24) if rva else "none")

    print("\n== names near 0x02711118 ==")
    for vt, name in sorted(vt_map.items()):
        if 0x02710C00 <= vt <= 0x02711200:
            print(f"  0x{vt:08x} {name}")


if __name__ == "__main__":
    main()
