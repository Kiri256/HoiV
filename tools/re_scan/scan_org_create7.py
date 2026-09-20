#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x002A8D90: "GetCountry",
    0x002A8E20: "GetCountry+8",
    0x006C29C0: "min getter",
    0x006C2400: "GetAI",
    0x006C2680: "GetCommandGroups",
    0x00ED9F40: "CTheatre ctor",
    0x00EDBF80: "theatre apply?",
    0x0029E7B0: "AI post",
    0x001DBA10: "wrap",
}


def main():
    data, ib, sections = load_pe(EXE)
    begin, end = 0x00EEA3E0, 0x00EEAC0B
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    print("0x00EEA3E0 E8 named/all first 40")
    n = 0
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in NAMED or n < 25:
            print(f"  0x{begin+i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")
            n += 1
    print("call site 0x00352030", hexdump(data, sections, 0x00352030, 48))
    print("call site 0x00367d60", hexdump(data, sections, 0x00367D60, 48))
    print("0x00EDBF80", hexdump(data, sections, 0x00EDBF80, 32))
    print("0x00EEA3E0 +0x40", hexdump(data, sections, 0x00EEA420, 48))
    # [rcx+8] in 0x00EEA3E0 first 0x100
    for i in range(0x100):
        if blob[i : i + 4] in (
            b"\x48\x8b\x43\x08",
            b"\x48\x8b\x4b\x08",
            b"\x48\x8b\x03",
            b"\x48\x8b\x0b",
            b"\x4c\x8b\x43\x08",
        ):
            print("load", hex(begin + i), blob[i : i + 8].hex())


if __name__ == "__main__":
    main()
