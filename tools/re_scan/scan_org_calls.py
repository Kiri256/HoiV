#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def main():
    data, ib, sections = load_pe(EXE)
    begin, end = 0x010B4620, 0x010B53B4
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    print("0x010B4620 all E8")
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        print(f"  0x{begin + i:08x} -> 0x{tgt:08x}")

    print("\n0x010ABA70 window around posts")
    for rva in (0x010ABB40, 0x010ABB60, 0x010ABB78, 0x010ABC80):
        print(hex(rva), hexdump(data, sections, rva, 48))


if __name__ == "__main__":
    main()
