#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def main():
    data, ib, sections = load_pe(EXE)
    print("call site 0x01082f20", hexdump(data, sections, 0x01082F20, 48))
    print("0x01081FE0", hexdump(data, sections, 0x01081FE0, 48))
    print("0x01058380", hexdump(data, sections, 0x01058380, 64))
    print("volunteer call 0x01a5d260", hexdump(data, sections, 0x01A5D260, 40))
    print("CAIGeneral[13] 0x0107d9c0", hexdump(data, sections, 0x0107D9C0, 40))
    print("call 0x0107dc00", hexdump(data, sections, 0x0107DC00, 24))
    print("call 0x0107dc30", hexdump(data, sections, 0x0107DC30, 24))
    print("call 0x0107dd20", hexdump(data, sections, 0x0107DD20, 32))
    for rva, name in (
        (0x01059820, "0x01059820"),
        (0x0105A4E0, "0x0105A4E0"),
        (0x0105DBB0, "0x0105DBB0"),
        (0x00EEA3E0, "theatre parent 0x00EEA3E0"),
        (0x006F8F50, "country theatre 0x006F8F50"),
    ):
        print(name, hexdump(data, sections, rva, 24))
        off = rva_to_off(sections, rva)
        blob = data[off : off + 0x200]
        for i in range(len(blob) - 6):
            if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15):
                rel = struct.unpack_from("<i", blob, i + 3)[0]
                tgt = (rva + i + 7 + rel) & 0xFFFFFFFF
                if tgt in (0x0298A870, 0x029E3500, 0x0294ED28, 0x029BE6C0, 0x0292BF58):
                    print(f"  lea 0x{rva+i:08x} vt 0x{tgt:08x}")
            if blob[i] == 0xE8:
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                tgt = (rva + i + 5 + rel) & 0xFFFFFFFF
                if tgt in (0x002A8D90, 0x002A8E20, 0x0029E7B0, 0x00ED9F40, 0x01353520, 0x0181B3E0):
                    print(f"  call 0x{rva+i:08x} -> 0x{tgt:08x}")


if __name__ == "__main__":
    main()
