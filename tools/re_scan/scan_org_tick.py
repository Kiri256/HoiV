#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")

TARGETS = {
    0x0107D9C0: "CAIGeneral[13]",
    0x01081FE0: "org parent",
    0x01058380: "org walk",
    0x0105CCE0: "AG poster",
    0x010B4620: "helper",
    0x0029E7B0: "AI post",
    0x01A31660: "move actor",
}


def dump(data, sections, begin, size, label):
    print(f"\n== {label} 0x{begin:08x} +{size:#x}")
    off = rva_to_off(sections, begin)
    blob = data[off : off + size]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in TARGETS or (0x01058000 <= tgt <= 0x01083000):
            print(f"  0x{begin+i:08x} -> 0x{tgt:08x} {TARGETS.get(tgt, '')}")


def main():
    data, ib, sections = load_pe(EXE)
    dump(data, sections, 0x01074470, 0x500, "CAIGeneral[14] 0x500")
    dump(data, sections, 0x0107D9C0, 0x450, "CAIGeneral[13] body")
    print("\n[14] after pdata", hexdump(data, sections, 0x0107449B, 32))
    # who calls [13] via lea of function - already 0 E8
    print("general tick bytes 16", hexdump(data, sections, 0x0107D9C0, 16))
    print("org walk 16", hexdump(data, sections, 0x01058380, 16))
    print("theatre can 16", hexdump(data, sections, 0x0135AF40, 16))
    print("ag can 15", hexdump(data, sections, 0x01831B90, 15))
    print("assign can 15", hexdump(data, sections, 0x01831D40, 15))


if __name__ == "__main__":
    main()
