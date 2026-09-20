#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def find_vt(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    p = 0
    hits = []
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        slot = None
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti(data, sections, col - IB)
                # count slot from vt start = i+8 is first method? vt ptr is at i, col at i-8
                # slot 0 is at i if this is slot 0... we're at the matching qword
        hits.append((vr, name))
        p = i + 1
        if len(hits) >= 8:
            break
    return hits


def dump_calls(data, sections, begin, n):
    off = rva_to_off(sections, begin)
    blob = data[off : off + n]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in (0x00EE10B0, 0x00EEE3A0, 0x00ED9F40, 0x002A8D90, 0x002A8E20, 0x0029E7B0, 0x01353520):
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x}")


def main():
    data, ib, sections = load_pe(EXE)
    print("0x00247630", hexdump(data, sections, 0x00247630, 32))
    print("vt", find_vt(data, sections, 0x00247630))
    dump_calls(data, sections, 0x00247630, 0x300)
    print("CCountryAI slots 140-160")
    off = rva_to_off(sections, 0x02710C90)
    for i in range(130, 160):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if IB <= va < IB + 0x4000000:
            rva = va - IB
            if rva in (0x00247630, 0x002AB450, 0x002A7DE0):
                print(f"  [{i}] 0x{rva:08x} <<<")
            elif 0x00247000 <= rva <= 0x00248000:
                print(f"  [{i}] 0x{rva:08x}")
    # search all of CCountryAI 200 slots
    print("search CCountryAI 0-200 for 0x00247630")
    for i in range(200):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if va == IB + 0x00247630:
            print("  found slot", i)
    off2 = rva_to_off(sections, 0x02962938)
    print("search minister 0-30")
    for i in range(30):
        va = struct.unpack_from("<Q", data, off2 + i * 8)[0]
        if va == IB + 0x00247630:
            print("  minister slot", i)
    print("0x00247630 GetCountry uses")
    off = rva_to_off(sections, 0x00247630)
    blob = data[off : off + 0x2A0]
    for i in range(len(blob) - 7):
        if blob[i : i + 3] == b"\x48\x8b\x41" or blob[i : i + 3] == b"\x48\x8b\x49":
            print(f"  0x{0x00247630+i:08x} {blob[i:i+8].hex()}")


if __name__ == "__main__":
    main()
