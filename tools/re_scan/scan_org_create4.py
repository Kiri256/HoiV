#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000

VTS = {
    0x0298A870: "CSetTheatreCommand",
    0x029E3500: "CArmyGroupCommand",
    0x0294ED28: "CTheatre",
    0x029BE6C0: "CTheaterGroup",
}


def pdata(data, sections):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    dd = e_lfanew + 24 + 112
    exc_rva, exc_size = struct.unpack_from("<II", data, dd + 3 * 8)
    off = rva_to_off(sections, exc_rva)
    out = []
    for i in range(exc_size // 12):
        begin, end, _u = struct.unpack_from("<III", data, off + i * 12)
        if begin < end:
            out.append((begin, end))
    out.sort()
    return out


def fn_for(funcs, rva):
    lo, hi = 0, len(funcs)
    while lo < hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= rva:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    begin, end = funcs[lo - 1]
    return (begin, end) if begin <= rva < end else None


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def vt_hits(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    p = 0
    out = []
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti(data, sections, col - IB)
        out.append((vr, name))
        p = i + 1
        if len(out) >= 6:
            break
    return out


def dump_vt(data, sections, name, vt, n=40):
    off = rva_to_off(sections, vt)
    print(f"\n{name} 0x{vt:08x}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            continue
        rva = va - IB
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")


def lea_in(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    hits = []
    for i in range(len(blob) - 6):
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            tgt = (begin + i + 7 + rel) & 0xFFFFFFFF
            if tgt in VTS:
                hits.append((begin + i, VTS[tgt]))
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
            if tgt in (0x00EEA3E0, 0x00ED9F40, 0x01355120, 0x01353520, 0x0029E7B0, 0x00EE10B0):
                hits.append((begin + i, f"call 0x{tgt:08x}"))
    return hits


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for vt in (0x027BBAD8, 0x027BBB68, 0x027BBBA8):
        dump_vt(data, sections, "CStrategicAI", vt, 48)

    print("\n== theatre parent callers ==")
    for rva, fn in (
        (0x00351C20, 0x00351C20),
        (0x003675D0, 0x003675D0),
        (0x00C6F1B0, 0x00C6F1B0),
        (0x00E79570, 0x00E79570),
        (0x00ED6A60, 0x00ED6A60),
        (0x00ED8810, 0x00ED8810),
        (0x00EEAC10, 0x00EEAC10),
        (0x00EECE80, 0x00EECE80),
        (0x00EF2ECC, 0x00EF2ECC),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  vt", vt_hits(data, sections, pfn[0] if pfn else rva))
        print(" ", hexdump(data, sections, rva, 24))
        if pfn:
            for site, what in lea_in(data, sections, pfn[0], pfn[1]):
                print(f"  {what} @0x{site:08x}")

    print("\nCSetTheatre[10] body calls")
    pfn = fn_for(funcs, 0x013576C0)
    print("pdata", None if not pfn else (hex(pfn[0]), hex(pfn[1])))
    if pfn:
        for site, what in lea_in(data, sections, pfn[0], pfn[1]):
            print(f"  {what} @0x{site:08x}")
        off = rva_to_off(sections, pfn[0])
        blob = data[off : off + (pfn[1] - pfn[0])]
        for i in range(len(blob) - 4):
            if blob[i] != 0xE8:
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
            if tgt in (0x00EEA3E0, 0x00ED9F40, 0x00EEE3A0, 0x00EE10B0, 0x00ED6A60):
                print(f"  E8 0x{pfn[0]+i:08x} -> 0x{tgt:08x}")


if __name__ == "__main__":
    main()
