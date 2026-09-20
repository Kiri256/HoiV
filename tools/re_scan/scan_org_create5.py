#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


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


def rtti(data, sections, col_rva):
    off = rva_to_off(sections, col_rva)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def name_vt(data, sections, vt):
    off = rva_to_off(sections, vt)
    if not off or off < 8:
        return "?"
    col = struct.unpack_from("<Q", data, off - 8)[0]
    if IB <= col < IB + 0x4000000:
        return rtti(data, sections, col - IB)
    return "?"


def dump_e8(data, sections, begin, end, interesting):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting or interesting is None:
            extra = interesting.get(tgt, "") if isinstance(interesting, dict) else ""
            print(f"  0x{begin+i:08x} -> 0x{tgt:08x} {extra}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for vt in (0x0274C788, 0x02746D80):
        print(f"vt 0x{vt:08x} {name_vt(data, sections, vt)}")

    # decode the vt hits from previous: ptr@ file rva
    for ptr in (41208200, 41185152, 43204024, 43300264):
        # those were file offsets? previous printed ptr@ as off_to_rva of the qword
        print("ptr rva", hex(ptr), "name", name_vt(data, sections, ptr) if rva_to_off(sections, ptr) else "no")

    interesting = {
        0x00EEA3E0: "theatre parent",
        0x00ED9F40: "CTheatre ctor",
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry+8",
        0x0029E7B0: "AI post",
        0x01355120: "SetTheatre factory",
        0x01353520: "SetTheatre ctor",
        0x00EE10B0: "AG factory",
        0x006C29C0: "maybe GetCountry min",
        0x001DBA10: "GetCountry wrap",
        0x006F1440: "CCountry[8] human?",
    }
    for rva in (0x00351C20, 0x003675D0, 0x013576C0, 0x00EEA3E0):
        pfn = fn_for(funcs, rva)
        print(f"\n== 0x{rva:08x} {None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print(" ", hexdump(data, sections, rva, 32))
        if pfn:
            dump_e8(data, sections, pfn[0], pfn[1], interesting)

    print("\ncallers 0x00351C20")
    hits = calls_to(data, sections, 0x00351C20)
    print("count", len(hits))
    for rva, kind in hits[:12]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")
        if pfn:
            print("   vt", name_vt(data, sections, pfn[0]))

    print("\ncallers 0x003675D0")
    hits = calls_to(data, sections, 0x003675D0)
    print("count", len(hits))
    for rva, kind in hits[:12]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")


if __name__ == "__main__":
    main()
