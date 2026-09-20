#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

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


def dump_calls(data, sections, begin, end):
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry2",
        0x0029E7B0: "post",
        0x0181DB50: "OrderGroup ctor A",
        0x0181DD70: "OrderGroup ctor B",
        0x0181B3E0: "AG ctor",
        0x0181BB10: "AssignAG",
        0x0181E620: "NewFront",
        0x0105CCE0: "AG poster",
        0x01058380: "AG parent",
        0x00BE0580: "OG ctor",
        0x00EE10B0: "AG factory",
        0x00EEE3A0: "front factory",
    }
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x} {interesting[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for rva, label in (
        (0x0105C5F0, "OrderGroup poster neighbor"),
        (0x01059820, "OrderGroup poster 59820"),
        (0x0181DB50, "OrderGroup ctor A"),
        (0x0181DD70, "OrderGroup ctor B"),
        (0x01832910, "COrderGroupCommand[9]"),
        (0x00F3AE80, "Idler-adjacent OrderGroup"),
        (0x01A5EA30, "vol-adjacent OrderGroup"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n==== {label} 0x{rva:08x} {None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  pro", hexdump(data, sections, pfn[0] if pfn else rva, 20))
        if pfn:
            dump_calls(data, sections, pfn[0], pfn[1])
        hits = calls_to(data, sections, pfn[0] if pfn else rva)
        print(f"  callers={len(hits)}")
        for site, kind in hits[:12]:
            pf = fn_for(funcs, site)
            print(f"    {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))}")


if __name__ == "__main__":
    main()
