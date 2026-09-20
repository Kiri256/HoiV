#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


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


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    print("CAIGeneral[13]", hexdump(data, sections, 0x0107D9C0, 24))
    pfn = fn_for(funcs, 0x0107D9C0)
    print("pdata", None if not pfn else (hex(pfn[0]), hex(pfn[1])))
    if pfn:
        off = rva_to_off(sections, pfn[0])
        blob = data[off : off + (pfn[1] - pfn[0])]
        for i in range(len(blob) - 4):
            if blob[i] != 0xE8:
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
            if tgt in (0x01081FE0, 0x01058380, 0x0105CCE0, 0x00ED9F40, 0x00EDA790, 0x01353520, 0x0029E7B0):
                print(f"  [13] call 0x{pfn[0]+i:08x} -> 0x{tgt:08x}")

    for target, label in (
        (0x00ED9F40, "CTheatre ctor A"),
        (0x00EDA790, "CTheatre ctor B"),
        (0x0107D9C0, "CAIGeneral[13]"),
    ):
        hits = calls_to(data, sections, target)
        print(f"\n{label} 0x{target:08x} callers={len(hits)}")
        for rva, kind in hits[:12]:
            pfn = fn_for(funcs, rva)
            print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")


if __name__ == "__main__":
    main()
