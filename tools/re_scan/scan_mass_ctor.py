#!/usr/bin/env python3
"""CMassMoveCommand ctor args and call site in 0x002AB450."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def parse_pdata(data, sections):
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
    funcs = parse_pdata(data, sections)

    print("== mass body around CMassMoveCommand ==")
    print(hexdump(data, sections, 0x002AB6A0, 96))
    print("\n== mass body around CSetResearchCommand ==")
    print(hexdump(data, sections, 0x002AB7F0, 80))
    print("\n== mass body around naval mass move ==")
    print(hexdump(data, sections, 0x002AB740, 80))

    print("\n== CMassMoveCommand ctor 0x0134FDA0 ==")
    print(hexdump(data, sections, 0x0134FDA0, 80))
    hits = calls_to(data, sections, 0x0134FDA0)
    print("callers", len(hits))
    for rva, kind in hits[:12]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} fn={fns}")

    print("\n== CSetResearchCommand site 0x01137A50 ==")
    print(hexdump(data, sections, 0x01137A50, 48))
    hits = calls_to(data, sections, 0x01137A50)
    print("callers", len(hits))
    for rva, kind in hits[:8]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}")

    print("\n== CMassMoveCommand vt slots ==")
    vt = rva_to_off(sections, 0x0298A488)
    for i in range(12):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")


if __name__ == "__main__":
    main()
