#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, lea_to, load_pe, off_to_rva, rva_to_off

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


def find_vt(data, sections, name: bytes):
    i = data.find(name + b"\0")
    if i < 0:
        return []
    td = off_to_rva(sections, i) - 16
    pat = struct.pack("<I", td)
    cols = []
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sections, j)
        if rva is not None:
            cols.append(rva - 12)
        start = j + 1
    vts = []
    for col in cols:
        q = struct.pack("<Q", IB + col)
        k = 0
        while True:
            p = data.find(q, k)
            if p < 0:
                break
            vr = off_to_rva(sections, p + 8)
            if vr:
                vts.append(vr)
            k = p + 1
    return vts


def dump_vt(data, sections, name, vt, n=12):
    print(f"\n{name} vt 0x{vt:08x}")
    off = rva_to_off(sections, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            print(f"  [{i:3d}] 0x{va:016x}")
            continue
        rva = va - IB
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")


def dump_calls_in(data, sections, begin, end):
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry2",
        0x0029E7B0: "post",
        0x00EEE3A0: "front factory",
        0x00EE10B0: "AG factory",
        0x00ED9F40: "theatre ctor",
        0x00BE0580: "orders group ctor",
        0x0105CCE0: "AG poster",
        0x01A23290: "newfront poster",
        0x00EEA3E0: "theatre AI",
    }
    off = rva_to_off(sections, begin)
    blob = data[off : off + min(end - begin, 0x2000)]
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
    names = (
        b".?AVCOrderGroupCommand@@",
        b".?AVCDeleteOrderGroupCommand@@",
        b".?AVCSelectionGroupCommand@@",
        b".?AVCMoveArmiesInTheaterCommand@@",
        b".?AVCMoveArmyGroupInTheaterCommand@@",
        b".?AVCOrderInsertFrontCommand@@",
        b".?AVCOrderAssignCommand@@",
        b".?AVCAssignToTheaterGroupCommand@@",
    )
    for name in names:
        vts = find_vt(data, sections, name)
        print(f"{name.decode()} {[hex(x) for x in vts[:3]]}")
        if not vts:
            continue
        dump_vt(data, sections, name.decode(), vts[0], 12)
        off = rva_to_off(sections, vts[0])
        can = struct.unpack_from("<Q", data, off + 9 * 8)[0] - IB
        do = struct.unpack_from("<Q", data, off + 10 * 8)[0] - IB
        print(f"  [9] 0x{can:08x} {hexdump(data, sections, can, 16)}")
        print(f"  [10] 0x{do:08x} {hexdump(data, sections, do, 16)}")
        for lea in lea_to(data, sections, vts[0], 12):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  LEA 0x{lea:08x} {fns}")
            if pfn and pfn[1] - pfn[0] < 0x800:
                hits = calls_to(data, sections, pfn[0])
                print(f"       callers={len(hits)}")
                for site, kind in hits[:10]:
                    pf = fn_for(funcs, site)
                    print(f"         {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))}")
                    if pf:
                        dump_calls_in(data, sections, pf[0], pf[1])


if __name__ == "__main__":
    main()
