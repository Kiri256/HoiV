#!/usr/bin/env python3
"""Pin land-org command [9]/[10] and AI callers. Do not scan factories as product gates."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, lea_to, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


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


def find_vt(data, ib, sections, name: bytes):
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
        q = struct.pack("<Q", ib + col)
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


def dump_vt(data, ib, sections, name, vt, n=12):
    print(f"\n{name} vt 0x{vt:08x}")
    off = rva_to_off(sections, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            print(f"  [{i:3d}] 0x{va:016x}")
            continue
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")


def dump_calls(data, sections, funcs, target, label, n=16):
    hits = calls_to(data, sections, target)
    print(f"\n== {label} 0x{target:08x} callers={len(hits)}")
    print("  prologue", hexdump(data, sections, target, 18))
    pfn0 = fn_for(funcs, target)
    if pfn0:
        print(f"  pdata [0x{pfn0[0]:08x},0x{pfn0[1]:08x})")
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} fn={fns}")
        print(f"       {hexdump(data, sections, max(0, rva - 16), 40)}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    print("ib", hex(ib))

    print("\n== RTTI Command/Action with army/theatre/front/group ==")
    start = 0
    shown = 0
    while shown < 60:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        low = name.lower()
        if ("command" in low or low.endswith("action@@")) and any(
            k in low
            for k in (
                "theatre",
                "theater",
                "armygroup",
                "army_group",
                "newarmy",
                "new_army",
                "createarmy",
                "assign",
                "newfront",
                "frontcommand",
            )
        ):
            vts = find_vt(data, ib, sections, data[i:end])
            print(f"  {name} {[hex(x) for x in vts[:3]]}")
            shown += 1
        start = i + 1

    commands = (
        ("CSetTheatreCommand", 0x0298A870),
        ("CArmyGroupCommand", 0x029E3500),
        ("COrderNewFrontCommand", 0x029E4180),
        ("CAssignToArmyGroupCommand", 0x029E35C8),
    )
    for name, vt in commands:
        dump_vt(data, ib, sections, name, vt, 12)
        off = rva_to_off(sections, vt)
        can = struct.unpack_from("<Q", data, off + 9 * 8)[0] - ib
        do = struct.unpack_from("<Q", data, off + 10 * 8)[0] - ib
        dump_calls(data, sections, funcs, can, f"{name}[9] Can")
        dump_calls(data, sections, funcs, do, f"{name}[10] Do")
        for lea in lea_to(data, sections, vt, 8):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  LEA vt 0x{lea:08x} fn={fns} {hexdump(data, sections, max(0, lea - 12), 36)}")

    dump_calls(data, sections, funcs, 0x01353520, "CSetTheatreCommand ctor 0x01353520")
    dump_calls(data, sections, funcs, 0x010B4620, "minister theater helper 0x010B4620")


if __name__ == "__main__":
    main()
