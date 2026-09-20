#!/usr/bin/env python3
"""Identify leftover execute/mass-move owners and CCountryAI slot of 0x002AB450."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IB_SPAN = 0x4000000


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


def find_qword(data, ib, sections, fn_rva):
    needle = struct.pack("<Q", ib + fn_rva)
    hits = []
    for name, _va, _vs, raw, raw_size in sections:
        if not (name.startswith(b".rdata") or name.startswith(b".data")):
            continue
        off = raw
        end = raw + raw_size
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            hits.append(off_to_rva(sections, i))
            off = i + 8
    return hits


def vt_near(vt_map, slot_rva):
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x400:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def identify(data, ib, sections, funcs, vt_map, rva, label):
    fn = fn_for(funcs, rva)
    print(f"\n== {label} 0x{rva:08x} pdata={None if not fn else (hex(fn[0]), hex(fn[1]))}")
    print(hexdump(data, sections, fn[0] if fn else rva, 48))
    target = fn[0] if fn else rva
    for q in find_qword(data, ib, sections, target):
        info = vt_near(vt_map, q)
        print(f"  qword@0x{q:08x} {info}")
    print("callers:")
    for site, kind in calls_to(data, sections, target)[:12]:
        pfn = fn_for(funcs, site)
        print(f"  {kind} 0x{site:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}")
        if pfn:
            for q in find_qword(data, ib, sections, pfn[0]):
                info = vt_near(vt_map, q)
                if info:
                    print(f"    {info[1]} [{info[2]}]")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    for rva, label in (
        (0x00F3EAE0, "COrderExecute site A"),
        (0x00F3B2F0, "COrderExecute site B"),
        (0x01A5BF00, "COrderExecute site C"),
        (0x01A21B10, "COrderExecute site D"),
        (0x002A7DE0, "thunk to CMassMove fn"),
        (0x002AB450, "CMassMove fn itself"),
        (0x0107D190, "strategic redeploy general fn"),
        (0x0181DA50, "COrderExecute ctor"),
    ):
        identify(data, ib, sections, funcs, vt_map, rva, label)

    print("\n== CCountryAI vtable slots around mass-move thunk ==")
    cai = 0x02710C90
    off = rva_to_off(sections, cai)
    for i in range(0, 160):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + IB_SPAN):
            continue
        rva = va - ib
        if rva in (0x002A7DE0, 0x002AB450, 0x002A7DFA) or abs(rva - 0x002AB450) < 0x20:
            print(f"  CCountryAI[{i}] 0x{rva:08x}")

    print("\n== CAIGeneral[13] window at 0x0107dd20 ==")
    print(hexdump(data, sections, 0x0107DD20, 80))
    print("\n== 0x01086f80 window ==")
    print(hexdump(data, sections, 0x01086F80, 48))
    print("\n== minister[14] general loop window ==")
    print(hexdump(data, sections, 0x010ABB40, 64))


if __name__ == "__main__":
    main()
