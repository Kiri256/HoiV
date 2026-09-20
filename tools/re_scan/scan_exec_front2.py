#!/usr/bin/env python3
"""Identify execute posters and AG-factory AI caller 0x00247630."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

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


def rtti_at_col(data, sections, col_rva):
    off = rva_to_off(sections, col_rva)
    if off is None:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if tdo is None:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def find_fn_vt(data, sections, fn_rva):
    q = struct.pack("<Q", IB + fn_rva)
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
                name = rtti_at_col(data, sections, col - IB)
        # guess slot: walk back 8-byte steps while values look like code ptrs
        if vr is not None:
            hits.append((hex(vr), name))
        p = i + 1
        if len(hits) >= 12:
            break
    return hits


def dump_calls_in(data, sections, begin, end, interesting):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting or 0x002A8D00 <= tgt <= 0x002A8E40:
            print(f"  call 0x{begin + i:08x} -> 0x{tgt:08x}")


def dump_vt_search(data, sections, fn_rva, vts):
    for name, vt, n in vts:
        off = rva_to_off(sections, vt)
        for i in range(n):
            va = struct.unpack_from("<Q", data, off + i * 8)[0]
            if va == IB + fn_rva:
                print(f"  {name}[{i}]")


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


def dump_cmd(data, ib, sections, funcs, rtti_name):
    vts = find_vt(data, ib, sections, rtti_name)
    print(f"\n{rtti_name.decode()} vts {[hex(x) for x in vts[:3]]}")
    if not vts:
        return
    vt = vts[0]
    off = rva_to_off(sections, vt)
    can = struct.unpack_from("<Q", data, off + 9 * 8)[0] - ib
    do = struct.unpack_from("<Q", data, off + 10 * 8)[0] - ib
    print(f"  [9] 0x{can:08x} {hexdump(data, sections, can, 16)}")
    print(f"  [10] 0x{do:08x} {hexdump(data, sections, do, 16)}")
    for lea in lea_to(data, sections, vt, 12):
        pfn = fn_for(funcs, lea)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  LEA 0x{lea:08x} {fns} {hexdump(data, sections, max(0, lea - 8), 28)}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    interesting = {
        0x002A8D90,
        0x002A8E20,
        0x006C2400,
        0x00EE10B0,
        0x00EEE3A0,
        0x0181DA50,
        0x0181E620,
        0x0029E7B0,
        0x0029E670,
        0x01A31660,
        0x01A2ED80,
        0x00F3EAE0,
        0x01353520,
        0x00ED9F40,
        0x00EEA3E0,
        0x0105CCE0,
        0x01058380,
        0x01081FE0,
        0x0181B3E0,
        0x0181BB10,
    }
    vts = [
        ("CCountryAI", 0x02710C90, 200),
        ("CCountryAI alt", 0x02710D20, 200),
        ("CAIMilitaryMinister", 0x02962938, 40),
        ("CAIGeneral", 0x029613D0, 40),
        ("CAIVolunteerGeneral", 0x02A0A7B0, 40),
        ("CCountry", 0x027C0E80, 80),
        ("CInGameIdler", 0x02942480, 20),
        ("CFront", 0x0294EE20, 40),
        ("CArmyGroup", 0x0292BF58, 40),
        ("CTheatre", 0x0294ED28, 40),
        ("COrdersGroup", 0x0292BEC0, 40),
    ]
    targets = [
        0x00247630,
        0x00F3B2F0,
        0x01A21B10,
        0x01A2ED80,
        0x01A23290,
        0x00F41450,
        0x01828E80,
        0x01496520,
        0x01A5BF00,
    ]
    for rva in targets:
        pfn = fn_for(funcs, rva)
        print(f"\n==== 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  pro", hexdump(data, sections, rva, 24))
        print("  vt hits", find_fn_vt(data, sections, rva))
        dump_vt_search(data, sections, rva, vts)
        if pfn:
            dump_calls_in(data, sections, pfn[0], pfn[1], interesting)
        hits = calls_to(data, sections, rva)
        print(f"  callers={len(hits)}")
        for site, kind in hits[:12]:
            pf = fn_for(funcs, site)
            print(f"    {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))}")

    dump_cmd(data, ib, sections, funcs, b".?AVCCreateAreaDefenseCommand@@")
    dump_cmd(data, ib, sections, funcs, b".?AVCEditAreaDefenseStateCommand@@")
    dump_cmd(data, ib, sections, funcs, b".?AVCSetAreaDefenseSettingCommand@@")
    dump_cmd(data, ib, sections, funcs, b".?AVCOrderAssignCommand@@")
    dump_cmd(data, ib, sections, funcs, b".?AVCAssignToTheaterGroupCommand@@")
    dump_cmd(data, ib, sections, funcs, b".?AVCMoveArmiesInTheaterCommand@@")

    print("\n== CCountryAI slots around 0x00247630 ==")
    off = rva_to_off(sections, 0x02710C90)
    for i in range(200):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            continue
        rva = va - IB
        if abs(rva - 0x00247630) < 0x800 or rva in (0x00247630, 0x00EEA3E0, 0x002AB450):
            print(f"  [{i}] 0x{rva:08x}")


if __name__ == "__main__":
    main()
