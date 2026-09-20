#!/usr/bin/env python3
"""Who posts COrderExecuteCommand, and who creates fronts/AGs besides CAIGeneral[13]."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

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


def dump_vt(data, ib, sections, name, vt, n=14):
    print(f"\n{name} vt 0x{vt:08x}")
    off = rva_to_off(sections, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            print(f"  [{i:3d}] 0x{va:016x}")
            continue
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 18)}")


def dump_calls(data, sections, funcs, target, label, n=24):
    hits = calls_to(data, sections, target)
    print(f"\n== {label} 0x{target:08x} callers={len(hits)}")
    print("  prologue", hexdump(data, sections, target, 20))
    pfn0 = fn_for(funcs, target)
    if pfn0:
        print(f"  pdata [0x{pfn0[0]:08x},0x{pfn0[1]:08x})")
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} fn={fns}")
        print(f"       {hexdump(data, sections, max(0, rva - 12), 36)}")


def dump_interesting_calls(data, sections, begin, end, interesting):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  call 0x{begin + i:08x} -> 0x{tgt:08x}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    print("ib", hex(ib))

    names = [
        b".?AVCOrderExecuteCommand@@",
        b".?AVCOrderNewFrontCommand@@",
        b".?AVCMoveArmiesInTheaterCommand@@",
        b".?AVCAssignToTheaterGroupCommand@@",
        b".?AVCRemoveFromArmyGroupCommand@@",
        b".?AVCSetAreaDefenseCommand@@",
        b".?AVCOrderAreaDefenseCommand@@",
        b".?AVCAreaDefenseCommand@@",
        b".?AVCExecuteOrderCommand@@",
    ]
    print("\n== RTTI ==")
    start = 0
    while True:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end]
        low = name.lower()
        if any(
            k in low
            for k in (
                b"execute",
                b"areadefen",
                b"area_def",
                b"newfront",
                b"assign",
                b"theatergroup",
                b"theatre",
            )
        ) and (b"command" in low or b"action" in low):
            vts = find_vt(data, ib, sections, name)
            print(f"  {name.decode('latin1')} {[hex(x) for x in vts[:4]]}")
        start = i + 1

    exec_vts = find_vt(data, ib, sections, b".?AVCOrderExecuteCommand@@")
    print("COrderExecuteCommand vts", [hex(x) for x in exec_vts])
    if exec_vts:
        dump_vt(data, ib, sections, "COrderExecuteCommand", exec_vts[0], 14)
        off = rva_to_off(sections, exec_vts[0])
        can = struct.unpack_from("<Q", data, off + 9 * 8)[0] - ib
        do = struct.unpack_from("<Q", data, off + 10 * 8)[0] - ib
        dump_calls(data, sections, funcs, can, "COrderExecuteCommand[9]")
        dump_calls(data, sections, funcs, do, "COrderExecuteCommand[10]")
        for lea in lea_to(data, sections, exec_vts[0], 16):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  LEA exec vt 0x{lea:08x} fn={fns} {hexdump(data, sections, max(0, lea - 8), 32)}")

    dump_calls(data, sections, funcs, 0x0181DA50, "COrderExecute ctor 0x0181DA50")
    dump_calls(data, sections, funcs, 0x01A5BF00, "volunteer execute helper 0x01A5BF00")
    dump_calls(data, sections, funcs, 0x00F3EAE0, "Idler execute 0x00F3EAE0")

    dump_vt(data, ib, sections, "COrderNewFrontCommand", 0x029E4180, 14)
    off = rva_to_off(sections, 0x029E4180)
    front_can = struct.unpack_from("<Q", data, off + 9 * 8)[0] - ib
    front_do = struct.unpack_from("<Q", data, off + 10 * 8)[0] - ib
    dump_calls(data, sections, funcs, front_can, "COrderNewFrontCommand[9]")
    dump_calls(data, sections, funcs, front_do, "COrderNewFrontCommand[10]")
    dump_calls(data, sections, funcs, 0x0181E620, "COrderNewFront ctor 0x0181E620")

    dump_calls(data, sections, funcs, 0x00EE10B0, "AG factory 0x00EE10B0")
    dump_calls(data, sections, funcs, 0x00EEE3A0, "front factory 0x00EEE3A0")
    dump_calls(data, sections, funcs, 0x0105CCE0, "AG poster 0x0105CCE0")
    dump_calls(data, sections, funcs, 0x01058380, "AG poster parent 0x01058380")

    interesting = {
        0x00EE10B0,
        0x00EEE3A0,
        0x00ED9F40,
        0x00EEA3E0,
        0x0181B3E0,
        0x0181BB10,
        0x0181E620,
        0x01353520,
        0x0181DA50,
        0x0029E7B0,
        0x002A8D90,
        0x00EE67F0,
    }
    print("\n== CCountry nearby 0x00EEA3E0 pdata neighbors ==")
    pfn = fn_for(funcs, 0x00EEA3E0)
    print("0x00EEA3E0", None if not pfn else (hex(pfn[0]), hex(pfn[1])))
    if pfn:
        dump_interesting_calls(data, sections, pfn[0], pfn[1], interesting)
    # neighbors in pdata around theatre wrapper
    idx = None
    for i, (b, e) in enumerate(funcs):
        if b == 0x00EEA3E0 or (b <= 0x00EEA3E0 < e):
            idx = i
            break
    if idx is not None:
        for j in range(max(0, idx - 8), min(len(funcs), idx + 9)):
            b, e = funcs[j]
            mark = " <<<" if b <= 0x00EEA3E0 < e else ""
            print(f"  neigh [{j}] [0x{b:08x},0x{e:08x}){mark}")
            dump_interesting_calls(data, sections, b, e, interesting)

    print("\n== CCountry vt slots whose body calls AG/front factory or NewFront ctor ==")
    vt = rva_to_off(sections, 0x027C0E80)
    for i in range(80):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            continue
        rva = va - IB
        pfn = fn_for(funcs, rva)
        if not pfn:
            continue
        off = rva_to_off(sections, pfn[0])
        blob = data[off : off + min(0x800, pfn[1] - pfn[0])]
        hits = []
        for k in range(len(blob) - 4):
            if blob[k] != 0xE8:
                continue
            rel = struct.unpack_from("<i", blob, k + 1)[0]
            tgt = (pfn[0] + k + 5 + rel) & 0xFFFFFFFF
            if tgt in interesting:
                hits.append(tgt)
        if hits:
            print(f"  CCountry[{i}] 0x{rva:08x} {sorted(set(hex(x) for x in hits))}")


if __name__ == "__main__":
    main()
