#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

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


def xrefs_fn(data, sections, fn_rva, limit=16):
    q = struct.pack("<Q", IB + fn_rva)
    hits = []
    p = 0
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
                # slot index if this qword is in a vtable: count from col+8
                if vr is not None:
                    slot = (vr - (col - IB + 8)) // 8 if vr >= col - IB + 8 else None
        hits.append((vr, name, slot))
        p = i + 8
        if len(hits) >= limit:
            break
    return hits


def rel_to(data, sections, target):
    raw0, raw1, _ = text_range(sections)
    out = []
    for off in range(raw0, raw1 - 5):
        if data[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        rva = off_to_rva(sections, off)
        if rva is not None and ((rva + 5 + rel) & 0xFFFFFFFF) == target:
            out.append((rva, "call" if data[off] == 0xE8 else "jmp"))
    return out


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


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)

    idx = None
    for i, (b, e) in enumerate(funcs):
        if b <= 0x017A77AC < e:
            idx = i
            break
    print("pdata around 0x017A77AC idx", idx)
    if idx is not None:
        for j in range(max(0, idx - 6), min(len(funcs), idx + 8)):
            b, e = funcs[j]
            mark = " <<<" if j == idx else ""
            print(f"  [{j}] [0x{b:08x},0x{e:08x}) len={e-b}{mark}")
            print("     ", hexdump(data, sections, b, 18))
            xr = xrefs_fn(data, sections, b, 6)
            if xr:
                print("      vt", xr)

    # walk back from 0x017A77AC looking for function-like prologue
    print("\nprologues before 0x017A77AC")
    for rva in range(0x017A7000, 0x017A77B0, 1):
        off = rva_to_off(sections, rva)
        b = data[off : off + 4]
        if b[:3] == b"\x48\x8B\xC4" or b[:2] == b"\x40\x53" or b[:3] == b"\x48\x89\x5C":
            if data[off] == 0x48 and data[off + 1] == 0x89 and data[off + 2] == 0x5C:
                print(hex(rva), hexdump(data, sections, rva, 16))

    print("\n== area defense / assign / execute LEA ==")
    for rtti in (
        b".?AVCCreateAreaDefenseCommand@@",
        b".?AVCEditAreaDefenseStateCommand@@",
        b".?AVCSetAreaDefenseSettingCommand@@",
        b".?AVCOrderExecuteCommand@@",
        b".?AVCOrderNewFrontCommand@@",
        b".?AVCArmyGroupCommand@@",
        b".?AVCAssignToArmyGroupCommand@@",
        b".?AVCAssignToTheaterGroupCommand@@",
        b".?AVCOrderAssignCommand@@",
    ):
        vts = find_vt(data, sections, rtti)
        print(f"{rtti.decode()} {[hex(x) for x in vts[:2]]}")
        if not vts:
            continue
        for lea in lea_to(data, sections, vts[0], 16):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            xr = xrefs_fn(data, sections, pfn[0], 4) if pfn else []
            print(f"  LEA 0x{lea:08x} {fns} {hexdump(data, sections, max(0, lea-8), 24)}")
            if xr:
                print(f"      ctor-fn vt {xr}")

    print("\nCFront/COrdersGroup/CTheatre/CArmyGroup slots 0-30")
    for name, vt in (
        ("CFront", 0x0294EE20),
        ("COrdersGroup", 0x0292BEC0),
        ("CTheatre", 0x0294ED28),
        ("CArmyGroup", 0x0292BF58),
        ("CTheaterGroup", 0x029BE6C0),
    ):
        off = rva_to_off(sections, vt)
        print(name)
        for i in range(32):
            va = struct.unpack_from("<Q", data, off + i * 8)[0]
            if not (IB <= va < IB + 0x4000000):
                continue
            rva = va - IB
            pfn = fn_for(funcs, rva)
            if pfn and pfn[0] <= 0x017A77FB < pfn[1]:
                print(f"  [{i}] 0x{rva:08x} CONTAINS exec caller")
            if pfn and pfn[0] <= 0x00F3B2F0 < pfn[1]:
                print(f"  [{i}] 0x{rva:08x} CONTAINS exec helper")
            if 0x017A7000 <= rva <= 0x017A8000:
                print(f"  [{i}] 0x{rva:08x} in 0x17A7xxx {hexdump(data, sections, rva, 12)}")


if __name__ == "__main__":
    main()
