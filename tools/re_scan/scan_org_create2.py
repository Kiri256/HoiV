#!/usr/bin/env python3
"""Identify 0x0105CCE0 / theater factory refs. No product hooks here."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

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


def rtti_at(data, sections, col_rva):
    off = rva_to_off(sections, col_rva)
    if off is None or off + 16 > len(data):
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdoff = rva_to_off(sections, td)
    if tdoff is None:
        return f"td=0x{td:x}"
    end = data.find(b"\0", tdoff + 16)
    return data[tdoff + 16 : end].decode("latin1", "replace")


def vtables_with(data, sections, fn_rva, limit=8):
    q = struct.pack("<Q", IB + fn_rva)
    hits = []
    start = 0
    while len(hits) < limit:
        p = data.find(q, start)
        if p < 0:
            break
        vr = off_to_rva(sections, p)
        if vr:
            col = None
            if p >= 8:
                col_va = struct.unpack_from("<Q", data, p - 8)[0]
                if IB <= col_va < IB + 0x4000000:
                    col = col_va - IB
            name = rtti_at(data, sections, col) if col else "?"
            slot = None
            # scan back for col qword then count
            hits.append((vr, name, col))
        start = p + 1
    return hits


def rip_to(data, sections, target):
    raw0, raw1, _ = text_range(sections)
    hits = []
    for off in range(raw0, raw1 - 7):
        # E8/E9 already known
        # LEA r64, [rip+disp] 48 8d r/m
        if data[off] == 0x48 and data[off + 1] == 0x8D and (data[off + 2] & 0xC7) == 0x05:
            rel = struct.unpack_from("<i", data, off + 3)[0]
            rva = off_to_rva(sections, off)
            if rva is not None and rva + 7 + rel == target:
                hits.append(("lea", rva))
        # CALL/JMP rel32 already
        # FF 15 disp32  call [rip]
        if data[off] == 0xFF and data[off + 1] in (0x15, 0x25):
            rel = struct.unpack_from("<i", data, off + 2)[0]
            rva = off_to_rva(sections, off)
            if rva is not None and rva + 6 + rel == target:
                hits.append(("ff", rva))
        # mov r64, [rip] 48 8b 05
        if data[off] == 0x48 and data[off + 1] == 0x8B and data[off + 2] in (0x05, 0x0D, 0x15):
            rel = struct.unpack_from("<i", data, off + 3)[0]
            rva = off_to_rva(sections, off)
            if rva is not None and rva + 7 + rel == target:
                hits.append(("mov", rva))
    return hits


def dump_fn(data, sections, funcs, rva, n=48):
    pfn = fn_for(funcs, rva)
    print(f"\nfn 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
    print(" ", hexdump(data, sections, rva, n))


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for fn in (
        0x0105CCE0,
        0x0105C430,
        0x0105C529,
        0x01298590,
        0x0181C890,
        0x0181DB50,
        0x0181D940,
        0x00F41450,
        0x01494DB0,
        0x01A23290,
    ):
        dump_fn(data, sections, funcs, fn, 32)
        print("  vt hits:")
        for vr, name, col in vtables_with(data, sections, fn):
            print(f"    ptr@0x{vr:08x} col=0x{col or 0:08x} {name}")

    print("\nRIP/LEA to CSetTheatre factory 0x01355120")
    for kind, rva in rip_to(data, sections, 0x01355120)[:20]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")

    print("\nRIP/LEA to CSetTheatre ctor 0x01353520")
    for kind, rva in rip_to(data, sections, 0x01353520)[:20]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")

    print("\ncallers of 0x0105C430")
    hits = calls_to(data, sections, 0x0105C430)
    print(" count", len(hits))
    for rva, kind in hits[:12]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")
        for vr, name, col in vtables_with(data, sections, pfn[0] if pfn else rva):
            print(f"    parent vt ptr@0x{vr:08x} {name}")

    print("\ncallers of 0x01298590")
    hits = calls_to(data, sections, 0x01298590)
    print(" count", len(hits))
    for rva, kind in hits[:16]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")

    # CSetTheatreCommand[9] first 64 bytes — tag offset
    print("\nCSetTheatre[9] 0x0135AF40")
    print(" ", hexdump(data, sections, 0x0135AF40, 64))
    print("CArmyGroup[9] 0x01831B90")
    print(" ", hexdump(data, sections, 0x01831B90, 48))
    print("CAssignAG[9] 0x01831D40")
    print(" ", hexdump(data, sections, 0x01831D40, 48))
    print("CNewFront[9] 0x01832DA0")
    print(" ", hexdump(data, sections, 0x01832DA0, 48))

    print("\n0x0105CCE0 first 80")
    print(" ", hexdump(data, sections, 0x0105CCE0, 80))
    print("0x0105C430 first 64")
    print(" ", hexdump(data, sections, 0x0105C430, 64))


if __name__ == "__main__":
    main()
