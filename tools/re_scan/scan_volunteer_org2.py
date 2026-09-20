#!/usr/bin/env python3
"""Pin volunteer owner, send-volunteer, and land org command ctors."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, describe_getter, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
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


def dump_vt(data, ib, sections, name, vt, n=24):
    print(f"\n{name} vt 0x{vt:08x}")
    off = rva_to_off(sections, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + IB_SPAN):
            continue
        rva = va - ib
        o = rva_to_off(sections, rva)
        desc = describe_getter(data[o : o + 12]) or hexdump(data, sections, rva, 12)
        print(f"  [{i:3d}] 0x{rva:08x} {desc}")


def dump_calls(data, sections, funcs, target, label, n=12):
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
        print(f"       {hexdump(data, sections, max(0, rva - 20), 44)}")


def lea_sites(data, sections, funcs, vt, label, n=10):
    print(f"\nLEA {label} 0x{vt:08x}")
    for lea in lea_to(data, sections, vt, n):
        pfn = fn_for(funcs, lea)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  0x{lea:08x} fn={fns} {hexdump(data, sections, max(0, lea - 16), 40)}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)

    dump_vt(data, ib, sections, "CAIGeneral", 0x029613D0, 20)
    dump_vt(data, ib, sections, "CAIVolunteerGeneral", 0x02A0A7B0, 8)

    print("\nCAIVolunteerGeneral[1] +0x30 getter", hexdump(data, sections, 0x006C29C0, 8))
    print("CAIVolunteerGeneral[14] window")
    print(" ", hexdump(data, sections, 0x01A5D160, 80))
    print("CAIVolunteerGeneral[13]")
    print(" ", hexdump(data, sections, 0x01A5E2D0, 48))
    print("0x01A5BF00 window")
    print(" ", hexdump(data, sections, 0x01A5BF00, 64))

    lea_sites(data, sections, funcs, 0x02A0A7B0, "CAIVolunteerGeneral vt")
    lea_sites(data, sections, funcs, 0x029613D0, "CAIGeneral vt")

    dump_calls(data, sections, funcs, 0x00247630, "AG factory AI caller fn")
    dump_calls(data, sections, funcs, 0x01827540, "AG factory UI-ish caller fn")
    dump_calls(data, sections, funcs, 0x00EF26B0, "CTheatre[2]")
    dump_calls(data, sections, funcs, 0x00EEE3A0, "CTheatre[4]/front factory")

    print("\n== land org / army / volunteer command RTTI ==")
    start = 0
    shown = 0
    keys = (
        "ArmyCommand",
        "CreateArmy",
        "AssignArmy",
        "AssignToArmy",
        "NewArmy",
        "CreateGroup",
        "CreateFront",
        "CreateTheatre",
        "CreateTheater",
        "SetTheatre",
        "SetTheater",
        "ArmyGroup",
        "Volunteer",
        "Expedition",
        "TheaterGroup",
        "TheatreGroup",
        "CreateOrder",
        "NewFront",
        "NewTheatre",
        "NewTheater",
        "AssignToFront",
        "AssignToTheatre",
        "AssignToTheater",
        "CreateHQ",
        "ArmyHq",
        "ArmyHQ",
    )
    while shown < 80:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        if "Command" in name or name.endswith("Action@@"):
            if any(k.lower() in name.lower() for k in keys):
                vts = find_vt(data, ib, sections, data[i:end])
                print(f"  {name} {[hex(x) for x in vts[:2]]}")
                shown += 1
        start = i + 1

    for label, vt in (
        ("CSetTheatreCommand", 0x0298A870),
        ("CArmyGroupCommand", 0x029E3500),
        ("CAssignToArmyGroupCommand", 0x029E35C8),
        ("CAssignToTheaterGroupCommand", 0x02A0AE00),
        ("CSendVolunteerAction", 0x029664D8),
        ("CSendExpeditionaryForceAction", 0x029666F8),
    ):
        dump_vt(data, ib, sections, label, vt, 12)
        lea_sites(data, sections, funcs, vt, label + " vt", 6)


if __name__ == "__main__":
    main()
