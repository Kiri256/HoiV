#!/usr/bin/env python3
"""Pin CAIVolunteerGeneral and player theatre/AG/army create commands."""

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
            print(f"  [{i:3d}] {hex(va)}")
            continue
        rva = va - ib
        o = rva_to_off(sections, rva)
        desc = describe_getter(data[o : o + 12]) or hexdump(data, sections, rva, 12)
        print(f"  [{i:3d}] 0x{rva:08x} {desc}")


def rtti_names(data, needles):
    seen = []
    start = 0
    while len(seen) < 80:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end]
        low = name.lower()
        if any(x in low for x in needles) and name not in seen and b"lambda" not in name:
            seen.append(name)
        start = i + 1
    return seen


def dump_calls(data, sections, funcs, target, label, n=16):
    hits = calls_to(data, sections, target)
    print(f"\n== {label} 0x{target:08x} callers={len(hits)}")
    print("  prologue", hexdump(data, sections, target, 24))
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} fn={fns} {hexdump(data, sections, max(0, rva - 16), 40)}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)

    print("== volunteer / org RTTI ==")
    names = rtti_names(
        data,
        (
            b"volunteer",
            b"theatre",
            b"theater",
            b"armygroup",
            b"createarmy",
            b"createfront",
            b"createtheatre",
            b"createtheater",
            b"assignarmy",
            b"newarmy",
            b"newfront",
            b"expedition",
            b"sendvol",
        ),
    )
    for name in names:
        vts = find_vt(data, ib, sections, name)
        print(f"  {name.decode('latin1')} {[hex(x) for x in vts[:4]]}")

    vol_vts = find_vt(data, ib, sections, b".?AVCAIVolunteerGeneral@@")
    print("\nCAIVolunteerGeneral", [hex(x) for x in vol_vts])
    if vol_vts:
        dump_vt(data, ib, sections, "CAIVolunteerGeneral", vol_vts[0], 24)
        off = rva_to_off(sections, vol_vts[0])
        slot14 = struct.unpack_from("<Q", data, off + 14 * 8)[0] - ib
        slot13 = struct.unpack_from("<Q", data, off + 13 * 8)[0] - ib
        print(f"  [13]={hex(slot13)} [14]={hex(slot14)}")
        dump_calls(data, sections, funcs, slot14, "CAIVolunteerGeneral[14]")
        dump_calls(data, sections, funcs, 0x01A5BF00, "known volunteer exec 0x01A5BF00")

    dump_calls(data, sections, funcs, 0x00EEE3A0, "CFront factory")
    dump_calls(data, sections, funcs, 0x00EE10B0, "CArmyGroup factory")

    theatre_vts = find_vt(data, ib, sections, b".?AVCTheatre@@")
    if theatre_vts:
        dump_vt(data, ib, sections, "CTheatre", theatre_vts[0], 20)
        print("\nLEA CTheatre vt")
        for lea in lea_to(data, sections, theatre_vts[0], 12):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  0x{lea:08x} fn={fns} {hexdump(data, sections, max(0, lea - 24), 48)}")

    print("\n== command names containing Theatre/ArmyGroup/Volunteer/CreateArmy ==")
    start = 0
    shown = 0
    while shown < 60:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        if "Command" in name and any(
            x in name
            for x in (
                "Theatre",
                "Theater",
                "ArmyGroup",
                "Volunteer",
                "CreateArmy",
                "CreateFront",
                "NewArmy",
                "AssignArmy",
                "CreateOrder",
                "CreateGroup",
            )
        ):
            vts = find_vt(data, ib, sections, data[i:end])
            print(f"  {name} {[hex(x) for x in vts[:2]]}")
            shown += 1
        start = i + 1

    print("\n== 0x01A31660 callers beyond known general ==")
    dump_calls(data, sections, funcs, 0x01A31660, "army-list mover")


if __name__ == "__main__":
    main()
