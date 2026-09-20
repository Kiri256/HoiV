#!/usr/bin/env python3
"""Identify every command 0x002AB450 posts. That skip may be killing research."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
IB_SPAN = 0x4000000
MASS = 0x002AB450
MASS_END = 0x002ABDF3


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


def col_name(data, ib, sections, slot_rva):
    for back in range(0, 64):
        vt = slot_rva - back * 8
        off = rva_to_off(sections, vt)
        if off is None or off < 8:
            continue
        col = struct.unpack_from("<Q", data, off - 8)[0]
        if not (ib <= col < ib + IB_SPAN):
            continue
        col_off = rva_to_off(sections, col - ib)
        if col_off is None:
            continue
        if struct.unpack_from("<I", data, col_off)[0] != 1:
            continue
        td_rva = struct.unpack_from("<I", data, col_off + 12)[0]
        name_off = rva_to_off(sections, td_rva + 16)
        if name_off is None:
            continue
        end = data.find(b"\0", name_off, name_off + 90)
        if end < 0:
            continue
        name = data[name_off:end]
        if name.startswith(b".?AV"):
            return name.decode("latin1"), back, vt
    return "?", -1, 0


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


def name_from_lea_site(data, ib, sections, site):
    off = rva_to_off(sections, site)
    if off is None or data[off] != 0x48 or data[off + 1] != 0x8D:
        return None
    rel = struct.unpack_from("<i", data, off + 3)[0]
    vt = (site + 7 + rel) & 0xFFFFFFFF
    name, slot, base = col_name(data, ib, sections, vt)
    return name, vt, slot, base


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)

    print("== LEA in mass body (command vtables) ==")
    raw0 = rva_to_off(sections, MASS)
    blob = data[raw0 : raw0 + (MASS_END - MASS)]
    for i in range(len(blob) - 7):
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            site = MASS + i
            vt = (site + 7 + rel) & 0xFFFFFFFF
            name, slot, base = col_name(data, ib, sections, vt)
            if name.startswith(".?AV"):
                print(f"  0x{site:08x} lea 0x{vt:08x} {name} slot={slot} vt={hex(base)}")

    print("\n== named command ctors near mass E8s ==")
    for rva, label in (
        (0x0134FDA0, "0x0134FDA0"),
        (0x013366A0, "0x013366A0"),
        (0x01137A50, "0x01137A50"),
        (0x021AA4D0, "0x021AA4D0"),
        (0x025650E0, "0x025650E0"),
        (0x00155810, "0x00155810"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n{label} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print(" ", hexdump(data, sections, rva, 24))
        start = pfn[0] if pfn else rva
        stop = pfn[1] if pfn else rva + 80
        off = rva_to_off(sections, start)
        b = data[off : off + min(120, stop - start)]
        for i in range(len(b) - 7):
            if b[i] == 0x48 and b[i + 1] == 0x8D and b[i + 2] in (0x05, 0x0D, 0x15, 0x1D):
                rel = struct.unpack_from("<i", b, i + 3)[0]
                site = start + i
                vt = (site + 7 + rel) & 0xFFFFFFFF
                name, slot, base = col_name(data, ib, sections, vt)
                if name.startswith(".?AV"):
                    print(f"  lea 0x{site:08x} -> 0x{vt:08x} {name}")

    print("\n== CMassMoveCommand / research command RTTI ==")
    start = 0
    n = 0
    while n < 40:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end]
        low = name.lower()
        if b"Command@@" in name and any(
            x in low
            for x in (
                b"mass",
                b"research",
                b"tech",
                b"science",
                b"doctrine",
                b"focus",
                b"production",
                b"construct",
            )
        ):
            vts = find_vt(data, ib, sections, name)
            print(f"  {name.decode('latin1')} {[hex(x) for x in vts[:2]]}")
            n += 1
        start = i + 1

    print("\n== CAIInteriorMinister / Political [14] ==")
    for name, expect in (
        (b".?AVCAIInteriorMinister@@", 0x029842D0),
        (b".?AVCAIPoliticalMinister@@", 0x02984FD0),
        (b".?AVCAIForeignMinister@@", 0x02983B58),
        (b".?AVCAIMilitaryMinister@@", 0x02962938),
        (b".?AVCAIBaseGeneral@@", 0x029F7868),
        (b".?AVCAIResearchNeed@@", 0x027BB890),
        (b".?AVCAIModule@@", 0x02AD0798),
        (b".?AVCAICore@@", 0x02AD0640),
    ):
        vts = find_vt(data, ib, sections, name)
        print(f"\n{name.decode()} { [hex(x) for x in vts[:2]] }")
        if not vts:
            continue
        vt = vts[0]
        off = rva_to_off(sections, vt)
        for i in (13, 14, 15, 16):
            va = struct.unpack_from("<Q", data, off + i * 8)[0]
            rva = va - ib if ib <= va < ib + IB_SPAN else 0
            print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 10) if rva else ''}")


if __name__ == "__main__":
    main()
