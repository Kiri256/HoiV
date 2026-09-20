#!/usr/bin/env python3
"""Theatre generation after observe: who posts CSetTheatre when AI takes the country."""

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


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


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


def dump_calls(data, sections, funcs, target, label, n=16):
    hits = calls_to(data, sections, target)
    print(f"\n== {label} 0x{target:08x} callers={len(hits)}")
    print("  prologue", hexdump(data, sections, target, 20))
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    print("CSetTheatre factory", hexdump(data, sections, 0x01355120, 80))
    print("CSetTheatre ctor", hexdump(data, sections, 0x01353520, 64))
    print("CSetTheatre[10]", hexdump(data, sections, 0x013576C0, 48))
    print("0x00EEA3E0", hexdump(data, sections, 0x00EEA3E0, 40))

    dump_calls(data, sections, funcs, 0x00EEA3E0, "theatre parent 0x00EEA3E0")
    dump_calls(data, sections, funcs, 0x013576C0, "CSetTheatre[10]")
    dump_calls(data, sections, funcs, 0x00ED9F40, "CTheatre ctor A")
    dump_calls(data, sections, funcs, 0x00B9B6E0, "IsHumanControlled 0x00B9B6E0")

    print("\n== RTTI theatre AI / strategic ==")
    start = 0
    while True:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        if any(
            k in name
            for k in (
                "TheatreAI",
                "TheaterAI",
                "StrategicAI",
                "CAITheatre",
                "CTheatreAI",
                "TheatreGenerator",
            )
        ) and "DefineRegistry" not in name:
            vts = find_vt(data, ib, sections, data[i:end])
            print(f"  {name} {[hex(x) for x in vts[:4]]}")
        start = i + 1

    print("\n== strings ==")
    raw0, raw1, _ = text_range(sections)
    for s in (
        b"THEATRE_GENERATION",
        b"NAITheatreAI",
        b"generate_theatre",
        b"GenerateTheatre",
        b"CSetTheatreCommand",
        b"observe",
        b"tagobserve",
    ):
        idx = 0
        found = 0
        while found < 5:
            j = data.find(s, idx)
            if j < 0:
                if found == 0:
                    print(f"  {s!r} missing")
                break
            rva = off_to_rva(sections, j)
            print(f"  {s!r} file={j} rva={hex(rva) if rva else None} {data[j:j+60]!r}")
            if rva and rva >= 0x1000:
                for lea in lea_to(data, sections, rva, 6):
                    pfn = fn_for(funcs, lea)
                    print(f"    lea 0x{lea:08x} {None if not pfn else hex(pfn[0])}")
            idx = j + 1
            found += 1

    # CCountryAI slots that look like theatre (0x00EDxxxx / 0x00EExxxx / 0x010Bxxxx)
    print("\nCCountryAI theatre-ish slots")
    off = rva_to_off(sections, 0x02710C90)
    for i in range(200):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            continue
        rva = va - IB
        if 0x00ED0000 <= rva <= 0x00F00000 or rva in (0x010B4620, 0x010ABA70, 0x0107D9C0):
            print(f"  [{i:3d}] 0x{rva:08x}")

    print("\nminister slots 0-20")
    off = rva_to_off(sections, 0x02962938)
    for i in range(20):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if IB <= va < IB + 0x4000000:
            print(f"  [{i:3d}] 0x{va-IB:08x}")


if __name__ == "__main__":
    main()
