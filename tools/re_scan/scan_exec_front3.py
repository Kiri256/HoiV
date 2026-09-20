#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import struct

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
    raw = data[tdo + 16 : data.find(b"\0", tdo + 16)]
    return raw.decode("latin1", "replace")


def xrefs_fn(data, sections, fn_rva):
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
                # count slot from nearest preceding col pointer? not reliable
        hits.append((vr, name))
        p = i + 8
        if len(hits) >= 20:
            break
    return hits


def dump_body_calls(data, sections, begin, end):
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountryTagish",
        0x006C2400: "GetAI",
        0x00EE10B0: "AG factory",
        0x00EEE3A0: "front factory",
        0x0181DA50: "Execute ctor",
        0x0181E620: "NewFront ctor",
        0x0029E7B0: "post",
        0x01A21B10: "exec poster",
        0x01A23290: "newfront poster",
        0x01A5BF00: "vol exec helper",
        0x0105CCE0: "AG poster",
        0x01058380: "AG parent",
        0x01081FE0: "gen org walk",
        0x00ED9F40: "CTheatre ctor",
        0x00EEA3E0: "theatre AI",
        0x01827540: "AGCommand[10]",
        0x0181B3E0: "AGCommand ctor",
        0x0181BB10: "AssignAG ctor",
        0x01A31660: "move list",
        0x00F3EAE0: "idler exec",
        0x00F41450: "newfront helper",
        0x00F3B2F0: "exec helper",
        0x00247630: "AG factory AI",
    }
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8 and blob[i] != 0xE9:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  {'call' if blob[i]==0xE8 else 'jmp'} 0x{begin+i:08x} -> 0x{tgt:08x} {interesting[tgt]}")


def slot_of(data, sections, vt, fn_rva, n=80):
    off = rva_to_off(sections, vt)
    if off is None:
        return None
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if va == IB + fn_rva:
            return i
    return None


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)

    print("== 0x00247630 xrefs ==")
    for vr, name in xrefs_fn(data, sections, 0x00247630):
        print(f"  {hex(vr) if vr else vr} {name}")
    pfn = fn_for(funcs, 0x00247630)
    print("pdata", pfn and (hex(pfn[0]), hex(pfn[1])))
    print("pro", hexdump(data, sections, 0x00247630, 32))
    if pfn:
        dump_body_calls(data, sections, pfn[0], pfn[1])
    print("first 80", hexdump(data, sections, 0x00247630, 80))

    print("\n== 0x01059D36 ==")
    pfn = fn_for(funcs, 0x01059D36)
    print("pdata", pfn and (hex(pfn[0]), hex(pfn[1])))
    if pfn:
        print("pro", hexdump(data, sections, pfn[0], 24))
        dump_body_calls(data, sections, pfn[0], pfn[1])
        print("xrefs", [(hex(a) if a else a, b) for a, b in xrefs_fn(data, sections, pfn[0])])
        hits = calls_to(data, sections, pfn[0])
        print("callers", len(hits))
        for site, kind in hits[:16]:
            pf = fn_for(funcs, site)
            print(f"  {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))}")

    for rva, label in (
        (0x017A77AC, "exec caller A"),
        (0x017A7D8C, "exec caller B"),
        (0x00F3B2F0, "exec helper"),
        (0x01A21B10, "exec poster"),
        (0x01A23290, "newfront poster"),
        (0x01828E80, "newfront helper"),
        (0x00F41450, "idler newfront helper"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n== {label} 0x{rva:08x} {None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  pro", hexdump(data, sections, rva if pfn is None else pfn[0], 20))
        print("  xrefs", [(hex(a) if a else a, b) for a, b in xrefs_fn(data, sections, pfn[0] if pfn else rva)])
        if pfn:
            dump_body_calls(data, sections, pfn[0], pfn[1])

    known_vts = [
        ("CCountryAI", 0x02710C90, 220),
        ("CAIMilitaryMinister", 0x02962938, 50),
        ("CAIGeneral", 0x029613D0, 50),
        ("CFront", 0x0294EE20, 50),
        ("CArmyGroup", 0x0292BF58, 50),
        ("CTheatre", 0x0294ED28, 50),
        ("COrdersGroup", 0x0292BEC0, 50),
        ("CTheaterGroup", 0x029BE6C0, 50),
        ("CInGameIdler", 0x02942480, 30),
        ("CCountry", 0x027C0E80, 80),
    ]
    print("\n== slot search ==")
    for fn in (0x00247630, 0x01059D36, 0x01059D00, 0x00F3B2F0, 0x01A21B10, 0x01A23290, 0x017A77AC):
        pfn = fn_for(funcs, fn)
        start = pfn[0] if pfn else fn
        for name, vt, n in known_vts:
            s = slot_of(data, sections, vt, start, n)
            if s is not None:
                print(f"  {name}[{s}] = 0x{start:08x}")


if __name__ == "__main__":
    main()
