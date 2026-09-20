#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

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
                if vr is not None and vr >= (col - IB + 8):
                    slot = (vr - (col - IB + 8)) // 8
        hits.append((hex(vr) if vr else vr, name, slot))
        p = i + 8
        if len(hits) >= 16:
            break
    return hits


def slot_search(data, sections, fn):
    vts = [
        ("CAIGeneral", 0x029613D0, 40),
        ("CAIVolunteerGeneral", 0x02A0A7B0, 40),
        ("CAIMilitaryMinister", 0x02962938, 40),
        ("CCountryAI", 0x02710C90, 200),
        ("CFront", 0x0294EE20, 40),
        ("CArmyGroup", 0x0292BF58, 40),
        ("CTheatre", 0x0294ED28, 40),
        ("COrdersGroup", 0x0292BEC0, 40),
        ("CInGameIdler", 0x02942480, 20),
    ]
    for name, vt, n in vts:
        off = rva_to_off(sections, vt)
        for i in range(n):
            va = struct.unpack_from("<Q", data, off + i * 8)[0]
            if va == IB + fn:
                print(f"  {name}[{i}]")


def dump_calls(data, sections, begin, end):
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry2",
        0x006C2400: "GetAI",
        0x01077350: "?",
        0x0029E7B0: "post",
        0x0181BE40: "CreateAreaDef",
        0x0181C020: "EditAreaDef",
        0x0181C140: "EditAreaDef2",
        0x01820660: "SetAreaDef",
        0x0181DA50: "Execute ctor",
        0x0181B3E0: "AG ctor",
        0x0181BB10: "AssignAG",
        0x0181E620: "NewFront",
        0x0105CCE0: "AG poster",
        0x01058380: "AG parent",
        0x01081FE0: "gen walk",
        0x01A31660: "move",
        0x01A2ED80: "per-army move",
        0x00F3EAE0: "idler",
        0x00F3B2F0: "exec helper",
        0x01086CB0: "gen helper",
        0x0107AFB0: "HQ",
        0x0107D190: "redeploy",
    }
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x} {interesting[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for rva, label in (
        (0x01085E00, "area def poster"),
        (0x01086CB0, "gen helper 86CB0"),
        (0x0105C430, "AG poster parent"),
        (0x0105CCE0, "AG poster"),
        (0x01A34190, "AssignAG bulk"),
        (0x017ABD70, "AssignAG 17ABD70"),
        (0x0186FFB0, "AssignAG UI?"),
        (0x01E4D340, "AssignAG late"),
        (0x0107D9C0, "CAIGeneral[13]"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n==== {label} 0x{rva:08x} {None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  pro", hexdump(data, sections, rva if not pfn else pfn[0], 24))
        print("  xrefs", xrefs_fn(data, sections, pfn[0] if pfn else rva))
        slot_search(data, sections, pfn[0] if pfn else rva)
        if pfn:
            dump_calls(data, sections, pfn[0], pfn[1])
        hits = calls_to(data, sections, pfn[0] if pfn else rva)
        print(f"  callers={len(hits)}")
        for site, kind in hits[:12]:
            pf = fn_for(funcs, site)
            print(f"    {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))}")


if __name__ == "__main__":
    main()
