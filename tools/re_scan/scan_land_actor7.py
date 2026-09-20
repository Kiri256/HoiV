#!/usr/bin/env python3
"""Dispatch of CCountryAI[145], Update calls, minister[14] commands."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IB_SPAN = 0x4000000
CAI_VT = 0x02710C90
MASS_THUNK = 0x002A7DE0
MASS_FN = 0x002AB450
UPDATE = 0x002ACF30
MIN14 = 0x010ABA70


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


def find_qword(data, ib, sections, fn_rva):
    needle = struct.pack("<Q", ib + fn_rva)
    hits = []
    for name, va, _vs, raw, raw_size in sections:
        off = raw
        end = raw + raw_size
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            hits.append((name.decode("latin1", "replace").rstrip("\x00"), off_to_rva(sections, i)))
            off = i + 8
    return hits


def vt_near(vt_map, slot_rva):
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x800:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def rel_calls(data, sections, start, stop):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    out = []
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        out.append((start + i, (start + i + 5 + rel) & 0xFFFFFFFF))
    return out


def slot(data, ib, sections, vt, i):
    off = rva_to_off(sections, vt + i * 8)
    va = struct.unpack_from("<Q", data, off)[0]
    return va - ib if ib <= va < ib + IB_SPAN else 0


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    print("== qword refs to mass-move thunk/fn ==")
    for fn in (MASS_THUNK, MASS_FN, UPDATE, 0x002A7DFA):
        print(f"\nVA 0x{ib + fn:x} rva 0x{fn:08x}")
        for sec, rva in find_qword(data, ib, sections, fn):
            info = vt_near(vt_map, rva)
            print(f"  {sec} 0x{rva:08x} {info}")

    print("\n== CCountryAI slots 130-155 ==")
    for i in range(130, 156):
        rva = slot(data, ib, sections, CAI_VT, i)
        print(f"  [{i:3d}] +0x{i * 8:03x} 0x{rva:08x} {hexdump(data, sections, rva, 12) if rva else ''}")

    print("\n== CCountryAI Update calls ==")
    print(hexdump(data, sections, UPDATE, 96))
    fn = fn_for(funcs, UPDATE)
    print("pdata", None if not fn else (hex(fn[0]), hex(fn[1])))
    if fn:
        for site, tgt in rel_calls(data, sections, fn[0], fn[1]):
            pfn = fn_for(funcs, tgt)
            extra = ""
            if pfn:
                for _sec, q in find_qword(data, ib, sections, pfn[0])[:3]:
                    info = vt_near(vt_map, q)
                    if info:
                        extra = f" {info[1]}[{info[2]}]"
                        break
            print(f"  0x{site:08x} -> 0x{tgt:08x}{extra}")

    print("\n== minister[14] all calls ==")
    mfn = fn_for(funcs, MIN14)
    if mfn:
        for site, tgt in rel_calls(data, sections, mfn[0], mfn[1]):
            pfn = fn_for(funcs, tgt)
            print(f"  0x{site:08x} -> 0x{tgt:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}")
            print("   ", hexdump(data, sections, max(0, site - 12), 28))

    print("\n== hourly / process AI strings ==")
    for k in (
        b"DoCountryHourlyUpdates",
        b"ProcessAIHourlyUpdate",
        b"UpdateTheaters",
        b"UpdateFronts",
        b"HandleAiMicroAttacks",
    ):
        offs = find_cstr(data, k)
        print(k, [hex(off_to_rva(sections, x) or 0) for x in offs[:3]])
        if offs:
            rva = off_to_rva(sections, offs[0])
            for lea in lea_to(data, sections, rva, 6):
                print("  lea", hex(lea), hexdump(data, sections, max(0, lea - 24), 40))

    print("\n== 0x016c3360 vtable membership + first calls ==")
    print(hexdump(data, sections, 0x016C3360, 80))
    sfn = fn_for(funcs, 0x016C3360)
    if sfn:
        for site, tgt in rel_calls(data, sections, sfn[0], sfn[1]):
            print(f"  0x{site:08x} -> 0x{tgt:08x}")
        raw0, raw1, _ = text_range(sections)
        # also search rip lea to this function? skip
        for _sec, q in find_qword(data, ib, sections, sfn[0]):
            print("  qword", hex(q), vt_near(vt_map, q))

    print("\n== callers of CCountryAI Update ==")
    for rva, kind in calls_to(data, sections, UPDATE)[:20]:
        pfn = fn_for(funcs, rva)
        extra = ""
        if pfn:
            for _sec, q in find_qword(data, ib, sections, pfn[0])[:2]:
                info = vt_near(vt_map, q)
                if info:
                    extra = f" {info[1]}[{info[2]}]"
                    break
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}{extra}")


if __name__ == "__main__":
    main()
