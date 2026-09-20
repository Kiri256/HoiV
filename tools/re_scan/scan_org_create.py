#!/usr/bin/env python3
"""Pin remaining theater/AG posters after helper skip. No factory hooks."""

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


def dump_calls_in(data, sections, begin, end, label):
    print(f"\n== {label} [0x{begin:08x},0x{end:08x}) size={end-begin}")
    print("  prologue", hexdump(data, sections, begin, 24))
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 6):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
            print(f"  call 0x{begin + i:08x} -> 0x{tgt:08x}")


def nearby_strings(data, sections, rva, radius=0x400):
    off = rva_to_off(sections, rva)
    window = data[max(0, off - radius) : off + radius]
    found = []
    i = 0
    while i < len(window) - 8:
        if 32 <= window[i] < 127:
            j = i
            while j < len(window) and 32 <= window[j] < 127:
                j += 1
            s = window[i:j]
            if len(s) >= 8 and (b"Theatre" in s or b"Theater" in s or b"Army" in s or b"Front" in s or b"AI" in s):
                found.append(s.decode("latin1", "replace"))
            i = j + 1
        else:
            i += 1
    return found[:12]


def callers(data, sections, funcs, target, label, n=20):
    hits = calls_to(data, sections, target)
    print(f"\n== {label} 0x{target:08x} callers={len(hits)}")
    print("  prologue", hexdump(data, sections, target, 18))
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} {fns}")
        print(f"       {hexdump(data, sections, max(0, rva - 12), 36)}")


def vt_slots(data, sections, vt, n=12):
    off = rva_to_off(sections, vt)
    out = []
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        out.append(va - IB if IB <= va < IB + 0x4000000 else None)
    return out


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)

    commands = {
        "CSetTheatreCommand": 0x0298A870,
        "CArmyGroupCommand": 0x029E3500,
        "COrderNewFrontCommand": 0x029E4180,
        "CAssignToArmyGroupCommand": 0x029E35C8,
        "CAssignToTheaterGroupCommand": 0x02A0AE00,
    }
    print("command [9]/[10]")
    for name, vt in commands.items():
        slots = vt_slots(data, sections, vt)
        print(f"  {name} [9]={hex(slots[9]) if slots[9] else '?'} [10]={hex(slots[10]) if slots[10] else '?'}")
        if slots[9]:
            print(f"    [9] bytes {hexdump(data, sections, slots[9], 16)}")
        if slots[10]:
            print(f"    [10] bytes {hexdump(data, sections, slots[10], 16)}")

    callers(data, sections, funcs, 0x01355120, "CSetTheatre factory 0x01355120")
    callers(data, sections, funcs, 0x0105CCE0, "AG ctor parent 0x0105CCE0")
    callers(data, sections, funcs, 0x00247630, "AG factory AI 0x00247630")

    pfn = fn_for(funcs, 0x0105CCE0)
    if pfn:
        dump_calls_in(data, sections, pfn[0], pfn[1], "0x0105CCE0 body")
        print("  nearby", nearby_strings(data, sections, pfn[0]))

    pfn = fn_for(funcs, 0x010B4620)
    if pfn:
        dump_calls_in(data, sections, pfn[0], min(pfn[1], pfn[0] + 0x800), "helper first 0x800")

    # RTTI names containing Theatre/Theater create
    print("\n== RTTI theatre/armygroup command/action ==")
    start = 0
    while True:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        low = name.lower()
        if any(k in low for k in ("theatre", "theater", "armygroup", "newfront", "newarmy")):
            print(f"  {name}")
        start = i + 1

    # strings used by helper / create
    print("\n== strings ==")
    for s in (
        b"CSetTheatreCommand",
        b"create_theatre",
        b"CreateTheatre",
        b"NArmyGroup",
        b"new army group",
    ):
        idx = data.find(s)
        print(f"  {s!r} {'found' if idx>=0 else 'missing'}")


if __name__ == "__main__":
    main()
