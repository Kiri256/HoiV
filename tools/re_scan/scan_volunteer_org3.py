#!/usr/bin/env python3
"""Ctor/player sites for volunteer owner and org commands."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


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


def dump_fn(data, sections, funcs, rva, label, n=96):
    pfn = fn_for(funcs, rva)
    print(f"\n== {label} 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
    start = pfn[0] if pfn else rva
    print(hexdump(data, sections, start, n))


def dump_calls(data, sections, funcs, target, label, n=10):
    hits = calls_to(data, sections, target)
    print(f"\n{label} 0x{target:08x} callers={len(hits)}")
    for rva, kind in hits[:n]:
        pfn = fn_for(funcs, rva)
        fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
        print(f"  {kind} 0x{rva:08x} fn={fns} {hexdump(data, sections, max(0, rva - 12), 32)}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)

    dump_fn(data, sections, funcs, 0x01A59070, "CAIVolunteerGeneral ctor", 120)
    dump_fn(data, sections, funcs, 0x01069990, "CAIGeneral ctor", 80)
    dump_fn(data, sections, funcs, 0x01A5D160, "volunteer[14]", 64)
    dump_calls(data, sections, funcs, 0x01A59070, "volunteer ctor")

    print("\nvolunteer[14] GetCountry-like calls in body")
    pfn = fn_for(funcs, 0x01A5D160)
    off = rva_to_off(sections, pfn[0])
    blob = data[off : off + pfn[1] - pfn[0]]
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
        if tgt in (0x002A8D90, 0x002A8E20, 0x01077350, 0x006C2400, 0x01A5BF00, 0x00F3EAE0, 0x0181DA50):
            print(f"  0x{pfn[0] + i:08x} call 0x{tgt:08x}")

    print("\n0x01A5BF00 calls")
    pfn = fn_for(funcs, 0x01A5BF00)
    off = rva_to_off(sections, pfn[0])
    blob = data[off : off + pfn[1] - pfn[0]]
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry+8",
        0x01077350: "GetCountry wrap",
        0x00F3EAE0: "exec",
        0x0181DA50: "COrderExecute ctor",
        0x0029E670: "AI post",
        0x0029E7B0: "AI post2",
    }
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting or abs(tgt - 0x0181DA50) < 0x20:
            print(f"  0x{pfn[0] + i:08x} call 0x{tgt:08x} {interesting.get(tgt, '')}")

    dump_fn(data, sections, funcs, 0x01353520, "CSetTheatreCommand ctor-ish", 80)
    dump_calls(data, sections, funcs, 0x01353520, "CSetTheatreCommand ctor")
    dump_fn(data, sections, funcs, 0x013576C0, "CSetTheatreCommand[10]", 48)
    dump_calls(data, sections, funcs, 0x013576C0, "CSetTheatreCommand[10]")

    dump_fn(data, sections, funcs, 0x0181B3E0, "CArmyGroupCommand ctor A", 64)
    dump_fn(data, sections, funcs, 0x0181B880, "CArmyGroupCommand ctor B", 48)
    dump_calls(data, sections, funcs, 0x0181B3E0, "AGCommand ctor A")
    dump_calls(data, sections, funcs, 0x0181B880, "AGCommand ctor B")
    dump_calls(data, sections, funcs, 0x01827540, "CArmyGroupCommand[10]/factory caller")

    dump_fn(data, sections, funcs, 0x029E4180, "COrderNewFrontCommand vt dump skip")
    vt = rva_to_off(sections, 0x029E4180)
    print("COrderNewFrontCommand slots")
    for i in range(12):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")
    for i in (0, 9, 10):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        dump_calls(data, sections, funcs, va - ib, f"COrderNewFrontCommand[{i}]")

    print("\nstrings create army/theatre")
    raw0, raw1, _ = text_range(sections)
    for s in (
        b"Create new army",
        b"create_new_army",
        b"NEW_ARMY",
        b"Create Army Group",
        b"CREATE_ARMY",
        b"CREATE_THEATRE",
        b"CREATE_THEATER",
        b"new_theatre",
        b"New Theatre",
        b"New Theater",
        b"Create Theatre",
        b"Create Theater",
        b"Create Front",
        b"new_front",
        b"NEW_FRONT",
        b"CREATE_FRONT",
        b"Assign to army",
        b"create_army_group",
    ):
        i = data.find(s)
        loc = off_to_rva(sections, i)
        print(f"  {s.decode()} {hex(loc) if loc is not None else 'MISS'}")


if __name__ == "__main__":
    main()
