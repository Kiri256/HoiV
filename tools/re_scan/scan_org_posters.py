#!/usr/bin/env python3
"""Who constructs land-org commands besides 0x010B4620."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, lea_to, load_pe, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000

VTS = {
    0x0298A870: "CSetTheatreCommand",
    0x029E3500: "CArmyGroupCommand",
    0x029E35C8: "CAssignToArmyGroupCommand",
    0x029E3690: "CRemoveFromArmyGroupCommand",
    0x029E3758: "CMoveArmiesInTheaterCommand",
    0x029E4180: "COrderNewFrontCommand",
    0x02A0AE00: "CAssignToTheaterGroupCommand",
    0x02707AB0: "CSetCountryReinforcementPriorityCommand",
    0x02A0A3E8: "CAiStoreTotalWantedNrDivisionsCommand",
}


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


def dump_fn_calls(data, sections, begin, end, label):
    print(f"\n== {label} [0x{begin:08x},0x{end:08x})")
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 6):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
            if 0x00100000 <= tgt <= 0x03000000:
                print(f"  call 0x{begin + i:08x} -> 0x{tgt:08x}")
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            tgt = (begin + i + 7 + rel) & 0xFFFFFFFF
            if tgt in VTS:
                print(f"  lea  0x{begin + i:08x} {VTS[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    dump_fn_calls(data, sections, 0x010ABA70, 0x010ABCB3, "minister walk")
    for vt, name in VTS.items():
        print(f"\nLEA {name} 0x{vt:08x}")
        for lea in lea_to(data, sections, vt, 20):
            pfn = fn_for(funcs, lea)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  0x{lea:08x} fn={fns} {hexdump(data, sections, max(0, lea - 8), 28)}")

    print("\nCFront factory 0x00EEE3A0 lea/call sites via imm in .text")
    raw0, raw1, _ = text_range(sections)
    pat = struct.pack("<I", 0x00EEE3A0)
    # not useful
    from scan import calls_to

    for target, label in (
        (0x00EEE3A0, "front factory"),
        (0x00EE10B0, "AG factory"),
        (0x00247630, "AG factory AI caller"),
        (0x01353520, "SetTheatre ctor"),
        (0x0181B3E0, "AGCommand ctor A"),
        (0x0181BB10, "AssignAG ctor"),
        (0x0181E620, "NewFront ctor"),
    ):
        hits = calls_to(data, sections, target)
        print(f"\n{label} 0x{target:08x} callers={len(hits)}")
        for rva, kind in hits[:16]:
            pfn = fn_for(funcs, rva)
            fns = f"[0x{pfn[0]:08x},0x{pfn[1]:08x})" if pfn else "?"
            print(f"  {kind} 0x{rva:08x} {fns}")


if __name__ == "__main__":
    main()
