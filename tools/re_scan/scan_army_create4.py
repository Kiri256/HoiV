#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off, text_range
from scan_theatre_skip import pdata, fn_for

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x0181DD70: "OrderGroup ctor B",
    0x0181DB50: "OrderGroup ctor A",
    0x0181A640: "copy +0x30",
    0x0182B0E0: "OrderGroup[10]",
    0x01832910: "OrderGroup[9]",
    0x00F3AE80: "player OrderGroup UI",
    0x00F3B1A0: "player AG UI",
    0x0105C5F0: "army AI poster",
    0x01059820: "army AI2 poster",
    0x0105CCE0: "AG AI poster",
    0x02231380: "player post",
    0x0029E7B0: "AI post2",
    0x021AA4D0: "alloc",
    0x021FFD50: "handle parse",
    0x00EE10B0: "AG factory",
}


def collect_e8(data, sections, targets):
    raw0, raw1, va = text_range(sections)
    hits = {t: [] for t in targets}
    for off in range(raw0, raw1 - 5):
        if data[off] != 0xE8:
            continue
        rva = va + (off - raw0)
        rel = struct.unpack_from("<i", data, off + 1)[0]
        tgt = (rva + 5 + rel) & 0xFFFFFFFF
        if tgt in hits:
            hits[tgt].append(rva)
    return hits


def dump_calls(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        print(f"  0x{begin + i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    hits = collect_e8(
        data,
        sections,
        {
            0x0181DD70,
            0x0181DB50,
            0x0181A640,
            0x00F3AE80,
            0x0181B880,
        },
    )
    for t, lab in (
        (0x0181DD70, "OrderGroup ctor B"),
        (0x0181DB50, "OrderGroup ctor A"),
        (0x00F3AE80, "player OrderGroup UI"),
        (0x0181B880, "AG ctor B"),
        (0x0181A640, "copy +0x30"),
    ):
        print(f"\n{lab} E8 n={len(hits[t])}")
        for rva in hits[t][:16]:
            pfn = fn_for(funcs, rva)
            print(f"  0x{rva:08x} fn={None if not pfn else hex(pfn[0])}")

    print("\nOrderGroup vt")
    off = rva_to_off(sections, 0x029E3370)
    for i in range(12):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")

    for rva, lab in (
        (0x0181DD70, "ctor B"),
        (0x0181DB50, "ctor A"),
        (0x01832910, "[9]"),
        (0x0182B0E0, "[10]"),
        (0x00F3AE80, "player UI"),
        (0x0181A640, "copy +0x30"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n{lab} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print(" ", hexdump(data, sections, rva, 24))
        if pfn:
            dump_calls(data, sections, pfn[0], min(pfn[0] + 0x120, pfn[1]))


if __name__ == "__main__":
    main()
