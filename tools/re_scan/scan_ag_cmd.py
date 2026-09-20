#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off, text_range
from scan_theatre_skip import pdata, fn_for

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x0181B3E0: "AG ctor A",
    0x0181B880: "AG ctor B",
    0x0181BB10: "AssignAG ctor",
    0x0181A640: "copy handles +0x30",
    0x01827540: "AG[10]",
    0x01831B90: "AG[9]",
    0x00EE10B0: "AG factory",
    0x0029E670: "post1",
    0x0029E7B0: "post2",
    0x021FFD50: "handle parse",
    0x00ED9F40: "CTheatre ctor",
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
    hits = collect_e8(data, sections, {0x0181B3E0, 0x0181B880, 0x00EE10B0, 0x01827540})
    for t, lab in (
        (0x0181B3E0, "AG ctor A"),
        (0x0181B880, "AG ctor B"),
        (0x00EE10B0, "AG factory"),
        (0x01827540, "AG[10]"),
    ):
        print(f"\n{lab} callers {len(hits[t])}")
        for rva in hits[t][:20]:
            pfn = fn_for(funcs, rva)
            print(f"  0x{rva:08x} fn={None if not pfn else hex(pfn[0])}")

    pfn = fn_for(funcs, 0x01831B90)
    print("\nAG[9]", hexdump(data, sections, 0x01831B90, 24), "pdata", None if not pfn else (hex(pfn[0]), hex(pfn[1])))
    if pfn:
        dump_calls(data, sections, pfn[0], pfn[1])

    pfn = fn_for(funcs, 0x01827540)
    print("\nAG[10] all E8")
    if pfn:
        dump_calls(data, sections, pfn[0], pfn[1])

    print("\nAG vt slots")
    off = rva_to_off(sections, 0x029E3500)
    for i in range(12):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")


if __name__ == "__main__":
    main()
