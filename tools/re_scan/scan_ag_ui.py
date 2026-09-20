#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off
from scan_theatre_skip import pdata, fn_for
from scan_theatre_ui import rtti

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def vt_hits(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    out = []
    p = 0
    while len(out) < 8:
        i = data.find(q, p)
        if i < 0:
            break
        name = "?"
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti(data, sections, col - IB)
        vr = off_to_rva(sections, i)
        out.append((vr, name))
        p = i + 1
    return out


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    for rva, lab in (
        (0x00F3B1A0, "ctorB UI 0xF3B1A0"),
        (0x01A34190, "ctorB 0x1A34190"),
        (0x00F38920, "collect 0xF38920"),
        (0x02231380, "player post 0x2231380"),
        (0x01355120, "CSetTheatre factory"),
        (0x013576C0, "CSetTheatre[10]"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"{lab} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  vt", vt_hits(data, sections, pfn[0] if pfn else rva)[:4])
        print(" ", hexdump(data, sections, rva, 16))

    print("\nlea CSetTheatre vt already known factory/copy only")
    print("player post 0x02231380 xref count via E8")
    from scan import text_range

    raw0, raw1, va = text_range(sections)
    n = 0
    start = raw0
    tgt = 0x02231380
    while n < 5:
        # not a full scan of callers here
        break
    count = 0
    for off in range(raw0, raw1 - 5):
        if data[off] != 0xE8:
            continue
        rva = va + (off - raw0)
        rel = struct.unpack_from("<i", data, off + 1)[0]
        if ((rva + 5 + rel) & 0xFFFFFFFF) == tgt:
            count += 1
    print("  E8 to player post", count)


if __name__ == "__main__":
    main()
