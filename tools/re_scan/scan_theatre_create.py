#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off
from scan_theatre_skip import pdata, fn_for, collect_xrefs, name_fn

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("ascii", "replace")


def vt_for_fn(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    out = []
    p = 0
    while len(out) < 6:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti(data, sections, col - IB)
        out.append((vr, name))
        p = i + 1
    return out


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    xrefs, _ = collect_xrefs(
        data,
        sections,
        {0x00EF0B50, 0x00BEFF30, 0x00C68E30, 0x006F8F50, 0x00ED9F40},
    )
    for t, lab in (
        (0x00EF0B50, "EF0B50"),
        (0x00BEFF30, "BEFF30"),
        (0x00C68E30, "C68E30"),
    ):
        pfn = fn_for(funcs, t)
        print(f"\n{lab} 0x{t:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))} callers={len(xrefs[t])}")
        print(" ", hexdump(data, sections, t, 20))
        print("  vt", vt_for_fn(data, sections, pfn[0] if pfn else t))
        for rva, k in xrefs[t][:16]:
            pfn2 = fn_for(funcs, rva)
            print(f"  {k} 0x{rva:08x} fn={None if not pfn2 else hex(pfn2[0])} vt={vt_for_fn(data, sections, pfn2[0] if pfn2 else rva)[:2]}")

    print("\nCCountry vt slots 0-6")
    off = rva_to_off(sections, 0x027C0E80)
    for i in range(8):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        rva = va - ib
        print(f"  [{i}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")

    print("\nCTheatreSelector string xref")
    i = data.find(b".?AVCTheatreSelector@@")
    print("td", hex(off_to_rva(sections, i) or 0))


if __name__ == "__main__":
    main()
