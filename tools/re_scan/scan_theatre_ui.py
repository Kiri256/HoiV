#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off
from scan_theatre_skip import pdata, fn_for

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off or off + 16 > len(data):
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("ascii", "replace")


def find_vt_from_td_name(data, ib, sections, name: bytes):
    i = data.find(name + b"\0")
    if i < 0:
        return []
    td = off_to_rva(sections, i) - 16
    pat = struct.pack("<I", td)
    cols = []
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sections, j)
        if rva is not None:
            cols.append(rva - 12)
        start = j + 1
    vts = []
    for col in cols:
        q = struct.pack("<Q", ib + col)
        k = 0
        while True:
            p = data.find(q, k)
            if p < 0:
                break
            vr = off_to_rva(sections, p + 8)
            if vr:
                vts.append(vr)
            k = p + 1
    return vts


def vt_hits(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    out = []
    p = 0
    while len(out) < 8:
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
    for name in (
        b".?AVCTheatreSelector@@",
        b".?AVCTheatre@@",
        b".?AVCTheaterGroup@@",
        b".?AVCSetTheatreCommand@@",
    ):
        vts = find_vt_from_td_name(data, ib, sections, name)
        print(name.decode(), [hex(x) for x in vts[:6]])

    print("\nfn classes")
    for rva in (0x00351C20, 0x003675D0, 0x00C6F1B0, 0x00C68E30, 0x00EDD1F0, 0x006F8F50):
        pfn = fn_for(funcs, rva)
        print(f"  0x{rva:08x} {vt_hits(data, sections, pfn[0] if pfn else rva)}")

    print("\nCTheatreSelector vt dump")
    vts = find_vt_from_td_name(data, ib, sections, b".?AVCTheatreSelector@@")
    if vts:
        off = rva_to_off(sections, vts[0])
        for i in range(16):
            va = struct.unpack_from("<Q", data, off + i * 8)[0]
            if not (IB <= va < IB + 0x4000000):
                continue
            rva = va - IB
            pfn = fn_for(funcs, rva)
            print(f"  [{i:3d}] 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")

    print("\nutf16 theatre strings")
    for s in (
        "CREATE_THEATRE",
        "NEW_THEATRE",
        "CREATE_THEATER",
        "NEW_THEATER",
        "theatre_create",
        "create_new_theatre",
    ):
        b = s.encode("utf-16le")
        i = data.find(b)
        print(s, "MISS" if i < 0 else hex(off_to_rva(sections, i) or 0))


if __name__ == "__main__":
    main()
