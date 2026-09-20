#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x002A8D90: "GetCountry",
    0x002A8E20: "GetCountry+8",
    0x0029E7B0: "AI post",
    0x0105C430: "org mid",
    0x0105CCE0: "org poster",
    0x0181B3E0: "AG ctor",
    0x0181BB10: "AssignAG ctor",
    0x0181E620: "NewFront ctor",
    0x0181C890: "AssignOrder ctor",
    0x00EEE3A0: "front factory",
    0x00EE10B0: "AG factory",
    0x002A8E20: "GetCountry+8",
    0x001DBA10: "maybe GetCountry wrap",
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


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def vt_hits(data, sections, fn):
    q = struct.pack("<Q", IB + fn)
    p = 0
    out = []
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        if i >= 8:
            col_va = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col_va < IB + 0x4000000:
                name = rtti(data, sections, col_va - IB)
        out.append((vr, name))
        p = i + 1
        if len(out) >= 6:
            break
    return out


def dump_e8(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in NAMED or 0x01058000 <= tgt <= 0x0105E000:
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    print("0x01058380", hexdump(data, sections, 0x01058380, 40))
    pfn = fn_for(funcs, 0x01058380)
    print("pdata", None if not pfn else (hex(pfn[0]), hex(pfn[1])))
    print("vt", vt_hits(data, sections, 0x01058380))
    if pfn:
        dump_e8(data, sections, pfn[0], pfn[1])
    print("\ncallers 0x01058380")
    hits = calls_to(data, sections, 0x01058380)
    print("count", len(hits))
    for rva, kind in hits[:20]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={None if not pfn else hex(pfn[0])}")
        if pfn:
            print("   vt", vt_hits(data, sections, pfn[0]))

    print("\nminister[14] prologue", hexdump(data, sections, 0x010ABA70, 20))
    print("CTheatre rtti cluster")
    i = data.find(b".?AVCTheatre@@\0")
    # complete object locator search like scan_org_can find_vt
    td = off_to_rva(sections, i) - 16
    pat = struct.pack("<I", td)
    cols = []
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sections, j)
        if rva:
            cols.append(rva - 12)
        start = j + 1
    print(" cols", [hex(c) for c in cols[:4]])
    for col in cols[:2]:
        q = struct.pack("<Q", IB + col)
        k = 0
        while True:
            p = data.find(q, k)
            if p < 0:
                break
            vr = off_to_rva(sections, p + 8)
            print("  vt", hex(vr) if vr else None)
            k = p + 1


if __name__ == "__main__":
    main()
