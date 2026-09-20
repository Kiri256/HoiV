#!/usr/bin/env python3
"""Find every vtable that holds volunteer[14] or mass-move, and research AI types."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB_SPAN = 0x4000000
VOL14 = 0x01A5D160
MASS = 0x002AB450
VOL_EXEC = 0x01A5BF00


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


def find_qwords(data, ib, sections, fn_rva):
    needle = struct.pack("<Q", ib + fn_rva)
    hits = []
    for name, _va, _vs, raw, raw_size in sections:
        if not (name.startswith(b".rdata") or name.startswith(b".data")):
            continue
        off = raw
        end = raw + raw_size
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            hits.append(off_to_rva(sections, i))
            off = i + 8
    return hits


def col_name(data, ib, sections, slot_rva):
    for back in range(0, 256):
        vt = slot_rva - back * 8
        off = rva_to_off(sections, vt)
        if off is None or off < 8:
            continue
        col = struct.unpack_from("<Q", data, off - 8)[0]
        if not (ib <= col < ib + IB_SPAN):
            continue
        col_off = rva_to_off(sections, col - ib)
        if col_off is None:
            continue
        if struct.unpack_from("<I", data, col_off)[0] != 1:
            continue
        td_rva = struct.unpack_from("<I", data, col_off + 12)[0]
        name_off = rva_to_off(sections, td_rva + 16)
        if name_off is None:
            continue
        end = data.find(b"\0", name_off, name_off + 80)
        if end < 0:
            continue
        name = data[name_off:end]
        if name.startswith(b".?AV"):
            return f"{name.decode('latin1')} [{back}] vt=0x{vt:08x}"
    return "?"


def find_vt(data, ib, sections, name: bytes):
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


def dump_calls_in(data, sections, start, stop, interesting):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (start + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  0x{start + i:08x} call 0x{tgt:08x} {interesting[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)

    print("== function sizes ==")
    for rva, label in ((VOL14, "vol[14]"), (MASS, "mass body"), (VOL_EXEC, "vol exec"), (0x002A7DE0, "mass thunk")):
        pfn = fn_for(funcs, rva)
        print(f"  {label} 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]), pfn[1]-pfn[0])}")

    print("\n== vtables holding 0x01A5D160 ==")
    for q in find_qwords(data, ib, sections, VOL14):
        name = col_name(data, ib, sections, q)
        # slot index unknown without vt base; print nearby name from COL at q-0
        print(f"  qword@0x{q:08x} {name}")

    print("\n== vtables holding 0x002AB450 ==")
    for q in find_qwords(data, ib, sections, MASS):
        print(f"  qword@0x{q:08x} {col_name(data, ib, sections, q)}")

    print("\n== vtables holding 0x01A5BF00 ==")
    for q in find_qwords(data, ib, sections, VOL_EXEC):
        print(f"  qword@0x{q:08x} {col_name(data, ib, sections, q)}")

    print("\n== research/tech RTTI ==")
    start = 0
    n = 0
    while n < 50:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end]
        low = name.lower()
        if any(x in low for x in (b"research", b"technology", b"techai", b"science", b"doctrine")) and b"lambda" not in name:
            vts = find_vt(data, ib, sections, name)
            print(f"  {name.decode('latin1')} {[hex(x) for x in vts[:3]]}")
            n += 1
        start = i + 1

    print("\n== CAI*General / minister RTTI ==")
    start = 0
    n = 0
    while n < 40:
        i = data.find(b".?AVCAI", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end]
        if b"lambda" not in name and b"DefineRegistry" not in name:
            vts = find_vt(data, ib, sections, name)
            print(f"  {name.decode('latin1')} {[hex(x) for x in vts[:3]]}")
            n += 1
        start = i + 1

    pfn = fn_for(funcs, MASS)
    print("\n== mass body command ctors ==")
    interesting = {}
    # scan for lea of known command vts later; first dump E8 targets that are ctors by size
    dump_calls_in(data, sections, pfn[0], pfn[1], {
        0x01350350: "CMoveCommand ctor",
        0x0181DA50: "COrderExecute ctor",
        0x0029E670: "AI post",
        0x0029E7B0: "AI post2",
    })
    print("mass first 32 E8 targets:")
    off = rva_to_off(sections, pfn[0])
    blob = data[off : off + min(0x800, pfn[1] - pfn[0])]
    seen = 0
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
        tfn = fn_for(funcs, tgt)
        print(f"  0x{pfn[0]+i:08x} -> 0x{tgt:08x} size={0 if not tfn else tfn[1]-tfn[0]}")
        seen += 1
        if seen >= 24:
            break

    print("\nCCountryAI[145] thunk", hexdump(data, sections, 0x002A7DE0, 32))
    print("mass prologue", hexdump(data, sections, MASS, 32))


if __name__ == "__main__":
    main()
