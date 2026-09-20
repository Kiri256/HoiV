#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

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


def rtti_from_qword_off(data, sections, file_off):
    if file_off < 8:
        return "?"
    col = struct.unpack_from("<Q", data, file_off - 8)[0]
    if not (IB <= col < IB + 0x4000000):
        return f"col={hex(col)}"
    coff = rva_to_off(sections, col - IB)
    if not coff:
        return "?"
    td = struct.unpack_from("<I", data, coff + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return f"td={hex(td)}"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    pfn = fn_for(funcs, 0x013576C0)
    print("CSetTheatre[10] all E8", hex(pfn[0]), hex(pfn[1]))
    off = rva_to_off(sections, pfn[0])
    blob = data[off : off + (pfn[1] - pfn[0])]
    for i in range(len(blob) - 4):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (pfn[0] + i + 5 + rel) & 0xFFFFFFFF
            print(f"  0x{pfn[0]+i:08x} -> 0x{tgt:08x} {hexdump(data, sections, tgt, 16)}")

    print("\n0x00EEA3E0 first 80 after prologue")
    print(hexdump(data, sections, 0x00EEA3E0, 80))

    # identify vtable of 0x00351C20
    q = struct.pack("<Q", IB + 0x00351C20)
    p = 0
    print("\nvt 0x00351C20")
    n = 0
    while n < 8:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        print(f"  qword file={i} rva={hex(vr) if vr else None} {rtti_from_qword_off(data, sections, i)}")
        p = i + 1
        n += 1

    q = struct.pack("<Q", IB + 0x003675D0)
    p = 0
    print("\nvt 0x003675D0")
    n = 0
    while n < 8:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        print(f"  qword file={i} rva={hex(vr) if vr else None} {rtti_from_qword_off(data, sections, i)}")
        p = i + 1
        n += 1

    print("\n0x00351C20 GetCountry-ish")
    pfn = fn_for(funcs, 0x00351C20)
    off = rva_to_off(sections, pfn[0])
    blob = data[off : off + 0x80]
    print(hexdump(data, sections, pfn[0], 64))
    # look for [rcx+8]
    for i in range(min(80, len(blob) - 4)):
        if blob[i : i + 4] in (b"\x48\x8b\x41\x08", b"\x48\x8b\x49\x08", b"\x48\x8b\x51\x08"):
            print("  +8 load", hex(pfn[0] + i))


if __name__ == "__main__":
    main()
