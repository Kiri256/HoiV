#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

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


def rtti(data, sections, col):
    off = rva_to_off(sections, col)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def vt_hits(data, fn):
    q = struct.pack("<Q", IB + fn)
    p = 0
    out = []
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva.__wrapped__ if False else None
        from scan import off_to_rva as o2r, rva_to_off
        # need sections - pass later
        out.append(i)
        p = i + 1
        if len(out) >= 8:
            break
    return out


def dump_calls_named(data, sections, begin, end, names):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    print(f"== [0x{begin:08x},0x{end:08x})")
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in names or names.get(tgt) or tgt in (
            0x01081FE0, 0x01058380, 0x0105C430, 0x0105CCE0, 0x01074470, 0x010B4620,
            0x01A5BF00, 0x01353520, 0x0181B3E0, 0x0181E620,
        ):
            print(f"  0x{begin+i:08x} -> 0x{tgt:08x} {names.get(tgt, '')}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    names = {
        0x01081FE0: "org walk parent",
        0x01058380: "org create walk",
        0x0105C430: "org mid",
        0x0105CCE0: "AG poster",
        0x01A5BF00: "volunteer body",
        0x0029E7B0: "AI post",
        0x01074470: "CAIGeneral[14]",
        0x01A5D160: "volunteer[14]",
    }
    for rva, label in (
        (0x01074470, "CAIGeneral[14]"),
        (0x01081FE0, "0x01081FE0"),
        (0x01A5D160, "volunteer[14]"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n{label} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print(" ", hexdump(data, sections, rva, 24))
        if pfn:
            dump_calls_named(data, sections, pfn[0], pfn[1], names)

    print("\ncallers 0x01081FE0")
    hits = calls_to(data, sections, 0x01081FE0)
    print("count", len(hits))
    for rva, kind in hits[:16]:
        pfn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} {None if not pfn else hex(pfn[0])}")

    # vtable containing 0x01081FE0
    q = struct.pack("<Q", IB + 0x01081FE0)
    p = 0
    print("\nvt 0x01081FE0")
    n = 0
    while n < 6:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti(data, sections, col - IB)
        print(f"  ptr@0x{vr:08x} {name}")
        p = i + 1
        n += 1

    print("CTheatre vt 0x0294ed28 slots 0-4", hexdump(data, sections, 0x0294ED28, 40))
    # LEA of CTheatre vt
    from scan import lea_to
    print("LEA CTheatre vt")
    for lea in lea_to(data, sections, 0x0294ED28, 12):
        pfn = fn_for(funcs, lea)
        print(f"  0x{lea:08x} {None if not pfn else hex(pfn[0])}")


if __name__ == "__main__":
    main()
