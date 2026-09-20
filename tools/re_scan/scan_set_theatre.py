#!/usr/bin/env python3
"""Pin CSetTheatreCommand factory/ctor/[9]/[10] arguments for native issue."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x0029E670: "AI post1",
    0x0029E7B0: "AI post2",
    0x002A8D90: "GetCountry",
    0x006C2400: "GetAI",
    0x006C2680: "GetCommandGroups",
    0x006F8F50: "native theatre parent",
    0x00ED9F40: "CTheatre ctor",
    0x00EDBF80: "apply 0x00EDBF80",
    0x00EEA3E0: "theatre wrapper",
    0x01353520: "copy ctor",
    0x01355120: "factory",
    0x013576C0: "CSetTheatre[10]",
    0x0135AF40: "CSetTheatre[9]",
    0x01357E70: "CSetTheatre[11]?",
    0x021AA4D0: "alloc",
    0x021FFD50: "handle parse",
    0x00BAB010: "0x00BAB010",
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


def collect_refs(data, sections, targets):
    raw0, raw1, va = text_range(sections)
    hits = {t: [] for t in targets}
    for off in range(raw0, raw1 - 7):
        rva = va + (off - raw0)
        b = data[off]
        if b in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", data, off + 1)[0]
            tgt = (rva + 5 + rel) & 0xFFFFFFFF
            if tgt in hits:
                hits[tgt].append((rva, "call" if b == 0xE8 else "jmp"))
        if data[off] == 0x48 and data[off + 1] == 0x8D and data[off + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", data, off + 3)[0]
            tgt = (rva + 7 + rel) & 0xFFFFFFFF
            if tgt in hits:
                hits[tgt].append((rva, "lea"))
        if data[off] == 0x4C and data[off + 1] == 0x8D and data[off + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", data, off + 3)[0]
            tgt = (rva + 7 + rel) & 0xFFFFFFFF
            if tgt in hits:
                hits[tgt].append((rva, "lea4c"))
    return hits


def dump_e8(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if 0x00100000 <= tgt <= 0x03000000:
            print(f"  0x{begin + i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")


def disasm(data, ib, sections, start, stop, label):
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    print(f"\n== {label} 0x{start:08x}-0x{stop:08x} ==")
    off = rva_to_off(sections, start)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for insn in md.disasm(data[off : off + stop - start], ib + start):
        rva = insn.address - ib
        line = f"  0x{rva:08x}: {insn.mnemonic:7} {insn.op_str}"
        if insn.bytes and insn.bytes[0] in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", insn.bytes, 1)[0]
            tgt = (rva + insn.size + rel) & 0xFFFFFFFF
            line += f"  ; -> 0x{tgt:08x} {NAMED.get(tgt, '')}"
        print(line)


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    want = {
        0x01355120,
        0x01353520,
        0x013576C0,
        0x0135AF40,
        0x01357E70,
        0x00EDBF80,
        0x006F8F50,
        0x0298A870,
    }
    refs = collect_refs(data, sections, want)
    for t in sorted(want):
        pfn = fn_for(funcs, t)
        print(f"\nrefs 0x{t:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))} n={len(refs[t])}")
        for rva, k in refs[t][:24]:
            pfn2 = fn_for(funcs, rva)
            print(f"  {k} 0x{rva:08x} fn={None if not pfn2 else hex(pfn2[0])}")

    pfn = fn_for(funcs, 0x01355120)
    print("\nfactory E8")
    dump_e8(data, sections, pfn[0], pfn[1])
    disasm(data, ib, sections, pfn[0], pfn[1], "factory")

    pfn = fn_for(funcs, 0x01353520)
    disasm(data, ib, sections, pfn[0], min(pfn[0] + 0xA0, pfn[1]), "copy ctor")

    pfn = fn_for(funcs, 0x0135AF40)
    disasm(data, ib, sections, pfn[0], pfn[1], "CSetTheatre[9]")

    pfn = fn_for(funcs, 0x013576C0)
    print("\n[10] E8")
    dump_e8(data, sections, pfn[0], pfn[1])
    disasm(data, ib, sections, pfn[0], pfn[1], "CSetTheatre[10]")

    disasm(data, ib, sections, 0x00EDBF80, 0x00EDC0A0, "EDBF80 head")
    disasm(data, ib, sections, 0x006FA700, 0x006FA7C0, "native ctor site")

    print("\nstrings")
    for s in (
        b"CSetTheatreCommand",
        b"CREATE_THEATRE",
        b"CREATE_THEATER",
        b"new_theatre",
        b"New Theatre",
        b"create_theatre",
    ):
        i = data.find(s)
        print(s, hex(off_to_rva(sections, i) or 0) if i >= 0 else "MISS")


if __name__ == "__main__":
    main()
