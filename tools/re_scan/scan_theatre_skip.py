#!/usr/bin/env python3
"""Find German theatre-create skip points that are not whole 0x00EEA3E0 or ctor return 0."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

capstone_root = Path(os.environ.get("HOIV_CAPSTONE", ""))
if capstone_root:
    sys.path.insert(0, str(capstone_root))

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x0029E670: "AI post1",
    0x0029E7B0: "AI post2",
    0x002A8D90: "GetCountry",
    0x002A8E20: "GetCountry+8",
    0x006C2400: "GetAI",
    0x006EB9B0: "0x006EB9B0",
    0x006F6070: "0x006F6070",
    0x006F8F50: "native theatre parent",
    0x00BABF70: "0x00BABF70",
    0x00ED9F40: "CTheatre ctor",
    0x00EDA790: "CTheatre ctor B",
    0x00EDBC50: "post-ctor 0x00EDBC50",
    0x00EDBF80: "CSetTheatre apply? 0x00EDBF80",
    0x00EE67F0: "pre-alloc 0x00EE67F0",
    0x00EEA3E0: "theatre wrapper",
    0x00EF1920: "pre-alloc 0x00EF1920",
    0x01353520: "CSetTheatre copy",
    0x01355120: "CSetTheatre factory",
    0x013576C0: "CSetTheatre[10]",
    0x0135AF40: "CSetTheatre[9]",
    0x021AA4D0: "alloc",
    0x021FF140: "0x021FF140",
    0x021FFD50: "handle parse 0x021FFD50",
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


def rtti(data, sections, col_rva):
    off = rva_to_off(sections, col_rva)
    if not off:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if not tdo:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def name_fn(data, sections, rva):
    off = rva_to_off(sections, rva)
    if not off or off < 8:
        return "?"
    col = struct.unpack_from("<Q", data, off - 8)[0]
    if IB <= col < IB + 0x4000000:
        return rtti(data, sections, col - IB)
    return "?"


def dump_e8(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        print(f"  0x{begin + i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")


def try_disasm(data, ib, sections, start, stop, label):
    print(f"\n== disasm {label} 0x{start:08x}-0x{stop:08x} ==")
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError:
        print("  (no capstone) " + hexdump(data, sections, start, min(96, stop - start)))
        return
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


def collect_xrefs(data, sections, targets):
    raw0, raw1, va = text_range(sections)
    hits = {t: [] for t in targets}
    leas = []
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
            if tgt == 0x0298A870:
                leas.append(rva)
    return hits, leas


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)

    want = (
        0x00EEA3E0,
        0x00ED9F40,
        0x00EDBC50,
        0x00EE67F0,
        0x00EF1920,
        0x00EDBF80,
        0x01355120,
        0x013576C0,
        0x0135AF40,
        0x006F8F50,
        0x00EEAC10,
        0x00EECE80,
        0x00ED6A60,
        0x00ED8810,
        0x006FA752,
        0x021AA4D0,
    )
    xrefs, leas = collect_xrefs(data, sections, set(want))

    print("CSetTheatre vt slots")
    vt = rva_to_off(sections, 0x0298A870)
    for i in range(12):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        rva = va - ib
        pfn = fn_for(funcs, rva)
        print(
            f"  [{i:3d}] 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))} "
            f"{hexdump(data, sections, rva, 12)}"
        )

    for target, label in (
        (0x00EEA3E0, "theatre wrapper"),
        (0x00ED9F40, "CTheatre ctor"),
        (0x00EDBC50, "post-ctor"),
        (0x00EE67F0, "pre-alloc EE67F0"),
        (0x00EF1920, "pre-alloc EF1920"),
        (0x00EDBF80, "EDBF80"),
        (0x01355120, "CSetTheatre factory"),
        (0x013576C0, "CSetTheatre[10]"),
        (0x0135AF40, "CSetTheatre[9]"),
        (0x006F8F50, "native parent"),
        (0x00EEAC10, "wrapper sibling"),
        (0x00EECE80, "EECE80"),
        (0x00ED6A60, "ED6A60"),
        (0x00ED8810, "ED8810"),
    ):
        pfn = fn_for(funcs, target)
        hits = xrefs.get(target, [])
        print(f"\n{label} 0x{target:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))} "
              f"rtti={name_fn(data, sections, pfn[0] if pfn else target)} callers={len(hits)}")
        print(" ", hexdump(data, sections, target, 24))
        for rva, kind in hits[:16]:
            pfn2 = fn_for(funcs, rva)
            print(
                f"  {kind} 0x{rva:08x} fn={None if not pfn2 else hex(pfn2[0])} "
                f"{name_fn(data, sections, pfn2[0] if pfn2 else rva)}"
            )

    print("\nLEA CSetTheatre vt")
    for rva in leas[:20]:
        pfn = fn_for(funcs, rva)
        print(f"  0x{rva:08x} fn={None if not pfn else hex(pfn[0])} {name_fn(data, sections, pfn[0] if pfn else rva)}")

    print("\nwrapper E8")
    dump_e8(data, sections, 0x00EEA3E0, 0x00EEAC0B)

    try_disasm(data, ib, sections, 0x00EEA7C0, 0x00EEAA20, "wrapper ctor branch A/B")
    try_disasm(data, ib, sections, 0x00EEA3E0, 0x00EEA520, "wrapper head")
    try_disasm(data, ib, sections, 0x00EDBC50, 0x00EDBD40, "post-ctor")
    try_disasm(data, ib, sections, 0x00EE67F0, 0x00EE68C0, "EE67F0")
    try_disasm(data, ib, sections, 0x00EF1920, 0x00EF1A20, "EF1920")
    try_disasm(data, ib, sections, 0x006FA720, 0x006FA7A0, "native ctor site")
    pfn = fn_for(funcs, 0x013576C0)
    if pfn:
        print("\nCSetTheatre[10] E8")
        dump_e8(data, sections, pfn[0], pfn[1])
        try_disasm(data, ib, sections, pfn[0], min(pfn[0] + 0x120, pfn[1]), "CSetTheatre[10] head")


if __name__ == "__main__":
    main()
