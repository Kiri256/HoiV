#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

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


def rtti_at_col(data, sections, col_rva):
    off = rva_to_off(sections, col_rva)
    if off is None:
        return "?"
    td = struct.unpack_from("<I", data, off + 12)[0]
    tdo = rva_to_off(sections, td)
    if tdo is None:
        return "?"
    return data[tdo + 16 : data.find(b"\0", tdo + 16)].decode("latin1", "replace")


def xrefs_fn(data, sections, fn_rva):
    q = struct.pack("<Q", IB + fn_rva)
    hits = []
    p = 0
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        vr = off_to_rva(sections, i)
        name = "?"
        slot = None
        if i >= 8:
            col = struct.unpack_from("<Q", data, i - 8)[0]
            if IB <= col < IB + 0x4000000:
                name = rtti_at_col(data, sections, col - IB)
                if vr is not None and vr >= (col - IB + 8):
                    slot = (vr - (col - IB + 8)) // 8
        hits.append((hex(vr) if vr else vr, name, slot))
        p = i + 8
        if len(hits) >= 12:
            break
    return hits


def dump_calls(data, sections, begin, end, interesting):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in interesting:
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x} {interesting[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    interesting = {
        0x002A8D90: "GetCountry",
        0x002A8E20: "GetCountry2",
        0x006C2400: "GetAI",
        0x00F3B2F0: "exec helper",
        0x0181DA50: "Execute ctor",
        0x0181E620: "NewFront ctor",
        0x0181B3E0: "AGCommand ctor A",
        0x0181B880: "AGCommand ctor B",
        0x0181BB10: "AssignAG ctor",
        0x0181BE40: "CreateAreaDef ctor",
        0x0029E7B0: "post",
        0x00EE10B0: "AG factory",
        0x00EEE3A0: "front factory",
        0x0105CCE0: "AG poster",
        0x01058380: "AG parent",
        0x00ED9F40: "theatre ctor",
        0x00EEA3E0: "theatre AI",
        0x01A31660: "move",
        0x00F3EAE0: "idler exec",
    }

    for rva, label in (
        (0x017A7770, "exec fn A"),
        (0x017A7D50, "exec fn B"),
        (0x017A7820, "big neighbor"),
        (0x0181B3E0, "AGCommand ctor A"),
        (0x0181BE40, "CreateAreaDef ctor"),
        (0x0181BB10, "AssignAG ctor"),
        (0x0181C020, "EditAreaDef ctor"),
    ):
        pfn = fn_for(funcs, rva)
        print(f"\n==== {label} 0x{rva:08x} {None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
        print("  pro", hexdump(data, sections, rva, 20))
        print("  xrefs", xrefs_fn(data, sections, rva))
        if pfn:
            dump_calls(data, sections, pfn[0], min(pfn[1], pfn[0] + 0x800), interesting)
        hits = calls_to(data, sections, rva)
        print(f"  callers={len(hits)}")
        for site, kind in hits[:20]:
            pf = fn_for(funcs, site)
            xr = xrefs_fn(data, sections, pf[0]) if pf else []
            print(f"    {kind} 0x{site:08x} {None if not pf else (hex(pf[0]), hex(pf[1]))} vt={xr[:3]}")


if __name__ == "__main__":
    main()
