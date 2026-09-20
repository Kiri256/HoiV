#!/usr/bin/env python3
"""Who sets plan execution type, and CCountryAI[145] callers."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IB_SPAN = 0x4000000


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


def find_qword(data, ib, sections, fn_rva):
    needle = struct.pack("<Q", ib + fn_rva)
    hits = []
    for name, _va, _vs, raw, raw_size in sections:
        if not (name.startswith(b".rdata") or name.startswith(b".data")):
            continue
        start = raw
        end = raw + raw_size
        off = start
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            hits.append(off_to_rva(sections, i))
            off = i + 8
    return hits


def vt_near(vt_map, slot_rva):
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x400:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def lea_to(data, sections, vt):
    raw0, raw1, _ = text_range(sections)
    out = []
    for off in range(raw0, raw1 - 7):
        if data[off] != 0x48 or data[off + 1] != 0x8D:
            continue
        if data[off + 2] not in (0x05, 0x0D, 0x15):
            continue
        rva = off_to_rva(sections, off)
        rel = struct.unpack_from("<i", data, off + 3)[0]
        if rva is not None and ((rva + 7 + rel) & 0xFFFFFFFF) == vt:
            out.append(rva)
    return out


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}
    name_to_vt = {}
    for vt, name in vt_map.items():
        name_to_vt.setdefault(name, vt)

    for cmd in (
        ".?AVCSetOrderGroupExecutionTypeCommand@@",
        ".?AVCOrderExecuteCommand@@",
        ".?AVCOrderAssignCommand@@",
        ".?AVCAutoMergeOrdersCommand@@",
    ):
        vt = name_to_vt.get(cmd, 0)
        print(f"\n== {cmd} vt=0x{vt:08x} ==")
        for site in lea_to(data, sections, vt):
            fn = fn_for(funcs, site)
            print(f"  lea 0x{site:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            if fn and fn[1] - fn[0] < 0x200:
                for rva, kind in calls_to(data, sections, fn[0])[:15]:
                    pfn = fn_for(funcs, rva)
                    extra = ""
                    if pfn:
                        for q in find_qword(data, ib, sections, pfn[0]):
                            info = vt_near(vt_map, q)
                            if info:
                                extra = f" {info[1]}[{info[2]}]"
                                break
                    print(f"    {kind} 0x{rva:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}{extra}")

    print("\n== CCountryAI[145] slot 0x488 callers ==")
    raw0, raw1, _ = text_range(sections)
    n = 0
    for off in range(raw0, raw1 - 6):
        if data[off] == 0xFF and data[off + 1] == 0x90 and struct.unpack_from("<I", data, off + 2)[0] == 0x488:
            rva = off_to_rva(sections, off)
            fn = fn_for(funcs, rva)
            print(f"  0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            if fn:
                for q in find_qword(data, ib, sections, fn[0]):
                    info = vt_near(vt_map, q)
                    if info:
                        print(f"    {info[1]}[{info[2]}]")
            n += 1
            if n >= 20:
                break
    print("hits", n)

    print("\n== CInGameIdler[4] ==")
    print(hexdump(data, sections, 0x00DC44C0, 32))


if __name__ == "__main__":
    main()
