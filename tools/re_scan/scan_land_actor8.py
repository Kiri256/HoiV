#!/usr/bin/env python3
"""Identify minister[14] posted commands and hourly update dispatch."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

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
        off = raw
        end = raw + raw_size
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
        if vt <= slot_rva < vt + 0x800:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def lea_imm(data, sections, start, stop):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    for i in range(len(blob) - 7):
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            dest = (start + i + 7 + rel) & 0xFFFFFFFF
            yield start + i, dest
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            yield start + i, (start + i + 5 + rel) & 0xFFFFFFFF


def identify_fn(data, ib, sections, funcs, vt_map, rva, label):
    fn = fn_for(funcs, rva)
    print(f"\n== {label} 0x{rva:08x} pdata={None if not fn else (hex(fn[0]), hex(fn[1]))}")
    print(hexdump(data, sections, fn[0] if fn else rva, 64))
    target = fn[0] if fn else rva
    for q in find_qword(data, ib, sections, target):
        print(f"  qword@0x{q:08x} {vt_near(vt_map, q)}")
    if fn:
        print("lea/call:")
        n = 0
        for site, dest in lea_imm(data, sections, fn[0], min(fn[1], fn[0] + 0x180)):
            name = vt_map.get(dest)
            extra = f" {name}" if name else ""
            print(f"  0x{site:08x} -> 0x{dest:08x}{extra}")
            n += 1
            if n >= 24:
                break
    print("callers:")
    for site, kind in calls_to(data, sections, target)[:10]:
        pfn = fn_for(funcs, site)
        extra = ""
        if pfn:
            for q in find_qword(data, ib, sections, pfn[0]):
                info = vt_near(vt_map, q)
                if info:
                    extra = f" {info[1]}[{info[2]}]"
                    break
        print(f"  {kind} 0x{site:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}{extra}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    for rva, label in (
        (0x01136DE0, "minister post ctor A 0x30"),
        (0x01A57370, "minister post ctor B"),
        (0x002AA550, "CCountryAI Update callee"),
        (0x002A7EA0, "CCountryAI method from min[14]"),
        (0x010B4620, "minister helper after generals"),
        (0x01A46B60, "minister helper 0x1a46b60"),
        (0x001DFC80, "near DoCountryHourlyUpdates lea"),
        (0x00F33B30, "execution-type helper"),
        (0x002AD600, "CCountryAI[149]"),
        (0x002AF0F0, "CCountryAI[153]"),
    ):
        identify_fn(data, ib, sections, funcs, vt_map, rva, label)


if __name__ == "__main__":
    main()
