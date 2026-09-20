#!/usr/bin/env python3
"""Country source and second entry for the 0x01A31660 land-move actor."""

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


def slot(data, ib, sections, vt, i):
    off = rva_to_off(sections, vt + i * 8)
    if off is None:
        return 0
    va = struct.unpack_from("<Q", data, off)[0]
    return va - ib if ib <= va < ib + IB_SPAN else 0


def dump(data, sections, rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sections, rva, n))


def all_calls(data, sections, funcs, start, stop, limit=60):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    n = 0
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (start + i + 5 + rel) & 0xFFFFFFFF
        fn = fn_for(funcs, tgt)
        print(f"  0x{start + i:08x} -> 0x{tgt:08x} {f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else ''}")
        n += 1
        if n >= limit:
            break


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    dump(data, sections, 0x0107D9C0, 220, "CAIGeneral[13]")
    print("\nCAIGeneral[13] calls")
    all_calls(data, sections, funcs, 0x0107D9C0, 0x0107DDF4)
    print("\nCAIGeneral[13] callers")
    for rva, kind in calls_to(data, sections, 0x0107D9C0):
        fn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        print("   ", hexdump(data, sections, max(0, rva - 20), 40))
        if fn:
            for q in find_qword(data, ib, sections, fn[0]):
                info = vt_near(vt_map, q)
                if info:
                    print(f"    parent method {info[1]} [{info[2]}]")

    dump(data, sections, 0x01086CB0, 180, "second entry 0x01086cb0")
    print("\n0x01086cb0 calls")
    all_calls(data, sections, funcs, 0x01086CB0, 0x01086FF7)
    print("\n0x01086cb0 callers")
    for rva, kind in calls_to(data, sections, 0x01086CB0):
        fn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        print("   ", hexdump(data, sections, max(0, rva - 20), 40))
        if fn:
            for q in find_qword(data, ib, sections, fn[0]):
                info = vt_near(vt_map, q)
                if info:
                    print(f"    parent method {info[1]} [{info[2]}]")
            print("    prologue", hexdump(data, sections, fn[0], 32))

    print("\n== CAIGeneral getters ==")
    for i in range(40):
        rva = slot(data, ib, sections, 0x029613D0, i)
        if not rva:
            continue
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")

    print("\n== CArmy more getters 80-140 ==")
    for i in range(80, 140):
        rva = slot(data, ib, sections, 0x02933D20, i)
        if not rva:
            continue
        off = rva_to_off(sections, rva)
        b = data[off : off + 12]
        desc = hexdump(data, sections, rva, 16)
        if b[:3] == b"\x48\x8b\x81" and len(b) >= 8 and b[7] == 0xC3:
            desc = f"mov rax,[rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]"
        elif b[:2] == b"\x8b\x81" and b[6] == 0xC3:
            desc = f"mov eax,[rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}]"
        elif b[:3] == b"\x48\x8d\x81" and b[7] == 0xC3:
            desc = f"lea rax,[rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]"
        elif b[:3] == b"\x48\x8b\x41" and b[4] == 0xC3:
            desc = f"mov rax,[rcx+0x{b[3]:x}]"
        print(f"  [{i:3d}] 0x{rva:08x} {desc}")

    print("\n== CUnit getters that look like owner/country ==")
    for i in range(80):
        rva = slot(data, ib, sections, 0x0292CCE8, i)
        if not rva:
            continue
        off = rva_to_off(sections, rva)
        b = data[off : off + 12]
        if b[:3] == b"\x48\x8b\x81" and b[7] == 0xC3:
            print(f"  CUnit[{i}] mov rax,[rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]")
        elif b[:2] == b"\x8b\x81" and b[6] == 0xC3:
            print(f"  CUnit[{i}] mov eax,[rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}]")
        elif b[:3] == b"\x48\x8b\x41" and b[4] == 0xC3:
            print(f"  CUnit[{i}] mov rax,[rcx+0x{b[3]:x}]")

    print("\n== CMassMove country-AI site 0x002AB450 ==")
    dump(data, sections, 0x002AB450, 96, "fn 0x002AB450")
    print("calls")
    all_calls(data, sections, funcs, 0x002AB450, 0x002ABDF3, 30)
    print("callers")
    for rva, kind in calls_to(data, sections, 0x002AB450)[:12]:
        fn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        if fn:
            for q in find_qword(data, ib, sections, fn[0]):
                info = vt_near(vt_map, q)
                if info:
                    print(f"    {info[1]} [{info[2]}]")

    print("\n== CStrategicRedeployment ctor via LEA vt 0x0298b5b8 ==")
    raw0, raw1, _ = text_range(sections)
    vt = 0x0298B5B8
    sites = []
    for off in range(raw0, raw1 - 7):
        if data[off] != 0x48 or data[off + 1] != 0x8D:
            continue
        if data[off + 2] not in (0x05, 0x0D, 0x15):
            continue
        rva = off_to_rva(sections, off)
        rel = struct.unpack_from("<i", data, off + 3)[0]
        if rva is not None and ((rva + 7 + rel) & 0xFFFFFFFF) == vt:
            sites.append(rva)
    print("lea sites", [hex(x) for x in sites])
    for site in sites:
        fn = fn_for(funcs, site)
        print(f"  0x{site:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        if fn and fn[1] - fn[0] < 0x200:
            print("  possible ctor callers:")
            for rva, kind in calls_to(data, sections, fn[0])[:15]:
                pfn = fn_for(funcs, rva)
                print(f"    {kind} 0x{rva:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}")

    print("\n== 0x01A36B30 (fallback after move helper) ==")
    dump(data, sections, 0x01A36B30, 64, "0x01A36B30")
    fb_fn = fn_for(funcs, 0x01A36B30)
    if fb_fn:
        interesting = {
            0x01350350: "CMoveCommand",
            0x01351750: "SupportAttack",
            0x0029E7B0: "post",
            0x0134FDA0: "MassMove",
        }
        off = rva_to_off(sections, fb_fn[0])
        blob = data[off : off + fb_fn[1] - fb_fn[0]]
        for i, b in enumerate(blob):
            if b != 0xE8 or i + 5 > len(blob):
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (fb_fn[0] + i + 5 + rel) & 0xFFFFFFFF
            if tgt in interesting:
                print(f"  0x{fb_fn[0] + i:08x} call 0x{tgt:08x} {interesting[tgt]}")

    print("\n== tiny helpers used by 0x01A31660 ==")
    for rva in (0x01077350, 0x01077370, 0x01056820, 0x00BABF70, 0x01026200):
        dump(data, sections, rva, 32, f"helper 0x{rva:08x}")


if __name__ == "__main__":
    main()
