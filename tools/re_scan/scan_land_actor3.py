#!/usr/bin/env python3
"""Find the no-general land-move actor: order execute, queue action, country mass move."""

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

CTORS = {
    0x01350350: "CMoveCommand",
    0x013516F0: "CStrategicRedeploy",
    0x01351750: "CSupportAttack",
    0x0134FDA0: "CMassMove",
    0x01352000: "CQueueUnitAction",
    0x0134F9D0: "CCancelMovement",
    0x0029E7B0: "post29e7b0",
    0x0029E670: "post29e670",
    0x002A8D90: "GetCountry",
    0x01A31660: "army-list mover",
    0x01A2ED80: "per-army move",
}


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


def slot(data, ib, sections, vt, i):
    off = rva_to_off(sections, vt + i * 8)
    if off is None:
        return 0
    va = struct.unpack_from("<Q", data, off)[0]
    return va - ib if ib <= va < ib + IB_SPAN else 0


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


def calls_in(data, sections, start, stop):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    out = []
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (start + i + 5 + rel) & 0xFFFFFFFF
        out.append((start + i, tgt))
    return out


def scan_fn(data, sections, funcs, start, stop, label):
    print(f"\n== {label} [0x{start:08x},0x{stop:08x}) size=0x{stop - start:x}")
    print("prologue", hexdump(data, sections, start, 32))
    hits = []
    for site, tgt in calls_in(data, sections, start, stop):
        name = CTORS.get(tgt)
        if name:
            hits.append((site, tgt, name))
            print(f"  0x{site:08x} -> 0x{tgt:08x} {name}")
    if not hits:
        print("  no tracked ctors/post")
    return hits


def lea_to_vt(data, sections, vt):
    raw0, raw1, _ = text_range(sections)
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
    return sites


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}
    name_to_vt = {}
    for vt, name in vt_map.items():
        name_to_vt.setdefault(name, vt)

    print("== CCountryAI first 8 and [127] ==")
    cai = 0x02710C90
    for i in list(range(8)) + [15, 16, 126, 127, 128]:
        rva = slot(data, ib, sections, cai, i)
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16) if rva else ''}")

    print("\n== 0x002A8E20 ==")
    print(hexdump(data, sections, 0x002A8E20, 24))
    print("GetCountry 0x002A8D90", hexdump(data, sections, 0x002A8D90, 24))

    print("\n== 0x00529210 (0x01086cb0 first call) ==")
    print(hexdump(data, sections, 0x00529210, 48))
    fn = fn_for(funcs, 0x00529210)
    print("pdata", None if not fn else (hex(fn[0]), hex(fn[1])))
    for q in find_qword(data, ib, sections, 0x00529210 if not fn else fn[0]):
        info = vt_near(vt_map, q)
        print("  qword", hex(q), info)

    print("\n== 0x00be5780 ==")
    print(hexdump(data, sections, 0x00BE5780, 48))

    tracked = [
        ("COrderInstance[2]", 0x0103B460, 0x0103B460 + 0x4000),
        ("COrdersGroup[2]", 0x00BEDF00, 0x00BEDF00 + 0x2000),
        ("CFront[2]", 0x00EF1B50, 0x00EF1B50 + 0x2000),
        ("CTheatre[2]", 0x00EF26B0, 0x00EF26B0 + 0x2000),
        ("CArmyGroup[2]", 0x00BEDE70, 0x00BEDE70 + 0x800),
        ("CCountryAI Update[2]", 0x002ACF30, 0x002AD340),
        ("CCountryAI[127]", 0x002AB450, 0x002ABDF3),
        ("CAIMilitaryMinister[14]", 0x010ABA70, 0x010ABCB3),
        ("CAIMilitaryMinister[13]", 0x010B53C0, 0x010B55C5),
        ("0x0107d190 redeploy-site", 0x0107D190, 0x0107D675),
        ("0x01A34190 sibling", 0x01A34190, 0x01A36B21),
        ("0x01A36B30 fallback", 0x01A36B30, 0x01A378A4),
    ]
    # clamp to pdata if available
    for i, (label, a, b) in enumerate(tracked):
        fn = fn_for(funcs, a)
        if fn:
            tracked[i] = (label, fn[0], fn[1])

    for item in tracked:
        scan_fn(data, sections, funcs, item[1], item[2], item[0])

    print("\n== CQueueUnitAction ctor callers ==")
    for rva, kind in calls_to(data, sections, 0x01352000)[:25]:
        fn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        if fn:
            for q in find_qword(data, ib, sections, fn[0]):
                info = vt_near(vt_map, q)
                if info:
                    print(f"    {info[1]} [{info[2]}]")

    print("\n== COrderExecuteCommand ctor via LEA ==")
    vt = name_to_vt.get(".?AVCOrderExecuteCommand@@", 0)
    print("vt", hex(vt))
    for site in lea_to_vt(data, sections, vt)[:8]:
        fn = fn_for(funcs, site)
        print(f"  lea 0x{site:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        if fn and fn[1] - fn[0] < 0x180:
            for rva, kind in calls_to(data, sections, fn[0])[:12]:
                pfn = fn_for(funcs, rva)
                print(f"    {kind} 0x{rva:08x} fn={f'[0x{pfn[0]:08x},0x{pfn[1]:08x})' if pfn else '?'}")
                if pfn:
                    for q in find_qword(data, ib, sections, pfn[0]):
                        info = vt_near(vt_map, q)
                        if info:
                            print(f"      {info[1]} [{info[2]}]")

    print("\n== who virtual-calls CAIGeneral[13] slot 0x68 ==")
    raw0, raw1, _ = text_range(sections)
    n = 0
    for off in range(raw0, raw1 - 6):
        # ff 50 68  or ff 90 68 00 00 00
        if data[off] == 0xFF and data[off + 1] == 0x50 and data[off + 2] == 0x68:
            rva = off_to_rva(sections, off)
            fn = fn_for(funcs, rva)
            print(f"  call [reg+0x68] 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            n += 1
        elif data[off] == 0xFF and data[off + 1] == 0x90 and struct.unpack_from("<I", data, off + 2)[0] == 0x68:
            rva = off_to_rva(sections, off)
            fn = fn_for(funcs, rva)
            print(f"  call [rax+0x68] 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            n += 1
        if n >= 25:
            break
    print("slot13 hits printed", n)

    print("\n== who virtual-calls CCountryAI[127] slot 0x3F8 ==")
    n = 0
    for off in range(raw0, raw1 - 6):
        if data[off] == 0xFF and data[off + 1] == 0x90 and struct.unpack_from("<I", data, off + 2)[0] == 0x3F8:
            rva = off_to_rva(sections, off)
            fn = fn_for(funcs, rva)
            print(f"  call [rax+0x3F8] 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            n += 1
            if n >= 20:
                break
    print("slot127 hits", n)


if __name__ == "__main__":
    main()
