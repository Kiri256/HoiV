#!/usr/bin/env python3
"""What DoCountryHourlyUpdates actually calls."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IB_SPAN = 0x4000000

INTERESTING = {
    0x002ACF30: "CCountryAI[2] Update",
    0x002A7DE0: "CCountryAI[145] mass-move thunk",
    0x002AB450: "CMassMove body",
    0x002A8D90: "GetCountry",
    0x010ABA70: "mil min [14]",
    0x010B53C0: "mil min [13]",
    0x01074470: "CAIGeneral[14]",
    0x0107D9C0: "CAIGeneral[13]",
    0x01A31660: "army-list mover",
    0x01A2ED80: "per-army move",
    0x0029E7B0: "post",
    0x01350350: "CMoveCommand",
    0x0134FDA0: "CMassMove ctor",
    0x01820B40: "SetExecutionType ctor",
    0x0181DA50: "OrderExecute ctor",
    0x00EEE3A0: "CFront factory",
    0x00EE10B0: "CArmyGroup factory",
    0x010BB0D0: "mil create generals",
    0x010B4620: "mil theater helper",
    0x002AA550: "CCountryAI Update callee",
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


def vt_near(vt_map, slot_rva):
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x800:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}

    start, stop = 0x001DF130, 0x001E0248
    print(f"== DoCountryHourlyUpdates fn [0x{start:08x},0x{stop:08x}) ==")
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    slots = {}
    for i, b in enumerate(blob):
        if b == 0xE8 and i + 5 <= len(blob):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (start + i + 5 + rel) & 0xFFFFFFFF
            name = INTERESTING.get(tgt)
            if name:
                print(f"  0x{start + i:08x} call 0x{tgt:08x} {name}")
            elif tgt in (0x002ACC80, 0x002AB0E0, 0x002AA100):
                print(f"  0x{start + i:08x} call 0x{tgt:08x} CCountryAI-ish")
        if b == 0xFF and i + 6 <= len(blob):
            if blob[i + 1] in (0x50, 0x51, 0x52, 0x56, 0x57):
                disp = blob[i + 2]
                slots.setdefault(disp, []).append(start + i)
            elif blob[i + 1] == 0x90:
                disp = struct.unpack_from("<i", blob, i + 2)[0]
                if 0 < disp < 0x800:
                    slots.setdefault(disp, []).append(start + i)
    print("indirect slots:")
    for disp, sites in sorted(slots.items()):
        print(f"  +0x{disp:x} slot~{disp // 8} x{len(sites)} first=0x{sites[0]:08x}")

    print("\n== 0x002ac2e0 (calls Update-callee, large CCountryAI fn) ==")
    fn = fn_for(funcs, 0x002AC2E0)
    print("pdata", None if not fn else (hex(fn[0]), hex(fn[1])))
    if fn:
        print(hexdump(data, sections, fn[0], 48))
        off = rva_to_off(sections, fn[0])
        blob = data[off : off + fn[1] - fn[0]]
        for i, b in enumerate(blob):
            if b != 0xE8 or i + 5 > len(blob):
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (fn[0] + i + 5 + rel) & 0xFFFFFFFF
            name = INTERESTING.get(tgt, "")
            if name or (0x002A0000 <= tgt <= 0x002B0000) or (0x010A0000 <= tgt <= 0x010C0000):
                print(f"  0x{fn[0] + i:08x} -> 0x{tgt:08x} {name}")

    print("\n== minister ctor vtables ==")
    for site, disp in ((0x01136DE7, 0x015D0CC2), (0x01A57377, 0x00FB306A)):
        dest = (site + 7 + disp) & 0xFFFFFFFF
        print(f"  lea 0x{site:08x} -> vt 0x{dest:08x} {vt_map.get(dest)}")

    print("\n== 0x010b4620 interesting calls ==")
    fn = fn_for(funcs, 0x010B4620)
    if fn:
        off = rva_to_off(sections, fn[0])
        blob = data[off : off + fn[1] - fn[0]]
        for i, b in enumerate(blob):
            if b != 0xE8 or i + 5 > len(blob):
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (fn[0] + i + 5 + rel) & 0xFFFFFFFF
            name = INTERESTING.get(tgt)
            if name:
                print(f"  0x{fn[0] + i:08x} -> 0x{tgt:08x} {name}")


if __name__ == "__main__":
    main()
