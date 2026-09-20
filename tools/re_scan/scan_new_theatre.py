#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off, text_range
from scan_theatre_skip import pdata, fn_for

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000
NAMED = {
    0x02231380: "player post",
    0x0181DD70: "OrderGroup ctor B",
    0x0181B880: "AG ctor B",
    0x01355120: "CSetTheatre factory",
    0x00ED9F40: "CTheatre ctor",
    0x00EE10B0: "AG factory",
    0x021AA4D0: "alloc",
}


def collect_e8(data, sections, targets):
    raw0, raw1, va = text_range(sections)
    hits = {t: [] for t in targets}
    for off in range(raw0, raw1 - 5):
        if data[off] != 0xE8:
            continue
        rva = va + (off - raw0)
        rel = struct.unpack_from("<i", data, off + 1)[0]
        tgt = (rva + 5 + rel) & 0xFFFFFFFF
        if tgt in hits:
            hits[tgt].append(rva)
    return hits


def dump_calls(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in NAMED or 0x01000000 <= tgt <= 0x02240000:
            print(f"  0x{begin + i:08x} -> 0x{tgt:08x} {NAMED.get(tgt, '')}")


def main():
    data, ib, sections = load_pe(EXE)
    for s in (
        b"new_theater_group_button",
        b"new_theater_group_item",
        b"NEW_THEATER_GROUP",
        b"CAssignToTheaterGroupCommand",
        b"CMoveArmiesInTheaterCommand",
        b"CMoveArmyGroupInTheaterCommand",
    ):
        i = data.find(s)
        print(s.decode(), "MISS" if i < 0 else hex(off_to_rva(sections, i) or 0))

    from scan_theatre_ui import find_vt_from_td_name

    for name in (
        b".?AVCAssignToTheaterGroupCommand@@",
        b".?AVCMoveArmiesInTheaterCommand@@",
        b".?AVCMoveArmyGroupInTheaterCommand@@",
        b".?AVCTheatreSelector@@",
    ):
        vts = find_vt_from_td_name(data, ib, sections, name)
        print(name.decode(), [hex(x) for x in vts[:4]])
        if vts:
            off = rva_to_off(sections, vts[0])
            for i in range(12):
                va = struct.unpack_from("<Q", data, off + i * 8)[0]
                if not (IB <= va < IB + 0x4000000):
                    continue
                rva = va - IB
                print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 12)}")


if __name__ == "__main__":
    main()
