#!/usr/bin/env python3
"""What 0x010ABA70 / 0x010B4620 post. Country tag path for German org skip."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000

VTS = {
    0x0298A870: "CSetTheatreCommand",
    0x029E3500: "CArmyGroupCommand",
    0x029E35C8: "CAssignToArmyGroupCommand",
    0x029E3690: "CRemoveFromArmyGroupCommand",
    0x029E3758: "CMoveArmiesInTheaterCommand",
    0x029E3820: "CMoveArmyGroupInTheaterCommand",
    0x029E3A78: "COrderAssignCommand",
    0x029E3B40: "COrderUnassignCommand",
    0x029E40B8: "COrderInsertFrontCommand",
    0x029E4180: "COrderNewFrontCommand",
    0x02A0AE00: "CAssignToTheaterGroupCommand",
    0x02707AB0: "CSetCountryReinforcementPriorityCommand",
    0x02A0A3E8: "CAiStoreTotalWantedNrDivisionsCommand",
    0x01137A50: "maybe research ctor not vt",
}

CALLS = {
    0x002A8D90: "GetCountry",
    0x002A8E20: "GetCountry+8",
    0x01077350: "GetCountry wrap",
    0x0029E670: "AI post",
    0x0029E7B0: "AI post2",
    0x010B4620: "theater helper",
    0x00EEE3A0: "front factory",
    0x00EE10B0: "AG factory",
    0x01353520: "SetTheatre ctor",
    0x0181B3E0: "AGCommand ctor A",
    0x0181B880: "AGCommand ctor B",
    0x0181BB10: "AssignAG ctor",
    0x0181E620: "NewFront ctor",
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


def dump_body(data, sections, funcs, rva, label):
    pfn = fn_for(funcs, rva)
    print(f"\n== {label} 0x{rva:08x} pdata={None if not pfn else (hex(pfn[0]), hex(pfn[1]))}")
    begin, end = pfn
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    print("prologue", hexdump(data, sections, begin, 24))
    for i in range(len(blob) - 6):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
            if tgt in CALLS or tgt in VTS:
                print(f"  call 0x{begin + i:08x} -> 0x{tgt:08x} {CALLS.get(tgt, VTS.get(tgt, ''))}")
        # LEA [rip+disp] -> vt
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            tgt = (begin + i + 7 + rel) & 0xFFFFFFFF
            if tgt in VTS:
                print(f"  lea  0x{begin + i:08x} -> 0x{tgt:08x} {VTS[tgt]}")
        if blob[i : i + 2] == b"\x48\xb8":
            imm = struct.unpack_from("<Q", blob, i + 2)[0]
            if IB <= imm < IB + 0x4000000:
                r = imm - IB
                if r in VTS:
                    print(f"  movabs 0x{begin + i:08x} vt {VTS[r]}")


def main():
    data, ib, sections = load_pe(EXE)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    dd = e_lfanew + 24 + 112
    exc_rva, exc_size = struct.unpack_from("<II", data, dd + 3 * 8)
    off = rva_to_off(sections, exc_rva)
    funcs = []
    for i in range(exc_size // 12):
        begin, end, _u = struct.unpack_from("<III", data, off + i * 12)
        if begin < end:
            funcs.append((begin, end))
    funcs.sort()
    dump_body(data, sections, funcs, 0x010ABA70, "minister walk 0x010ABA70")
    dump_body(data, sections, funcs, 0x010B4620, "theater helper 0x010B4620")
    dump_body(data, sections, funcs, 0x010B53B4, "after helper if separate")


if __name__ == "__main__":
    main()
