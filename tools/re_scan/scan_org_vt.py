#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, lea_to, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000

WANT = {
    0x01058380,
    0x010594AB,
    0x0105C430,
    0x0105CCE0,
    0x010ABA70,
    0x010B4620,
    0x010ADFB0,
    0x010A9FC0,
}

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
    0x029BE6C0: "CTheaterGroup",
    0x0292BF58: "CArmyGroup",
    0x0294EE20: "CFront",
}


def dump_vt(data, sections, name, vt, n=80):
    off = rva_to_off(sections, vt)
    print(f"\n{name} 0x{vt:08x}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (IB <= va < IB + 0x4000000):
            continue
        rva = va - IB
        mark = " <<<" if rva in WANT else ""
        if mark or i < 20 or (0x01050000 <= rva <= 0x010C0000):
            print(f"  [{i:3d}] 0x{rva:08x}{mark}")


def lea_in(data, sections, begin, end):
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 6):
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", blob, i + 3)[0]
            tgt = (begin + i + 7 + rel) & 0xFFFFFFFF
            if tgt in VTS:
                print(f"  lea 0x{begin+i:08x} {VTS[tgt]}")


def main():
    data, ib, sections = load_pe(EXE)
    dump_vt(data, sections, "CAIMilitaryMinister", 0x02962938, 80)
    dump_vt(data, sections, "CAIGeneral", 0x029613D0, 40)
    dump_vt(data, sections, "CCountryAI", 0x02710C90, 160)
    dump_vt(data, sections, "CCountryAI alt", 0x02710D20, 40)

    print("\n0x00079176", hexdump(data, sections, 0x00079170, 32))

    print("\nctor LEAs")
    for begin, end, label in (
        (0x0181C890, 0x0181CB57, "0x0181C890"),
        (0x0181DB50, 0x0181DD67, "0x0181DB50"),
        (0x0181D940, 0x0181DA49, "0x0181D940"),
        (0x01058380, 0x0105C000, "0x01058380 first chunk"),
        (0x00F41450, 0x00F423FA, "NewFront parent 0x00F41450"),
        (0x0105CCE0, 0x0105D9C8, "AG poster 0x0105CCE0"),
    ):
        print(label)
        lea_in(data, sections, begin, end)

    print("\nCTheatre vtable search via RTTI")
    i = data.find(b".?AVCTheatre@@\0")
    print(" CTheatre rtti off", i)
    i = data.find(b".?AVCTheaterGroup@@\0")
    print(" CTheaterGroup rtti off", i)


if __name__ == "__main__":
    main()
