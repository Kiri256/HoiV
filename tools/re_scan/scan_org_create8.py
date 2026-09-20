#!/usr/bin/env python3
"""0x00EEA3E0 is hot; find CTheatre ctor vs deploy/recruit inside it."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def main():
    data, ib, sections = load_pe(EXE)
    print("CTheatre ctor 0x00ED9F40", hexdump(data, sections, 0x00ED9F40, 24))
    begin, end = 0x00EEA3E0, 0x00EEAC0B
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    print("\n0x00EEA3E0 all E8")
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if 0x00100000 <= tgt <= 0x03000000:
            print(f"  0x{begin+i:08x} -> 0x{tgt:08x}")

    print("\nRTTI recruit/deploy/train command")
    start = 0
    n = 0
    while n < 40:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("latin1", "replace")
        low = name.lower()
        if ("command" in low or low.endswith("action@@")) and any(
            k in low
            for k in (
                "recruit",
                "deploy",
                "train",
                "createunit",
                "create_unit",
                "divisiontemplate",
                "conscript",
                "mobilize",
            )
        ):
            print(f"  {name}")
            n += 1
        start = i + 1


if __name__ == "__main__":
    main()
