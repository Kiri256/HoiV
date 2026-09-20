#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def main():
    data, ib, sections = load_pe(EXE)
    print("ctor call A", hexdump(data, sections, 0x00EEA830, 48))
    print("ctor call B", hexdump(data, sections, 0x00EEA970, 48))
    print("0x00EE67F0", hexdump(data, sections, 0x00EE67F0, 24))
    print("0x00EF1920", hexdump(data, sections, 0x00EF1920, 24))
    print("0x00EDBC50", hexdump(data, sections, 0x00EDBC50, 24))
    print("0x006F6070", hexdump(data, sections, 0x006F6070, 24))
    print("0x00BAB570", hexdump(data, sections, 0x00BAB570, 16))


if __name__ == "__main__":
    main()
