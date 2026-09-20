#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def main():
    data, ib, sections = load_pe(EXE)
    start = 0
    shown = 0
    while shown < 80:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        name = data[i:end].decode("ascii", "replace")
        low = name.lower()
        if "theat" in low:
            rva = off_to_rva(sections, i)
            print(f"0x{rva or 0:08x} {name}")
            shown += 1
        start = i + 1


if __name__ == "__main__":
    main()
