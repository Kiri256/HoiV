#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off, text_range
from scan_theatre_skip import pdata, fn_for

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = pdata(data, sections)
    raw0, raw1, va = text_range(sections)
    pat = struct.pack("<I", 0x2F0D)
    print("imm 0x2F0D in .text")
    n = 0
    start = raw0
    while n < 30:
        i = data.find(pat, start, raw1)
        if i < 0:
            break
        rva = va + (i - raw0)
        pfn = fn_for(funcs, rva)
        ctx = hexdump(data, sections, max(va, rva - 8), 24)
        print(f"  0x{rva:08x} fn={None if not pfn else hex(pfn[0])} {ctx}")
        n += 1
        start = i + 1

    print("\nCSetTheatre[11]", hexdump(data, sections, 0x01357E70, 16))
    print("factory +0x28 rip")
    # 0x01355160 mov rcx, [rip+0x1fbce81]
    rel = struct.unpack_from("<i", data, rva_to_off(sections, 0x01355163))[0]
    tgt = (0x01355167 + rel) & 0xFFFFFFFF
    print(hex(tgt), hexdump(data, sections, tgt, 16) if rva_to_off(sections, tgt) else "bss")


if __name__ == "__main__":
    main()
