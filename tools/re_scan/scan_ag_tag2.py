#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
capstone_root = Path(os.environ.get("HOIV_CAPSTONE", ""))
if capstone_root:
    sys.path.insert(0, str(capstone_root))
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, image_base, sections = load_pe(EXE)


def rel_target(rva, off, size):
    if data[off] not in (0xE8, 0xE9) or off + 5 > len(data):
        return None
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return (rva + size + rel) & 0xFFFFFFFF


def disasm(start, stop, label):
    off = rva_to_off(sections, start)
    code = data[off : off + stop - start]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"\n== {label} 0x{start:08x}-0x{stop:08x} ==")
    n = 0
    for insn in md.disasm(code, image_base + start):
        rva = insn.address - image_base
        text = f"0x{rva:08x}: {insn.mnemonic:7} {insn.op_str}"
        if insn.mnemonic in ("call", "jmp") and insn.bytes[0] in (0xE8, 0xE9):
            target = rel_target(rva, off + (rva - start), insn.size)
            if target is not None:
                text += f"  ; -> 0x{target:08x}"
        print(text)
        n += 1
        if n >= 80:
            break


disasm(0x0105C430, 0x0105C5F0, "parent")
disasm(0x01058380, 0x01058480, "walk head")
disasm(0x01059480, 0x01059500, "walk call parent")
disasm(0x0105C4E0, 0x0105C540, "parent call posters")
disasm(0x0105CCE0, 0x0105CD80, "AG poster head")
disasm(0x0105C5F0, 0x0105C690, "army poster head")
disasm(0x01059820, 0x010598C0, "army2 head")
disasm(0x01081FE0, 0x01082080, "0x01081FE0 head")
disasm(0x01082F00, 0x01082F50, "call 0x01058380 site")
