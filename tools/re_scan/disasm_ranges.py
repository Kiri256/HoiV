#!/usr/bin/env python3
"""Focused x64 disassembly for the pinned HOI4 executable."""

from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

capstone_root = Path(os.environ.get("HOIV_CAPSTONE", ""))
if capstone_root:
    sys.path.insert(0, str(capstone_root))
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, off_to_rva, rva_to_off


def rel_target(rva: int, off: int, size: int, data: bytes) -> int | None:
    if data[off] not in (0xE8, 0xE9) or off + 5 > len(data):
        return None
    return (rva + size + struct.unpack_from("<i", data, off + 1)[0]) & 0xFFFFFFFF


def dump(data: bytes, image_base: int, sections, start: int, stop: int) -> None:
    off = rva_to_off(sections, start)
    if off is None:
        raise SystemExit(f"bad RVA 0x{start:x}")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"\n== 0x{start:08x}-0x{stop:08x} ==")
    for insn in md.disasm(data[off : off + stop - start], image_base + start):
        rva = insn.address - image_base
        line = f"0x{rva:08x}: {insn.mnemonic:7} {insn.op_str}"
        if insn.bytes and insn.bytes[0] in (0xE8, 0xE9):
            target = rel_target(rva, off + rva - start, insn.size, data)
            if target is not None:
                line += f"  ; -> 0x{target:08x}"
        if insn.bytes[:2] == b"\xff\x50" and len(insn.bytes) >= 3:
            line += f"  ; indirect slot +0x{insn.bytes[2]:x}"
        if insn.bytes[:2] == b"\xff\x90" and len(insn.bytes) >= 6:
            line += f"  ; indirect slot +0x{struct.unpack_from('<i', insn.bytes, 2)[0]:x}"
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--stop", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--exe", type=Path, default=Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe"))
    args = parser.parse_args()
    data, image_base, sections = load_pe(args.exe)
    dump(data, image_base, sections, args.start, args.stop)


if __name__ == "__main__":
    main()
