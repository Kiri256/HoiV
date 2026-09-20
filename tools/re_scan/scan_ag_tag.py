#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
NAMED = {
    0x002A8D90: "GetCountry",
    0x002A8E20: "GetCountry+8",
    0x01077350: "GetCountry wrap",
    0x0029E7B0: "post",
    0x0181B3E0: "AG ctor",
    0x0181BB10: "AssignAG",
    0x0181DB50: "OrderGroup A",
    0x0181DD70: "OrderGroup B",
    0x0181E620: "NewFront",
    0x00ED9F40: "CTheatre ctor",
    0x00EDBF80: "theatre apply",
    0x01353520: "CSetTheatre ctor?",
    0x010B4620: "org helper",
    0x0105CCE0: "AG poster",
    0x0105C5F0: "army poster",
    0x01059820: "army poster2",
    0x0105C430: "parent",
    0x00EEA3E0: "theatre AI",
}


def dump_fn(data, sections, begin, end, label):
    print(f"\n==== {label} 0x{begin:08x}-0x{end:08x}")
    print("  pro", hexdump(data, sections, begin, 32))
    off = rva_to_off(sections, begin)
    blob = data[off : off + (end - begin)]
    for i in range(len(blob) - 4):
        if blob[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (begin + i + 5 + rel) & 0xFFFFFFFF
        if tgt in NAMED:
            ctx = blob[max(0, i - 12) : i].hex()
            print(f"  call 0x{begin+i:08x} -> 0x{tgt:08x} {NAMED[tgt]}  pre={ctx}")
    for i in range(min(len(blob), 0x80)):
        b = blob[i : i + 4]
        if b in (
            b"\x48\x8b\x41\x08",
            b"\x48\x8b\x49\x08",
            b"\x48\x8b\x51\x08",
            b"\x4c\x8b\x41\x08",
            b"\x48\x8b\x41\x18",
            b"\x48\x8b\x49\x18",
            b"\x4c\x8b\x41\x18",
            b"\x48\x8b\x01",
        ):
            print(f"  load 0x{begin+i:08x} {blob[i:i+8].hex()}")


def main():
    data, ib, sections = load_pe(EXE)
    dump_fn(data, sections, 0x0105C430, 0x0105C5EF, "parent 0x0105C430")
    dump_fn(data, sections, 0x0105C5F0, 0x0105CCD5, "army poster 0x0105C5F0")
    dump_fn(data, sections, 0x0105CCE0, 0x0105D9C8, "AG poster 0x0105CCE0")
    dump_fn(data, sections, 0x01059820, 0x01059D18, "army poster2 0x01059820")
    dump_fn(data, sections, 0x01058380, 0x0105961E, "AG walk 0x01058380")
    dump_fn(data, sections, 0x00EEA3E0, 0x00EEAC0B, "theatre 0x00EEA3E0")


if __name__ == "__main__":
    main()
