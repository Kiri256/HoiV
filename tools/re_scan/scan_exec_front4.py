#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
IB = 0x140000000


def rel_hits(data, sections, target):
    raw0, raw1, _ = text_range(sections)
    out = []
    for off in range(raw0, raw1 - 5):
        if data[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        rva = off_to_rva(sections, off)
        if rva is not None and rva + 5 + rel == target:
            out.append((rva, "call" if data[off] == 0xE8 else "jmp"))
    return out


def ff_hits(data, sections, target):
    # FF 15 / FF 25 RIP-relative to a qword holding the fn
    q = struct.pack("<Q", IB + target)
    hits = []
    p = 0
    while True:
        i = data.find(q, p)
        if i < 0:
            break
        rva = off_to_rva(sections, i)
        hits.append(rva)
        p = i + 1
        if len(hits) >= 20:
            break
    return hits


def main():
    data, ib, sections = load_pe(EXE)
    for tgt, label in (
        (0x00247630, "AG factory AI"),
        (0x01059D36, "mid org exec/front"),
        (0x01059D00, "near org"),
        (0x01A21B10, "exec poster"),
        (0x01A23290, "newfront poster"),
        (0x00F3B2F0, "exec helper"),
        (0x017A77AC, "exec caller A"),
        (0x017A7D8C, "exec caller B"),
    ):
        hits = rel_hits(data, sections, tgt)
        print(f"\n{label} 0x{tgt:08x} rel={len(hits)}")
        for rva, kind in hits[:16]:
            print(f"  {kind} 0x{rva:08x} {hexdump(data, sections, max(0, rva - 8), 24)}")
        qh = ff_hits(data, sections, tgt)
        print("  qword xrefs", [hex(x) for x in qh[:8]])

    print("\nCCountryAI 0x247xxx slots")
    off = rva_to_off(sections, 0x02710C90)
    for i in range(220):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if IB <= va < IB + 0x4000000:
            rva = va - IB
            if 0x00247000 <= rva <= 0x00248000:
                print(f"  [{i}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")

    print("\n0x00247630 body 160")
    print(hexdump(data, sections, 0x00247630, 160))
    print("\n0x01059600..0x01059E20")
    print("59620", hexdump(data, sections, 0x01059620, 24))
    print("59c00", hexdump(data, sections, 0x01059C00, 24))
    print("59d00", hexdump(data, sections, 0x01059D00, 32))
    print("59d36", hexdump(data, sections, 0x01059D36, 48))

    print("\n0x01081FE0 calls into 0x1059xxx / 0x1a21 / 0x1a23 / 0x247")
    off = rva_to_off(sections, 0x01081FE0)
    blob = data[off : off + (0x01083021 - 0x01081FE0)]
    for i in range(len(blob) - 4):
        if blob[i] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (0x01081FE0 + i + 5 + rel) & 0xFFFFFFFF
        if tgt in (0x00247630, 0x01059D36, 0x01A21B10, 0x01A23290, 0x01058380, 0x0105CCE0, 0x00F3B2F0):
            print(f"  {'call' if blob[i]==0xE8 else 'jmp'} 0x{0x01081FE0+i:08x} -> 0x{tgt:08x}")

    print("\n0x01058380 same")
    off = rva_to_off(sections, 0x01058380)
    blob = data[off : off + (0x0105961E - 0x01058380)]
    for i in range(len(blob) - 4):
        if blob[i] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (0x01058380 + i + 5 + rel) & 0xFFFFFFFF
        if tgt in (0x00247630, 0x01059D36, 0x01A21B10, 0x01A23290, 0x0105CCE0, 0x00F3B2F0, 0x01081FE0):
            print(f"  {'call' if blob[i]==0xE8 else 'jmp'} 0x{0x01058380+i:08x} -> 0x{tgt:08x}")

    print("\nexec caller A context 0x017A7700")
    print(hexdump(data, sections, 0x017A7700, 48))
    print("exec caller A 0x017A77AC")
    print(hexdump(data, sections, 0x017A77AC, 80))

    # CCountryAI[145] style thunks near 0x247630
    print("\nthunks 0x247000-0x248000 that jmp 0x00247630")
    raw = rva_to_off(sections, 0x00247000)
    blob = data[raw : raw + 0x1000]
    for i in range(len(blob) - 5):
        if blob[i] == 0xE9:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (0x00247000 + i + 5 + rel) & 0xFFFFFFFF
            if tgt == 0x00247630:
                print(f"  jmp at 0x{0x00247000+i:08x}")
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (0x00247000 + i + 5 + rel) & 0xFFFFFFFF
            if tgt == 0x00247630:
                print(f"  call at 0x{0x00247000+i:08x}")


if __name__ == "__main__":
    main()
