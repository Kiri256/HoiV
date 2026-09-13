#!/usr/bin/env python3
"""One-off CFront / CTheaterGroup PE dump."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import describe_getter, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")

CFront_VT = 0x0294EE20
CFront_2 = 0x00EF1B50
CFront_4 = 0x00EED000
CTheaterGroup_2 = 0x01621860
CTheaterGroup_VT = 0x029BE6C0


def dump_vt_slots(data, image_base, sections, vt_rva: int, count: int, label: str):
    print(f"=== {label} vtable 0x{vt_rva:08X} slots 0..{count - 1} ===")
    vt_off = rva_to_off(sections, vt_rva)
    if vt_off is None:
        print(f"bad vtable rva 0x{vt_rva:x}")
        return
    for i in range(count):
        va = struct.unpack_from("<Q", data, vt_off + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            print(f"  [{i:3d}] va=0x{va:016X} (out of range)")
            continue
        rva = va - image_base
        fn_off = rva_to_off(sections, rva)
        if fn_off is None:
            print(f"  [{i:3d}] 0x{rva:08X} (no file offset)")
            continue
        b12 = data[fn_off : fn_off + 12]
        desc = describe_getter(data[fn_off : fn_off + 8])
        if desc:
            print(f"  [{i:3d}] 0x{rva:08X} {desc}")
        else:
            hx = " ".join(f"{b:02x}" for b in b12)
            print(f"  [{i:3d}] 0x{rva:08X} {hx}")
    print()


def _modrm_base(modrm: int, rex_b: bool) -> str | None:
    rm = modrm & 7
    if rm == 0:
        return "rax" if not rex_b else "r8"
    if rm == 1:
        return "rcx" if not rex_b else "r9"
    if rm == 2:
        return "rdx" if not rex_b else "r10"
    if rm == 3:
        return "rbx" if not rex_b else "r11"
    if rm == 5:
        return "rbp" if not rex_b else "r13"
    if rm == 6:
        return "rsi" if not rex_b else "r14"
    if rm == 7:
        return "rdi" if not rex_b else "r15"
    return None


def scan_field_accesses(buf: bytes, base_rva: int):
    """Find [reg+disp] for rcx/rdi/rbx/r15 in a byte window."""
    want = {"rcx", "rdi", "rbx", "r15"}
    hits: list[tuple[int, str, int, str]] = []
    i = 0
    while i < len(buf):
        insn_idx = i
        off = base_rva + i
        rex = 0
        while i < len(buf) and 0x40 <= buf[i] <= 0x4F:
            rex = buf[i]
            i += 1
        if i >= len(buf):
            break
        op = buf[i]
        insn_start = base_rva + insn_idx
        rex_w = bool(rex & 0x08)
        rex_b = bool(rex & 0x01)
        rex_r = bool(rex & 0x04)

        # 0F secondary opcodes
        if op == 0x0F and i + 2 < len(buf):
            op2 = buf[i + 1]
            modrm = buf[i + 2]
            mod = (modrm >> 6) & 3
            if mod in (1, 2) and op2 in (0xB6, 0xB7, 0xBE, 0xBF, 0xAF, 0x85):
                base = _modrm_base(modrm, rex_b)
                if base in want:
                    if mod == 1:
                        disp = struct.unpack_from("<b", buf, i + 3)[0]
                        raw = buf[insn_idx : i + 4]
                        hits.append((insn_start, base, disp & 0xFF, " ".join(f"{b:02x}" for b in raw)))
                        i += 4
                        continue
                    if mod == 2 and i + 6 < len(buf):
                        disp = struct.unpack_from("<i", buf, i + 3)[0]
                        raw = buf[insn_idx : i + 7]
                        hits.append((insn_start, base, disp, " ".join(f"{b:02x}" for b in raw)))
                        i += 7
                        continue
            i += 1
            continue

        if i + 1 >= len(buf):
            break
        modrm = buf[i + 1]
        mod = (modrm >> 6) & 3
        ops = {
            0x8B: "mov",
            0x89: "mov",
            0x8D: "lea",
            0x3B: "cmp",
            0x39: "cmp",
            0x85: "test",
            0x83: "arith",
            0x80: "cmp/test byte",
            0xC6: "mov byte",
            0xC7: "mov dword",
            0xFF: "call/indirect",
        }
        if mod in (1, 2) and op in ops:
            base = _modrm_base(modrm, rex_b)
            if base in want:
                if mod == 1 and i + 2 < len(buf):
                    disp = struct.unpack_from("<b", buf, i + 2)[0]
                    raw = buf[insn_idx : i + 3]
                    hits.append((insn_start, base, disp & 0xFF, " ".join(f"{b:02x}" for b in raw)))
                    i += 3
                    continue
                if mod == 2 and i + 5 < len(buf):
                    disp = struct.unpack_from("<i", buf, i + 2)[0]
                    raw = buf[insn_idx : i + 6]
                    hits.append((insn_start, base, disp, " ".join(f"{b:02x}" for b in raw)))
                    i += 6
                    continue
        i += 1

    out = []
    for h in hits:
        disp = h[2]
        if disp < 0:
            disp_u = disp & 0xFFFFFFFF
        else:
            disp_u = disp
        if disp_u > 0x400:
            continue
        out.append(h)
    out.sort(key=lambda x: (x[0], x[2]))
    return out


def main():
    data, image_base, sections = load_pe(EXE)
    print(f"image_base=0x{image_base:x} exe={EXE}")
    print()

    dump_vt_slots(data, image_base, sections, CFront_VT, 41, "CFront")

    print(f"=== CFront[2] 0x{CFront_2:08X} hexdump 220 bytes ===")
    hx220 = hexdump(data, sections, CFront_2, 220)
    # print in 16-byte lines
    off = rva_to_off(sections, CFront_2)
    for row in range(0, 220, 16):
        chunk = data[off + row : off + row + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        print(f"  0x{CFront_2 + row:08X}: {hx}")
    print(f"  flat: {hx220}")
    print()

    buf = data[off : off + 220]
    print(f"=== Field accesses in CFront[2] 220-byte window ===")
    hits = scan_field_accesses(buf, CFront_2)
    for insn_rva, reg, disp, pat in hits:
        print(f"  @0x{insn_rva:08X} [{reg}+0x{disp:X}] ({pat})")
    print()

    print(f"=== CTheaterGroup[2] 0x{CTheaterGroup_2:08X} first 96 bytes ===")
    print(f"  {hexdump(data, sections, CTheaterGroup_2, 96)}")
    print()

    dump_vt_slots(data, image_base, sections, CTheaterGroup_VT, 21, "CTheaterGroup")

    print(f"=== CFront slot[4] fn 0x{CFront_4:08X} first 80 bytes ===")
    print(f"  {hexdump(data, sections, CFront_4, 80)}")


if __name__ == "__main__":
    main()
