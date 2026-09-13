#!/usr/bin/env python3
"""One-shot RE dump for front/theater/AG factory."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, hexdump, calls_to, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def dump_label(label: str, rva: int, n: int, data, sections):
    print(f"\n=== {label} ===")
    print(f"RVA 0x{rva:08X}  ({n} bytes)")
    print(hexdump(data, sections, rva, n))


def note_plus18(label: str, rva: int, n: int, data, sections):
    dump_label(label, rva, n, data, sections)
    off = rva_to_off(sections, rva)
    if off is None:
        return
    chunk = data[off : off + n]
    patterns = {
        b"\x48\x89\x7b\x18": "[rdi+0x18] mov [rbx+0x18], rdi",
        b"\x48\x89\x73\x18": "[rsi+0x18] mov [rbx+0x18], rsi",
        b"\x4c\x89\x73\x18": "[rsi+0x18] mov [rbx+0x18], r14",
        b"\x4c\x89\x7b\x18": "[rdi+0x18] mov [rbx+0x18], r15",
        b"\x48\x89\x43\x18": "[rcx+0x18] mov [rbx+0x18], rax",
        b"\x48\x89\x4b\x18": "[rcx+0x18] mov [rbx+0x18], rcx",
        b"\x4c\x89\x43\x18": "[rcx+0x18] mov [rbx+0x18], r8",
        b"\x4c\x89\x4b\x18": "[rcx+0x18] mov [rbx+0x18], r9",
        b"\x48\x8b\x79\x18": "[rcx+0x18] mov rdi, [rcx+0x18]",
        b"\x48\x8b\x71\x18": "[rcx+0x18] mov rsi, [rcx+0x18]",
        b"\x4c\x8b\x71\x18": "[rcx+0x18] mov r14, [rcx+0x18]",
        b"\x4c\x8b\x79\x18": "[rcx+0x18] mov r15, [rcx+0x18]",
        b"\x48\x8b\x47\x18": "[rdi+0x18] mov rax, [rdi+0x18]",
        b"\x48\x8b\x77\x18": "[rsi+0x18] mov rsi, [rsi+0x18]",
        b"\x4c\x8b\x77\x18": "[rsi+0x18] mov r14, [rsi+0x18]",
        b"\x4c\x8b\x7f\x18": "[rdi+0x18] mov r15, [rdi+0x18]",
    }
    hits = []
    for i in range(len(chunk) - 3):
        for pat, desc in patterns.items():
            if chunk[i : i + len(pat)] == pat:
                hits.append((rva + i, desc, pat.hex()))
    if hits:
        print("  +0x18 patterns:")
        for addr, desc, hx in hits:
            print(f"    0x{addr:08X}: {desc} ({hx})")
    else:
        print("  (no obvious [rdi/rcx+0x18] encodings in range)")


def calls_with_context(label: str, target: int, data, sections, limit=20, ctx=40):
    print(f"\n=== {label} ===")
    print(f"calls_to 0x{target:08X}")
    hits = calls_to(data, sections, target)
    print(f"total callers: {len(hits)}")
    for i, (rva, kind) in enumerate(hits[:limit]):
        print(f"\n--- caller {i + 1}: 0x{rva:08X} ({kind}) ---")
        start = max(0, rva - ctx)
        pre = hexdump(data, sections, start, ctx)
        site = hexdump(data, sections, rva, 8)
        print(f"  -{ctx} bytes: {pre}")
        print(f"  call site: {site}")


def main():
    data, image_base, sections = load_pe(EXE)
    print(f"image_base=0x{image_base:x}  exe={EXE}")

    dump_label("1. CFront create (r14 before mov [rbx+0x18], r14)", 0x00EEE380, 140, data, sections)

    dump_label("2. AG factory prologue confirm", 0x00EE10B0, 96, data, sections)

    dump_label("3. theater small ctor (rdx -> +0x18)", 0x01620900, 80, data, sections)

    note_plus18("4. CTheaterGroup[2]", 0x01621860, 128, data, sections)

    dump_label("5. CFront[8]", 0x00EE8720, 64, data, sections)

    calls_with_context("6. GetCommandGroups / lea +0x548", 0x006C2680, data, sections, limit=20, ctx=40)

    print("\n=== 7. calls_to AG factory ===")
    for tgt in (0x00EE10B0, 0x00EE10A0, 0x00EE10C0):
        hits = calls_to(data, sections, tgt)
        print(f"  0x{tgt:08X}: {len(hits)} callers")
        if hits:
            calls_with_context(f"7. AG factory @ 0x{tgt:08X}", tgt, data, sections, limit=20, ctx=40)
            break

    dump_label("8. CAIMilitaryMinister[12] hook steal", 0x010BB0D0, 24, data, sections)


if __name__ == "__main__":
    main()
