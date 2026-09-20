from pathlib import Path
import os
import struct
import sys

capstone_root = Path(os.environ.get("HOIV_CAPSTONE", ""))
if capstone_root:
    sys.path.insert(0, str(capstone_root))
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, off_to_rva, rva_to_off

NO_XREFS = "--no-xrefs" in sys.argv

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, image_base, sections = load_pe(EXE)


def rel_target(rva: int, off: int, size: int):
    if data[off] not in (0xE8, 0xE9) or off + 5 > len(data):
        return None
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return rva + size + rel


def disasm(start: int, stop: int, label: str):
    off = rva_to_off(sections, start)
    if off is None:
        raise SystemExit(f"bad RVA 0x{start:x}")
    code = data[off : off + stop - start]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"\n== {label} 0x{start:08x}-0x{stop:08x} ==")
    for insn in md.disasm(code, image_base + start):
        rva = insn.address - image_base
        text = f"0x{rva:08x}: {insn.mnemonic:7} {insn.op_str}"
        if insn.mnemonic in ("call", "jmp") and insn.bytes[0] in (0xE8, 0xE9):
            target = rel_target(rva, off + (rva - start), insn.size)
            if target is not None:
                text += f"  ; -> 0x{target:08x}"
        if insn.bytes[:2] == b"\xff\x50" and len(insn.bytes) >= 3:
            text += f"  ; indirect slot +0x{insn.bytes[2]:x}"
        if insn.bytes[:2] == b"\xff\x90" and len(insn.bytes) >= 6:
            disp = struct.unpack_from("<i", insn.bytes, 2)[0]
            text += f"  ; indirect slot +0x{disp:x}"
        print(text)


def direct_xrefs(target: int):
    print(f"\n== direct xrefs to 0x{target:08x} ==")
    for name, va, _vsize, raw, raw_size in sections:
        if not name.startswith(b".text"):
            continue
        for off in range(raw, raw + raw_size - 5):
            rva = off_to_rva(sections, off)
            if rva is None:
                continue
            if data[off] in (0xE8, 0xE9):
                if rel_target(rva, off, 5) == target:
                    print(f"0x{rva:08x}: {data[off]:02x} direct branch")


for start, stop, label in (
    (0x002ACF30, 0x002AD340, "CCountryAI[2] Update"),
    (0x010ABA70, 0x010ABCB3, "CAIMilitaryMinister[14]"),
    (0x010B53C0, 0x010B55C5, "CAIMilitaryMinister[13]"),
    (0x010BD2E0, 0x010BD3C3, "CAIMilitaryMinister[15]"),
    (0x010B5DE0, 0x010B5F2B, "CAIMilitaryMinister[16]"),
    (0x010BD3D0, 0x010BD423, "CAIMilitaryMinister[17]"),
    (0x010A6980, 0x010A707E, "CAIMilitaryMinister helper 0x10a6980"),
    (0x010BB750, 0x010BBC3A, "CAIMilitaryMinister helper 0x10bb750"),
    (0x010BC630, 0x010BCD3B, "CAIMilitaryMinister helper 0x10bc630"),
    (0x002ACC80, 0x002ACF30, "CCountryAI[14] create ministers"),
    (0x002ACF20, 0x002ACF30, "CCountryAI[15]"),
    (0x002AB0E0, 0x002AB160, "CCountryAI[16]"),
    (0x00D61C30, 0x00D62D9A, "CMoveCommand-related 0x00d61c30"),
    (0x01A2F800, 0x01A2FE00, "CMoveCommand-related 0x01a2f800"),
    (0x014B8500, 0x014B9100, "CMoveCommand-related player UI"),
):
    disasm(start, stop, label)

if not NO_XREFS:
  for target in (
    0x010B53C0,
    0x010BD2E0,
    0x010B5DE0,
    0x010BD3D0,
    0x0107D9C0,
    0x01074470,
      0x01350350,
  ):
      direct_xrefs(target)
