from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


dump(0x01350350, 220, "CMoveCommand ctor")
dump(0x013596B0, 32, "CanExecute + next")
dump(0x01356600, 32, "Execute + next")
dump(0x0029E670, 200, "real post-AI 0x29e670")
dump(0x00D61EC0, 200, "fn containing 0xd62020")
dump(0x01A2F9C0, 220, "fn containing 0x1a2faee")

print("\nCArmy simple getters")
vt = rva_to_off(sec, 0x02933D20)
for i in range(120):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    off = rva_to_off(sec, rva)
    b = data[off : off + 16]
    # mov rax,[rcx+imm32]; ret
    if b[0:3] == bytes.fromhex("48 8b 81") and b[7] == 0xC3:
        imm = struct.unpack_from("<I", b, 3)[0]
        print(f"  [{i:3d}] +0x{imm:x} ptr/qword")
    elif b[0:3] == bytes.fromhex("48 8b 41") and b[4] == 0xC3:
        print(f"  [{i:3d}] +0x{b[3]:x} ptr8")
    elif b[0:3] == bytes.fromhex("8b 81") and b[6] == 0xC3:
        imm = struct.unpack_from("<I", b, 2)[0]
        print(f"  [{i:3d}] +0x{imm:x} dword")
    elif b[0] == 0x8B and b[1] == 0x41 and b[3] == 0xC3:
        print(f"  [{i:3d}] +0x{b[2]:x} dword8")

print("\ncallers of fn 0x00d61xxx / who calls around d62000")
# find function start of d62020: look backwards for cc cc or ret
dump(0x00D61D00, 48, "earlier d61d00")

print("\ncalls to 0x00d61f00-ish: find start by scanning back")
raw = rva_to_off(sec, 0x00D61C00)
for delta in range(0, 0x400):
    o = raw + delta
    if data[o : o + 5] == bytes.fromhex("40 53 48 83 ec") or data[o : o + 4] == bytes.fromhex(
        "48 89 5c 24"
    ):
        rva = 0x00D61C00 + delta
        if rva <= 0x00D62020:
            print("possible start", hex(rva), hexdump(data, sec, rva, 12))
