from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


dump(0x0029E620, 200, "post-AI around C20 check")
dump(0x0029E6F0, 120, "after first assert")
dump(0x00D61F40, 160, "move caller 0xd62")
dump(0x01A2FA40, 160, "move caller 0x1a2")

print("\nRTTI CAIFront / COrdersGroup / CTheater")
for name in (
    b".?AVCAIFront@@",
    b".?AVCOrdersGroup@@",
    b".?AVCTheater@@",
    b".?AVCFront@@",
    b".?AVCAITheater@@",
):
    offs = find_cstr(data, name)
    print(name.decode(), "rva", hex(off_to_rva(sec, offs[0])) if offs else "MISSING")

print("\nHandleAiMicroAttacks LEA")
key = b"HandleAiMicroAttacksForOrdersGroup"
i = data.find(key)
if i >= 0:
    rva = off_to_rva(sec, i)
    print("str", hex(rva))
    for lea in lea_to(data, sec, rva, 8):
        print("lea", hex(lea), hexdump(data, sec, lea - 24, 48))

print("\nCMoveCommand execute 0x01356600 callers")
for rva, kind in calls_to(data, sec, 0x01356600)[:20]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 12), 24)}")
