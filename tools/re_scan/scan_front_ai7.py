from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("d61c30", hexdump(data, sec, 0x00D61C30, 32))
print("callers")
for rva, kind in calls_to(data, sec, 0x00D61C30)[:15]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 20), 32)}")

# find 1a2 function start
off = rva_to_off(sec, 0x01A2F000)
for delta in range(0, 0xC00):
    o = off + delta
    if data[o - 1] == 0xCC and data[o] in (0x40, 0x48, 0x4C) and data[o + 1] in (
        0x53, 0x55, 0x56, 0x57, 0x89, 0x83, 0x8B,
    ):
        rva = 0x01A2F000 + delta
        if rva <= 0x01A2FAEE:
            print("1a2 cand", hex(rva), hexdump(data, sec, rva, 16))

print("\n1a2fa00", hexdump(data, sec, 0x01A2F900, 24))
print("1a2e800", hexdump(data, sec, 0x01A2E800, 16))
