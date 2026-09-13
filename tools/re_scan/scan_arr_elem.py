from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("lea +0x548 site 0xce7120")
print(hexdump(data, sec, 0x00CE7100, 96))
print("\n0xd9d6c0")
print(hexdump(data, sec, 0x00D9D6C0, 80))
print("\n0xce5fe0")
print(hexdump(data, sec, 0x00CE5FC0, 80))

print("\nlea +0x278 0x6c29e0 callers")
for rva, kind in calls_to(data, sec, 0x006C29E0)[:10]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 8, 32)}")

print("\n+0xF88 after call 0x1d3084")
print(hexdump(data, sec, 0x001D3070, 48))
print("\n+0xFA0 after 0x1c776d")
print(hexdump(data, sec, 0x001C7750, 64))

print("\nCFront[2] 0xef1b50")
print(hexdump(data, sec, 0x00EF1B50, 80))
print("\nCFront[8] 0xee8720")
print(hexdump(data, sec, 0x00EE8720, 64))

print("\nCTheaterGroup getters")
from scan import rva_to_off
import struct
off = rva_to_off(sec, 0x029BE6C0)
for i in range(24):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    print(f"  [{i:3d}] {hex(rva)} {hexdump(data, sec, rva, 14)}")
