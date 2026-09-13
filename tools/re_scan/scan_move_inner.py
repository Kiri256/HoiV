from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

ctor = 0x01350350
off = rva_to_off(sec, ctor)
chunk = data[off : off + 180]
e8 = chunk.find(b"\xe8")
print("first e8 at", e8, "bytes", chunk[e8 : e8 + 5].hex())
rel = struct.unpack_from("<i", chunk, e8 + 1)[0]
inner = ctor + e8 + 5 + rel
print("inner ctor", hex(inner & 0xFFFFFFFF))
print(hexdump(data, sec, inner & 0xFFFFFFFF, 240))

print("\nCArmy vt first 50")
vt = rva_to_off(sec, 0x02933D20)
for i in range(50):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    rva = va - ib
    print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 20)}")

print("\n0x01223A10")
print(hexdump(data, sec, 0x01223A10, 80))
print("\n0x002A6C50")
print(hexdump(data, sec, 0x002A6C50, 80))
