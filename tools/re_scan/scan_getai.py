from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


print("CArmyGroup[12] full")
print(hexdump(data, sec, 0x00BE88D0, 128))

print("\nCCountryAI ctor more 0x2a6d10")
print(hexdump(data, sec, 0x002A6D10, 256))

print("\ncallers CCountryAI ctor 0x2a6d10")
for rva, kind in calls_to(data, sec, 0x002A6D10)[:15]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 24, 40)}")

print("\nalloc 0xC28")
pat = bytes([0x28, 0x0C, 0x00, 0x00])
start = raw0
n = 0
while n < 20:
    i = data.find(pat, start, raw1)
    if i < 0:
        break
    rva = off_to_rva(sec, i - 1)
    print(f"  {hex(rva)} {hexdump(data, sec, rva - 8, 28)}")
    n += 1
    start = i + 1

print("\nlea CArmyGroup vt 0x292bf58")
target = 0x0292BF58
hits = []
for off in range(raw0, raw1 - 7):
    if data[off : off + 3] != b"\x48\x8d\x05":
        continue
    rva = off_to_rva(sec, off)
    rel = struct.unpack_from("<i", data, off + 3)[0]
    if rva + 7 + rel == target:
        hits.append(rva)
print([hex(x) for x in hits[:12]])
for rva in hits[:6]:
    print(hex(rva), hexdump(data, sec, rva - 12, 32))

print("\nlea CTheaterGroup vt")
target = 0x029BE6C0
hits = []
for off in range(raw0, raw1 - 7):
    if data[off : off + 3] != b"\x48\x8d\x05":
        continue
    rva = off_to_rva(sec, off)
    rel = struct.unpack_from("<i", data, off + 3)[0]
    if rva + 7 + rel == target:
        hits.append(rva)
print([hex(x) for x in hits[:12]])
for rva in hits[:6]:
    print(hex(rva), hexdump(data, sec, rva - 12, 32))

print("\nlea CAIMilitaryMinister vt 0x2962938")
target = 0x02962938
hits = []
for off in range(raw0, raw1 - 7):
    if data[off : off + 3] != b"\x48\x8d\x05":
        continue
    rva = off_to_rva(sec, off)
    rel = struct.unpack_from("<i", data, off + 3)[0]
    if rva + 7 + rel == target:
        hits.append(rva)
print([hex(x) for x in hits[:8]])
for rva in hits[:6]:
    print(hex(rva), hexdump(data, sec, rva - 16, 40))

print("\nGetArmies which vtable")
fn = 0x006C2410
q = struct.pack("<Q", ib + fn)
start = 0
while True:
    p = data.find(q, start)
    if p < 0:
        break
    rva = off_to_rva(sec, p)
    if rva:
        print("  slot at", hex(rva), "index?", )
    start = p + 1
