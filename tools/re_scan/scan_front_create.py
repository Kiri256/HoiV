from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import describe_getter, hexdump, lea_to, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def getters(name, vt, n):
    off = rva_to_off(sec, vt)
    print(f"\n{name} {hex(vt)}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            continue
        rva = va - ib
        o = rva_to_off(sec, rva)
        desc = describe_getter(data[o : o + 12])
        if desc:
            print(f"  [{i:3d}] {hex(rva)} {desc}")


getters("CFront", 0x0294EE20, 40)
getters("CTheaterGroup", 0x029BE6C0, 30)
getters("CArmyGroup", 0x0292BF58, 24)

print("\nCFront[2] 0xef1b50")
print(hexdump(data, sec, 0x00EF1B50, 160))
print("\nAG create 0xee10c0")
print(hexdump(data, sec, 0x00EE10C0, 160))
print("\nCFront ctor 0xeee400")
print(hexdump(data, sec, 0x00EEE400, 200))
print("\nCFront 0xeee660")
print(hexdump(data, sec, 0x00EEE660, 80))
print("\nTG 0x1620940")
print(hexdump(data, sec, 0x01620940, 80))
print("\nTG 0x16209b0")
print(hexdump(data, sec, 0x016209B0, 64))
print("\nTG 0x1620a40")
print(hexdump(data, sec, 0x01620A40, 80))

print("\nLEA CFront vt")
for lea in lea_to(data, sec, 0x0294EE20, 8)[:12]:
    print(hex(lea), hexdump(data, sec, max(0, lea - 24), 48))
