from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import describe_getter, hexdump, load_pe, rva_to_off

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
        elif i < 8:
            print(f"  [{i:3d}] {hex(rva)} {hexdump(data, sec, rva, 14)}")


getters("CFront", 0x0294EE20, 36)
getters("CTheaterGroup", 0x029BE6C0, 20)
getters("CArmyGroup", 0x0292BF58, 20)
print("\nCFront[2]", hexdump(data, sec, 0x00EF1B50, 128))
print("\nAG create", hexdump(data, sec, 0x00EE1080, 180))
print("\nctor eee400", hexdump(data, sec, 0x00EEE400, 180))
print("\nctor eee660", hexdump(data, sec, 0x00EEE660, 80))
print("\nTG 1620940", hexdump(data, sec, 0x01620940, 96))
print("\nTG 1620a40", hexdump(data, sec, 0x01620A40, 80))
print("\nCFront[2] slots raw")
off = rva_to_off(sec, 0x0294EE20)
for i in range(8):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    print(i, hex(va - ib), hexdump(data, sec, va - ib, 16))
