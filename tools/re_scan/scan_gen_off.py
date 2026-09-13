from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, describe_getter, hexdump, lea_to, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


def getters(name, vt, n):
    off = rva_to_off(sec, vt)
    print(f"\n{name} getters {hex(vt)}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            continue
        rva = va - ib
        o = rva_to_off(sec, rva)
        desc = describe_getter(data[o : o + 12])
        if desc:
            print(f"  [{i:3d}] {hex(rva)} {desc}")


dump(0x01074470, 160, "CAIGeneral[14]")
dump(0x0107D9C0, 128, "CAIGeneral[13]")
dump(0x01069980, 96, "CAIGeneral ctor area")
getters("CAIGeneral", 0x029613D0, 40)

print("\nLEA CAIGeneral vt")
for lea in lea_to(data, sec, 0x029613D0, 8):
    print(hex(lea), hexdump(data, sec, max(0, lea - 32), 64))

print("\nCAIGeneral[14] callers")
for rva, kind in calls_to(data, sec, 0x01074470)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, max(0, rva - 24), 40)}")

print("\nCAIGeneral[13] callers")
for rva, kind in calls_to(data, sec, 0x0107D9C0)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, max(0, rva - 24), 40)}")

dump(0x010ABA70, 160, "CAIMilitaryMinister[14]")
dump(0x010B53C0, 96, "CAIMilitaryMinister[13]")
dump(0x010BB0D0, 96, "CAIMilitaryMinister[12]")
getters("CAIMilitaryMinister", 0x02962938, 30)
