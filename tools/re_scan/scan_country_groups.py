from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, describe_getter, hexdump, load_pe, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


def dump_getters(name, vt, n):
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


dump_getters("CCountry", 0x027C0E80, 220)
dump_getters("CArmy", 0x02933D20, 120)

print("\nCArmy[13] and nearby")
vt = rva_to_off(sec, 0x02933D20)
for i in range(10, 20):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    rva = va - ib
    print(f"  [{i:3d}] {hex(rva)} {hexdump(data, sec, rva, 24)}")

print("\nCArmyGroup ctor callers 0xbe0580")
for rva, kind in calls_to(data, sec, 0x00BE0580)[:12]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 40, 56)}")

print("\nCTheaterGroup ctor 0x1620a40 callers")
for rva, kind in calls_to(data, sec, 0x01620A40)[:12]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 32, 48)}")

# lea [rcx+imm32] ret in CCountry range - maybe missed because of 8b 81 vs 48 8d 81
print("\nCCountry vt raw first 30")
off = rva_to_off(sec, 0x027C0E80)
for i in range(30):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if ib <= va < ib + 0x4000000:
        print(f"  [{i:3d}] {hex(va-ib)} {hexdump(data, sec, va-ib, 16)}")
    else:
        print(f"  [{i:3d}] {hex(va)} STOP")
        break
