from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


print("CAIGeneral[7] 0x1076740")
print(hexdump(data, sec, 0x01076740, 32))

print("\nCArmyGroup[12] 0xbe88d0")
print(hexdump(data, sec, 0x00BE88D0, 64))
print("\nCArmyGroup[11] 0xbe5fc0")
print(hexdump(data, sec, 0x00BE5FC0, 16))
print("\nCOrdersGroup[11] 0xbe5fd0")
print(hexdump(data, sec, 0x00BE5FD0, 48))
print("\nCOrdersGroup[16] 0xbe95c0")
print(hexdump(data, sec, 0x00BE95C0, 16))
print("\nCTheaterGroup[2] 0x1621860")
print(hexdump(data, sec, 0x01621860, 64))
print("\nCTheaterGroup[8] 0x1620ee0")
print(hexdump(data, sec, 0x01620EE0, 48))

print("\nCCountryAI ctor 0x2a6d00")
print(hexdump(data, sec, 0x002A6D00, 128))
print("\nCCountryAI 0x2a7600")
print(hexdump(data, sec, 0x002A7600, 80))

print("\nCCountry ALL simple getters")
vt = rva_to_off(sec, 0x027C0E80)
for i in range(0, 250):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        if i > 5 and va < ib:
            break
        continue
    rva = va - ib
    o = rva_to_off(sec, rva)
    if o is None:
        continue
    b = data[o : o + 12]
    extra = ""
    if b[0] == 0x8B and b[1] == 0x81 and b[6] == 0xC3:
        extra = f"eax +0x{struct.unpack_from('<I', b, 2)[0]:x}"
    elif b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
        extra = f"rax +0x{struct.unpack_from('<I', b, 4)[0]:x}"
    elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
        extra = f"lea +0x{struct.unpack_from('<I', b, 4)[0]:x}"
    elif b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
        extra = f"byte +0x{struct.unpack_from('<I', b, 3)[0]:x}"
    elif b[0] == 0x8A and b[1] == 0x81 and b[6] == 0xC3:
        extra = f"al +0x{struct.unpack_from('<I', b, 2)[0]:x}"
    if extra:
        print(f"  [{i:3d}] {hex(rva)} {extra}")

print("\nCAIGeneral +0x38 cmp/set")
# 38 41 38 / 38 43 38 / 80 79 38 / c6 41 38 / c6 43 38
n = 0
for off in range(raw0, raw1 - 6):
    if data[off : off + 3] in (b"\x38\x41\x38", b"\x38\x43\x38", b"\x38\x46\x38", b"\x38\x47\x38"):
        rva = off_to_rva(sec, off)
        print(f"  cmp {hex(rva)} {hexdump(data, sec, rva - 4, 16)}")
        n += 1
    elif data[off : off + 3] in (b"\x80\x79\x38", b"\x80\x7b\x38"):
        rva = off_to_rva(sec, off)
        print(f"  cmp0 {hex(rva)} {hexdump(data, sec, rva - 4, 16)}")
        n += 1
    elif data[off : off + 3] in (b"\xc6\x41\x38", b"\xc6\x43\x38", b"\xc6\x46\x38"):
        rva = off_to_rva(sec, off)
        print(f"  set {hex(rva)} {data[off:off+4].hex()} {hexdump(data, sec, rva - 8, 20)}")
        n += 1
    if n >= 50:
        break
print("sites", n)
