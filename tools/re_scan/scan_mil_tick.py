from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def rel32_call(off):
    return off_to_rva(sec, off + 5 + struct.unpack_from("<i", data, off + 1)[0])


print("CCountryAI Update 0x2acf30")
print(hexdump(data, sec, 0x002ACF30, 160))

print("\nCAIMilitaryMinister [14] 0x10aba70")
print(hexdump(data, sec, 0x010ABA70, 128))

print("\nCAIMilitaryMinister [13] 0x10b53c0")
print(hexdump(data, sec, 0x010B53C0, 80))

print("\nCAIMilitaryMinister [12] 0x10bb0d0")
print(hexdump(data, sec, 0x010BB0D0, 80))

print("\nCAIMilitaryMinister [15] 0x10bd2e0")
print(hexdump(data, sec, 0x010BD2E0, 64))

print("\nCAIMilitaryMinister [16] 0x10b5de0")
print(hexdump(data, sec, 0x010B5DE0, 96))

print("\nCAIMilitaryMinister [17] 0x10bd3d0")
print(hexdump(data, sec, 0x010BD3D0, 96))

print("\nCAIMilitaryMinister [11] 0x204e850")
print(hexdump(data, sec, 0x0204E850, 48))

print("\nCAIMilitaryMinister [2] identity users via vtable slot?")

# strings
for k in (
    b"military_ai",
    b"Military AI",
    b"ai_military",
    b"Disable military",
    b"land_ai",
    b"army_ai",
    b"control_theaters",
    b"AI_MILITARY",
    b"MilitaryMinister",
    b"CAIMilitary",
    b"ai_front",
    b"front_ai",
    b"auto_execute",
    b"execution_type",
    b"AI_CONTROL",
    b"take_over",
):
    offs = find_cstr(data, k)
    if offs:
        print(k, [hex(off_to_rva(sec, x)) for x in offs[:4]])

print("\nCAIGeneral [13] 0x107d9c0")
print(hexdump(data, sec, 0x0107D9C0, 96))
print("\nCAIGeneral [14] 0x1074470")
print(hexdump(data, sec, 0x01074470, 96))

# CCountryAI Update calls
print("\nCCountryAI Update calls")
off = rva_to_off(sec, 0x002ACF30)
end = off + 0x400
i = off
n = 0
while i < end and n < 40:
    if data[i] == 0xE8:
        tgt = rel32_call(i)
        site = off_to_rva(sec, i)
        if site is not None and tgt is not None:
            print(f"  {hex(site)} call {hex(tgt)}")
        n += 1
        i += 5
        continue
    if data[i] == 0xFF and data[i + 1] in (0x50, 0x51, 0x52, 0x53, 0x56, 0x57):
        slot = data[i + 2] // 8
        print(f"  {hex(off_to_rva(sec, i))} call [reg+0x{data[i+2]:x}] slot~{slot}")
        n += 1
    i += 1
