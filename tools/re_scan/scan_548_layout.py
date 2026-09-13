from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def vt_off(vt, field_hex):
    """Who compares [obj+field] among known vtable methods - skip, just dump structs."""
    pass


print("CFront +0x28/+0x3C uses in CFront methods")
# dump CFront ctor 0xeee400
print("CFront ctor-ish 0xeee400")
print(hexdump(data, sec, 0x00EEE400, 96))
print("\nCFront 0xeda560")
print(hexdump(data, sec, 0x00EDA560, 80))

print("\nCOrdersGroup[11] +0x5C already; dump start of OG for +0x28/+0x3C")
print("OG dtor/ctor nearby 0xbe1360")
print(hexdump(data, sec, 0x00BE1360, 32))

# COrdersGroupMember
print("\nCOrdersGroupMember vt 0x292be78")
off = rva_to_off(sec, 0x0292BE78)
for i in range(16):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if ib <= va < ib + 0x4000000:
        print(f"  [{i:3d}] {hex(va-ib)} {hexdump(data, sec, va-ib, 14)}")

print("\n+0x278 walk 0x1d83c4")
print(hexdump(data, sec, 0x001D83B0, 96))

print("\ncreate AG after 0xee10ed store")
print(hexdump(data, sec, 0x00EE10E0, 120))

print("\nCTheaterGroup ctor 0x1620a40")
print(hexdump(data, sec, 0x01620A40, 64))
print("callers of 0x1620940")
for cand in (0x01620900, 0x01620940, 0x01620980, 0x01620A00, 0x01620A40):
    cs = calls_to(data, sec, cand)
    if cs:
        print(hex(cand), len(cs), hexdump(data, sec, cs[0][0] - 16, 32) if cs else "")

# cmp dword [reg+0x3C] near front/order
print("\nwho uses +0x3C with +0x28 province")
print(hexdump(data, sec, 0x00D9D720, 48))

# GetAI +0x228 then +0x548 together?
print("\n0x6c2680 callers that also get country tag")
for rva, kind in calls_to(data, sec, 0x006C2680)[:12]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 24, 40)}")
