from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


print("create AI + store +0x228 @ 0x705d00")
print(hexdump(data, sec, 0x00705C80, 200))

print("\nCAIMilitaryMinister ctor callers")
for cand in (0x010A1FE0, 0x010A2000, 0x010A1F80, 0x010A1F00):
    cs = calls_to(data, sec, cand)
    if cs:
        print(hex(cand), len(cs))
        for rva, kind in cs[:10]:
            print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 20, 48)}")

print("\nForeign minister ctor lea 0x2983b58")
# already have ctor 0x12d8720 as vt[0] dtor. find lea of vt
from scan import text_range
raw0, raw1, _ = text_range(sec)
for name, target in (
    ("mil", 0x02962938),
    ("for", 0x02983B58),
    ("int", 0x029842D0),
    ("pol", 0x02984FD0),
):
    hits = []
    for off in range(raw0, raw1 - 7):
        if data[off : off + 3] != b"\x48\x8d\x05":
            continue
        rva = off_to_rva(sec, off)
        rel = struct.unpack_from("<i", data, off + 3)[0]
        if rva + 7 + rel == target:
            hits.append(rva)
    print(name, [hex(x) for x in hits[:6]])

print("\nCCountryAI more ctor 0x2a6e00")
print(hexdump(data, sec, 0x002A6E10, 200))

print("\nwho calls CArmyGroup[12] 0xbe88d0")
for rva, kind in calls_to(data, sec, 0x00BE88D0)[:15]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 16, 32)}")

print("\nCCountry +0x228 uses")
from scan import imm32_uses
for rva, hx in imm32_uses(data, sec, 0x228, 25):
    print(f"  {hex(rva)} {hx}")
