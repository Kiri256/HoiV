from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

for rva, label in (
    (0x006C2400, "GetAI +0x228"),
    (0x006C2410, "GetArmies +0x290"),
    (0x006C2600, "ptr +0xFD8"),
    (0x006C2680, "lea +0x548"),
    (0x006C27E0, "ptr +0x1380"),
    (0x006C27F0, "ptr +0xFA0"),
    (0x006C2800, "ptr +0xF88"),
):
    print(f"\n== {label} {hex(rva)}")
    print(hexdump(data, sec, rva, 16))
    cs = calls_to(data, sec, rva)
    print("callers", len(cs))
    for site, kind in cs[:8]:
        print(f"  {kind} {hex(site)} {hexdump(data, sec, site - 12, 28)}")

print("\n0x6c2680 body more")
print(hexdump(data, sec, 0x006C2680, 48))
print("\n0x6c2600 body")
print(hexdump(data, sec, 0x006C25F0, 32))

# dump all lea/ptr ret in 0x6c2400-0x6c2c00
print("\nall small getters 6c2400-6c2c00")
from scan import rva_to_off, off_to_rva
off = rva_to_off(sec, 0x006C2400)
end = rva_to_off(sec, 0x006C2C00)
pos = off
while pos < end:
    if data[pos : pos + 3] in (b"\x48\x8d\x81", b"\x48\x8b\x81") and data[pos + 7] == 0xC3:
        rva = off_to_rva(sec, pos)
        disp = int.from_bytes(data[pos + 3 : pos + 7], "little")
        kind = "lea" if data[pos + 2] == 0x81 and data[pos + 1] == 0x8D else "ptr"
        if data[pos + 1] == 0x8D:
            kind = "lea"
        else:
            kind = "ptr"
        print(f"  {hex(rva)} {kind} +0x{disp:x}")
    pos += 1
