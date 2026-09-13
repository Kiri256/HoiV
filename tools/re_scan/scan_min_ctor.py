from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("mil ctor 0x10a1fc0")
print(hexdump(data, sec, 0x010A1FC0, 120))
print("\nfor ctor 0x12d8360")
print(hexdump(data, sec, 0x012D8360, 160))
print("\nint ctor 0x12ea7e0")
print(hexdump(data, sec, 0x012EA7E0, 120))
print("\npol ctor 0x130a140")
print(hexdump(data, sec, 0x0130A140, 120))

# find who calls these by walking back to typical prologue
for label, site in (
    ("mil", 0x010A1FE0),
    ("for", 0x012D8380),
    ("int", 0x012EA800),
    ("pol", 0x0130A160),
):
    # scan backwards for CC CC or ret then next function
    off = rva_to_off(sec, site)
    start = site
    for i in range(0, 0x80):
        b = data[off - i]
        if b == 0xCC and data[off - i - 1] == 0xCC:
            start = site - i + 1
            break
    print(f"\n{label} fn~{hex(start)}")
    for rva, kind in calls_to(data, sec, start)[:8]:
        print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 28, 56)}")

print("\nstore AI +0x228 more context 0x705d20")
print(hexdump(data, sec, 0x00705D20, 80))
