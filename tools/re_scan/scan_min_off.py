from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("CCountryAI[14] 0x2acc80 minister create")
print(hexdump(data, sec, 0x002ACC80, 320))

print("\n0x2ace00")
print(hexdump(data, sec, 0x002ACE00, 160))

print("\nmil ctor 0x10a1fe0 callers")
for rva, kind in calls_to(data, sec, 0x010A1FE0)[:8]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 32, 64)}")

print("\npol ctor 0x130a160 callers")
for rva, kind in calls_to(data, sec, 0x0130A160)[:8]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 32, 64)}")
