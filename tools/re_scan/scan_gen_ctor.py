from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

ctor = 0x010699B0
print("ctor callers")
for rva, kind in calls_to(data, sec, ctor)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, max(0, rva - 40), 56)}")

# maybe ctor starts a bit earlier
for cand in (0x01069980, 0x01069990, 0x010699A0, 0x010699B0, 0x010699C0):
    n = len(calls_to(data, sec, cand))
    print(f"calls {hex(cand)} {n}")

print("\n[14]+340")
print(hexdump(data, sec, 0x01074470 + 330, 48))
print("\n[14]+740")
print(hexdump(data, sec, 0x01074470 + 740, 48))

# CCountryAI[14] 0x002acc80 creates ministers - dump around general create
print("\nCCountryAI[14] 0x2acc80")
print(hexdump(data, sec, 0x002ACC80, 160))

# writes to [reg+8] near CAIGeneral after lea vt
print("\nsearch mov [reg+8] after general vt stores is hard; dump 0x1069a80")
print(hexdump(data, sec, 0x01069A80, 120))
print(hexdump(data, sec, 0x01069B00, 80))
