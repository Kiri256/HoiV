from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("CAIGeneral[14] callers")
for rva, kind in calls_to(data, sec, 0x01074470)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 16, 32)}")

print("\nCAIGeneral[13] callers")
for rva, kind in calls_to(data, sec, 0x0107D9C0)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 16, 32)}")

print("\nCAIMilitaryMinister[14] callers")
for rva, kind in calls_to(data, sec, 0x010ABA70)[:15]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 16, 32)}")

print("\nCAIMilitaryMinister[13] callers")
for rva, kind in calls_to(data, sec, 0x010B53C0)[:15]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 16, 32)}")

print("\nCAIMilitaryMinister[12] callers")
for rva, kind in calls_to(data, sec, 0x010BB0D0)[:12]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 12, 28)}")

print("\nForeign[13] callers (should stay alive)")
for rva, kind in calls_to(data, sec, 0x012DFD10)[:8]:
    print(f"  {kind} {hex(rva)}")

print("\nPolitical[14] callers")
for rva, kind in calls_to(data, sec, 0x0130A7D0)[:8]:
    print(f"  {kind} {hex(rva)}")

print("\nmil 0x7A0 ctor call 0x10a1fe0 vs nearby")
for cand in (0x010A1F00, 0x010A1F40, 0x010A1F80, 0x010A1FC0, 0x010A1FE0, 0x010A2000):
    n = len(calls_to(data, sec, cand))
    if n:
        print(hex(cand), n)
