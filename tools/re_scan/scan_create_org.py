from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, lea_to, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump_calls(target, label, n=20):
    print(f"\n== {label} {hex(target)}")
    hits = calls_to(data, sec, target)
    print("count", len(hits))
    for rva, kind in hits[:n]:
        print(f"  {kind} {hex(rva)} {hexdump(data, sec, max(0, rva - 24), 48)}")


# ctor starts from earlier scan
for cand in (0x00BE0400, 0x00BE04C0, 0x00BE0520, 0x00BE0560, 0x00BE0580):
    n = len(calls_to(data, sec, cand))
    if n:
        print("AG ctor cand", hex(cand), n)

for cand in (0x01620900, 0x01620980, 0x01620A00, 0x01620A40, 0x01620A80):
    n = len(calls_to(data, sec, cand))
    if n:
        print("TG ctor cand", hex(cand), n)

dump_calls(0x00BE0580, "CArmyGroup 0xbe0580")
dump_calls(0x01620A40, "CTheaterGroup 0x1620a40")

print("\nLEA CArmyGroup vt")
for lea in lea_to(data, sec, 0x0292BF58, 8)[:15]:
    print(hex(lea), hexdump(data, sec, max(0, lea - 20), 44))

print("\nLEA CTheaterGroup vt")
for lea in lea_to(data, sec, 0x029BE6C0, 8)[:15]:
    print(hex(lea), hexdump(data, sec, max(0, lea - 20), 44))

print("\nLEA CAIGeneral vt")
for lea in lea_to(data, sec, 0x029613D0, 8)[:15]:
    print(hex(lea), hexdump(data, sec, max(0, lea - 20), 44))

print("\nCAIGeneral ctor 0x1069990 callers")
dump_calls(0x01069990, "gen ctor-ish")

# minister [14] after general loop — already know +0x98 size 0
print("\nmil[12] 0x10bb0d0 more")
print(hexdump(data, sec, 0x010BB0D0, 96))
print("\nmil[14] after +0x223D")
print(hexdump(data, sec, 0x010ABA90, 80))
