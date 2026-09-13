from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


# Is d61090 a CArmy slot?
vt = rva_to_off(sec, 0x02933D20)
print("CArmy slots matching d61/c2")
for i in range(200):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    rva = va - ib
    if rva in (0x00D61090, 0x00D612F0, 0x00D61910, 0x00C2EF00, 0x00C2EF40) or (
        0x00D61000 <= rva <= 0x00D63000
    ):
        print(f"  [{i}] 0x{rva:08x}")

dump(0x00C2EE80, 80, "caller of d61090")
dump(0x00D695E0, 80, "other caller d69694")
dump(0x00D61910, 64, "d61910")
print("callers d61910")
for rva, kind in calls_to(data, sec, 0x00D61910)[:12]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")

dump(0x01074470, 120, "CAIGeneral[14] more")
dump(0x0107D9C0, 100, "CAIGeneral[13] more")

# ctor of CAIGeneral: lea vt
from scan import lea_to
print("\nLEA CAIGeneral vt")
for lea in lea_to(data, sec, 0x029613D0, 8):
    print(hex(lea), hexdump(data, sec, max(0, lea - 24), 48))
