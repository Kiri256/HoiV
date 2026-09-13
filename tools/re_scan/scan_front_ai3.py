from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off, text_range, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


# How many calls land in 0xD61000-0xD63000?
hits = {}
for off in range(raw0, raw1 - 5):
    if data[off] != 0xE8:
        continue
    rel = struct.unpack_from("<i", data, off + 1)[0]
    rva = off_to_rva(sec, off)
    if rva is None:
        continue
    tgt = (rva + 5 + rel) & 0xFFFFFFFF
    if 0x00D61000 <= tgt <= 0x00D63000:
        hits[tgt] = hits.get(tgt, 0) + 1
print("call targets in d61xxx")
for tgt, n in sorted(hits.items(), key=lambda x: -x[1])[:20]:
    print(f"  0x{tgt:08x} x{n} {hexdump(data, sec, tgt, 16)}")

dump(0x00BEDF00, 64, "COrdersGroup[2]")
dump(0x00BE8920, 48, "COrdersGroup[12] +0x39")
dump(0x00EF1B50, 64, "CFront[2]")
dump(0x00BEDE70, 48, "CArmyGroup[2]")

print("\ncallers COrdersGroup[2]")
for rva, kind in calls_to(data, sec, 0x00BEDF00)[:12]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")
print("\ncallers CFront[2]")
for rva, kind in calls_to(data, sec, 0x00EF1B50)[:12]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")
print("\ncallers COrdersGroup[12]")
for rva, kind in calls_to(data, sec, 0x00BE8920)[:12]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")

# CCountryAI more slots
vt = rva_to_off(sec, 0x02710C90)
print("\nCCountryAI vt 16-40")
for i in range(16, 40):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 16)}")

dump(0x0204DD50, 48, "CStrategicAI[2]")
print("callers StrategicAI[2]")
for rva, kind in calls_to(data, sec, 0x0204DD50)[:10]:
    print(f"  {kind} 0x{rva:08x}")
