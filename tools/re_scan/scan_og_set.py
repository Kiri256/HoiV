from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump_vt(name, vt, n=30):
    print(f"\n{name} {hex(vt)}")
    off = rva_to_off(sec, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            continue
        rva = va - ib
        o = rva_to_off(sec, rva)
        b = data[o : o + 10]
        extra = ""
        if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
            extra = f" ptr+0x{struct.unpack_from('<I', b, 4)[0]:x}"
        elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
            extra = f" lea+0x{struct.unpack_from('<I', b, 4)[0]:x}"
        elif b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
            extra = f" byte+0x{struct.unpack_from('<I', b, 3)[0]:x}"
        elif b[0] == 0xC6 and b[1] == 0x41:
            extra = f" set +0x{b[2]:x}={b[3]}"
        print(f"  [{i:3d}] {hex(rva)}{extra} {b[:8].hex()}")


print("COrdersGroup +0x39 setter 0xbe0500")
print(hexdump(data, sec, 0x00BE0500, 220))
print("\ncallers of likely setter")
# find function start: 0xbe05c1 is near end (ret). walk back
for start in (0x00BE04E0, 0x00BE0520, 0x00BE0560, 0x00BE0580, 0x00BE05A0):
    print(start, hexdump(data, sec, start, 16))

for cand in (0x00BE0560, 0x00BE0580, 0x00BE05A0, 0x00BE04C0, 0x00BE0400):
    cs = calls_to(data, sec, cand)
    if cs:
        print(f"calls {hex(cand)} {len(cs)}")
        for rva, kind in cs[:8]:
            print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 12, 24)}")

dump_vt("COrdersGroup", 0x0292BEC0, 28)
dump_vt("CArmyGroup", 0x0292BF58, 28)
dump_vt("CFront", 0x0294EE20, 24)
dump_vt("CTheaterGroup", 0x029BE6C0, 24)
dump_vt("CAIGeneral", 0x029613D0, 20)

print("\nlea CCountryAI vtable stores")
# 48 8D 05 xx xx xx xx  that resolve to 0x02710C90
raw0, raw1, _ = text_range(sec)
target = 0x02710C90
hits = []
for off in range(raw0, raw1 - 7):
    if data[off : off + 3] != b"\x48\x8d\x05":
        continue
    rva = off_to_rva(sec, off)
    rel = struct.unpack_from("<i", data, off + 3)[0]
    if rva + 7 + rel == target:
        hits.append(rva)
print([hex(x) for x in hits[:20]])
for rva in hits[:8]:
    print(hex(rva), hexdump(data, sec, rva - 16, 40))
