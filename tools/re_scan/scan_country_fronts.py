from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


def lea_ret_getters_near(start_rva, n=40):
    off = rva_to_off(sec, start_rva)
    print(f"\nlea-ret around {hex(start_rva)}")
    i = 0
    pos = off - 0x200
    end = off + 0x400
    while pos < end and i < n:
        if data[pos : pos + 3] == b"\x48\x8d\x81" and data[pos + 7] == 0xC3:
            rva = off_to_rva(sec, pos)
            disp = struct.unpack_from("<I", data, pos + 3)[0]
            print(f"  {hex(rva)} lea +0x{disp:x}")
            i += 1
        elif data[pos : pos + 3] == b"\x48\x8b\x81" and data[pos + 7] == 0xC3:
            rva = off_to_rva(sec, pos)
            disp = struct.unpack_from("<I", data, pos + 3)[0]
            print(f"  {hex(rva)} ptr +0x{disp:x}")
            i += 1
        pos += 1


print("create AG 0xee1080")
print(hexdump(data, sec, 0x00EE1080, 160))
print("\ncreate AG 0xeee620")
print(hexdump(data, sec, 0x00EEE620, 120))

print("\nCFront getters")
off = rva_to_off(sec, 0x0294EE20)
for i in range(40):
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
    print(f"  [{i:3d}] {hex(rva)}{extra} {b[:8].hex()}")

lea_ret_getters_near(0x006C2410)

print("\nlea CFront vt 0x294ee20")
target = 0x0294EE20
hits = []
for off in range(raw0, raw1 - 7):
    if data[off : off + 3] != b"\x48\x8d\x05":
        continue
    rva = off_to_rva(sec, off)
    rel = struct.unpack_from("<i", data, off + 3)[0]
    if rva + 7 + rel == target:
        hits.append(rva)
print([hex(x) for x in hits[:10]])
for rva in hits[:6]:
    print(hex(rva), hexdump(data, sec, rva - 16, 36))

print("\nGetArmies callers sample")
n = 0
for rva, kind in calls_to(data, sec, 0x006C2410):
    if n < 8:
        print(f"  {kind} {hex(rva)} {hexdump(data, sec, rva - 8, 24)}")
    n += 1
print("total", n)
