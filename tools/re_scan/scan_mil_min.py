from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def find_vt(name: bytes):
    i = data.find(name + b"\0")
    if i < 0:
        print("no name", name)
        return []
    td = off_to_rva(sec, i) - 16
    pat = struct.pack("<I", td)
    cols = []
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sec, j)
        if rva is not None:
            cols.append(rva - 12)
        start = j + 1
    vts = []
    for col in cols:
        q = struct.pack("<Q", ib + col)
        k = 0
        while True:
            p = data.find(q, k)
            if p < 0:
                break
            vr = off_to_rva(sec, p + 8)
            if vr:
                vts.append(vr)
            k = p + 1
    return vts


def dump_vt(name, vt, n=24):
    print(f"\n{name} vt {hex(vt)}")
    off = rva_to_off(sec, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            print(f"  [{i:3d}] {hex(va)}")
            continue
        rva = va - ib
        o = rva_to_off(sec, rva)
        b = data[o : o + 12]
        extra = ""
        if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
            extra = f"  ptr +0x{struct.unpack_from('<I', b, 4)[0]:x}"
        elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
            extra = f"  lea +0x{struct.unpack_from('<I', b, 4)[0]:x}"
        elif b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
            extra = f"  byte +0x{struct.unpack_from('<I', b, 3)[0]:x}"
        elif b[0] == 0xC3:
            extra = "  ret"
        elif b[:2] == b"\x32\xC0" and b[2] == 0xC3:
            extra = "  xor al,al ret"
        print(f"  [{i:3d}] {hex(rva)}{extra}  {b[:8].hex()}")


for name in (
    b".?AVCAIMilitaryMinister@@",
    b".?AVCAIForeignMinister@@",
    b".?AVCAIInteriorMinister@@",
    b".?AVCAIPoliticalMinister@@",
    b".?AVCAIModule@@",
    b".?AVCAICore@@",
    b".?AVCAIBaseGeneral@@",
    b".?AVCAIVolunteerGeneral@@",
):
    vts = find_vt(name)
    print(name.decode(), [hex(x) for x in vts[:4]])
    if vts:
        dump_vt(name.decode(), vts[0], 20)

# CCountryAI more methods - dump first 40 slots
print("\nCCountryAI first 40")
off = rva_to_off(sec, 0x02710C90)
for i in range(40):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    o = rva_to_off(sec, rva)
    b = data[o : o + 16]
    extra = ""
    if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
        extra = f" ptr+0x{struct.unpack_from('<I', b, 4)[0]:x}"
    elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
        extra = f" lea+0x{struct.unpack_from('<I', b, 4)[0]:x}"
    elif b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
        extra = f" byte+0x{struct.unpack_from('<I', b, 3)[0]:x}"
    print(f"  [{i:3d}] {hex(rva)}{extra} {b[:10].hex()}")
