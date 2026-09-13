from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


def find_vt(name: bytes):
    i = data.find(name + b"\0")
    if i < 0:
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


print("COrdersGroup[12] callers")
for rva, kind in calls_to(data, sec, 0x00BE8920)[:20]:
    print(f"  {kind} {hex(rva)} {hexdump(data, sec, max(0, rva - 20), 36)}")

print("\nimm writes to +0x39 (c6 4x 39 / c6 8x 39 00 00 00)")
n = 0
for off in range(raw0, raw1 - 8):
    b = data[off]
    if b != 0xC6:
        continue
    # C6 41/43/45/46/47 39 imm8
    if data[off + 1] in (0x41, 0x42, 0x43, 0x45, 0x46, 0x47) and data[off + 2] == 0x39:
        rva = off_to_rva(sec, off)
        print(f"  {hex(rva)} {data[off:off+4].hex()} {hexdump(data, sec, rva - 8, 20)}")
        n += 1
        if n >= 40:
            break
    # C6 81/83 39 00 00 00 imm8
    if data[off + 1] in (0x81, 0x83) and data[off + 2:off + 6] == b"\x39\x00\x00\x00":
        rva = off_to_rva(sec, off)
        print(f"  {hex(rva)} {data[off:off+7].hex()} {hexdump(data, sec, rva - 8, 24)}")
        n += 1
        if n >= 40:
            break
print("write sites", n)

print("\nRTTI theater/front/group")
for name in (
    b".?AVCTheater@@",
    b".?AVCLandTheater@@",
    b".?AVCArmyTheater@@",
    b".?AVCArmyGroup@@",
    b".?AVCFront@@",
    b".?AVCAIFront@@",
    b".?AVCOrdersGroup@@",
    b".?AVCStrategicRegion@@",
    b".?AVCCommandGroup@@",
    b".?AVCUnitController@@",
    b".?AVCTheaterGroup@@",
    b".?AVCAiTheater@@",
):
    vts = find_vt(name)
    print(name.decode(), [hex(x) for x in vts[:3]])

print("\nmore RTTI with Theater/Front/ArmyGroup")
start = 0
seen = []
while len(seen) < 40:
    i = data.find(b".?AVC", start)
    if i < 0:
        break
    end = data.find(b"\0", i)
    name = data[i:end]
    low = name.lower()
    if any(x in low for x in (b"theater", b"front", b"armygroup", b"ordersgroup", b"general")):
        if name not in seen and b"lambda" not in name:
            seen.append(name)
            print(" ", name.decode("latin1", "replace"))
    start = i + 1
