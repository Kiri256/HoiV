from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, imm32_uses, lea_to, load_pe, off_to_rva, rva_to_off, text_range

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


print("slot2 of known types")
for name, vt in (
    ("COrdersGroup", 0x0292BEC0),
    ("CArmyGroup", 0x0292BF58),
    ("CFront", 0x0294EE20),
    ("CTheaterGroup", 0x029BE6C0),
    ("CCountry", 0x027C0E80),
    ("CArmy", 0x02933D20),
):
    off = rva_to_off(sec, vt)
    slot2 = struct.unpack_from("<Q", data, off + 16)[0] - ib
    print(f"  {name} [2]={hex(slot2)}")

print("\n+0x548 uses")
for rva, hx in imm32_uses(data, sec, 0x548, 30):
    print(f"  {hex(rva)} {hx}")

print("\n0xce712b loop more")
print(hexdump(data, sec, 0x00CE7140, 80))
print("\n0xd9d6e9 more")
print(hexdump(data, sec, 0x00D9D6E8, 96))

print("\nRTTI *Theater* *Command* *Order*")
start = 0
seen = []
while len(seen) < 50:
    i = data.find(b".?AVC", start)
    if i < 0:
        break
    end = data.find(b"\0", i)
    name = data[i:end]
    low = name.lower()
    if any(x in low for x in (b"theater", b"command", b"order", b"front", b"armygroup", b"battleplan")):
        if name not in seen and b"lambda" not in name and b"Define" not in name:
            seen.append(name)
            vts = find_vt(name)
            print(" ", name.decode("latin1", "replace"), [hex(x) for x in vts[:4]])
    start = i + 1

print("\nCArmy lea/ptr getters 0-120")
off = rva_to_off(sec, 0x02933D20)
for i in range(120):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    o = rva_to_off(sec, rva)
    b = data[o : o + 12]
    if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
        print(f"  [{i:3d}] ptr +0x{struct.unpack_from('<I', b, 4)[0]:x}")
    elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
        print(f"  [{i:3d}] lea +0x{struct.unpack_from('<I', b, 4)[0]:x}")
    elif b[:3] == b"\x48\x8b" and b[3] == 0x41 and b[5] == 0xC3:
        print(f"  [{i:3d}] ptr +0x{b[4]:x}")
    elif b[:3] == b"\x48\x8d" and b[3] == 0x41 and b[5] == 0xC3:
        print(f"  [{i:3d}] lea +0x{b[4]:x}")
