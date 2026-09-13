from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


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


print("RTTI CAI*")
start = 0
seen = []
while len(seen) < 80:
    i = data.find(b".?AVCAI", start)
    if i < 0:
        break
    end = data.find(b"\0", i)
    name = data[i:end]
    if name not in seen and b"lambda" not in name:
        seen.append(name)
        print(" ", name.decode("latin1", "replace"))
    start = i + 1

print("\nRTTI *AI@@ interesting")
for part in (b"Theater", b"Military", b"ArmyAI", b"LandAI", b"FrontAI", b"GeneralAI", b"CombatAI"):
    start = 0
    n = 0
    while n < 6:
        i = data.find(part, start)
        if i < 0:
            break
        begin = max(0, i - 20)
        chunk = data[begin : i + 40]
        if b".?AV" in chunk:
            s = chunk[chunk.find(b".?AV") :].split(b"\0", 1)[0]
            print(" ", part.decode(), s.decode("latin1", "replace"))
            n += 1
        start = i + 1

print("\nCCountryAI ctor / set +0x60 callers already known")
# dump CCountryAI more getters
vt = rva_to_off(sec, 0x02710C90)
print("CCountryAI lea-getters / ptrs")
for i in range(80):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    off = rva_to_off(sec, rva)
    b = data[off : off + 8]
    if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
        disp = struct.unpack_from("<I", b, 4)[0]
        print(f"  [{i:3d}] ptr +0x{disp:x}")
    elif b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
        disp = struct.unpack_from("<I", b, 4)[0]
        print(f"  [{i:3d}] lea +0x{disp:x}")
    elif b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
        disp = struct.unpack_from("<I", b, 3)[0]
        print(f"  [{i:3d}] byte +0x{disp:x}")

print("\nCOrdersGroup[12] more")
print(hexdump(data, sec, 0x00BE8920, 80))

print("\nCAIGeneral ctor 0x10699b4 area")
print(hexdump(data, sec, 0x01069980, 64))

# human_ai toggle body
print("\nhuman_ai leas")
for k in (b"Enable human_ai", b"Human AI is now ON", b"Human AI is now OFF", b"human_ai"):
    offs = find_cstr(data, k)
    print(k, [hex(off_to_rva(sec, x)) for x in offs[:3]])
    if offs:
        for lea in lea_to(data, sec, off_to_rva(sec, offs[0]), 5):
            print("  lea", hex(lea), hexdump(data, sec, max(0, lea - 32), 48))
