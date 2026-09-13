from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def find_vt(name: bytes) -> int:
    i = data.find(name + b"\0")
    if i < 0:
        print(name, "missing")
        return 0
    td = off_to_rva(sec, i) - 16
    pat = struct.pack("<I", td)
    start = 0
    cols = []
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sec, j)
        if rva is not None:
            # COL +0x0C = td; COL starts at rva-12
            col = rva - 12
            cols.append(col)
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
    print(name.decode(), "td", hex(td), "cols", [hex(c) for c in cols[:4]], "vt", [hex(v) for v in vts[:6]])
    return vts[0] if vts else 0


def dump_vt(vt, n, name):
    if not vt:
        return
    off = rva_to_off(sec, vt)
    print(f"\n{name} 0x{vt:08x}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            continue
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 18)}")


def fn_start(rva):
    off = rva_to_off(sec, rva)
    for back in range(0, 0x800):
        o = off - back
        prev = data[o - 1] if o > 0 else 0
        if prev in (0xCC, 0xC3) and data[o] in (0x40, 0x48, 0x4C, 0x55, 0x56, 0x57, 0x41):
            return rva - back
    return 0


for name in (
    b".?AVCAIGeneral@@",
    b".?AVCOrdersGroup@@",
    b".?AVCFront@@",
    b".?AVCOrderInstance@@",
    b".?AVCArmyGroup@@",
    b".?AVCStrategicAI@@",
):
    vt = find_vt(name)
    dump_vt(vt, 20, name.decode())

start = fn_start(0x00D62020)
print("\nmove-site fn start", hex(start))
if start:
    print(hexdump(data, sec, start, 32))
    print("callers:")
    for rva, kind in calls_to(data, sec, start)[:20]:
        print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")

# 0x01a2faee site
s2 = fn_start(0x01A2FAEE)
print("\n1a2 site start", hex(s2))
if s2:
    print("callers:")
    for rva, kind in calls_to(data, sec, s2)[:15]:
        print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")
