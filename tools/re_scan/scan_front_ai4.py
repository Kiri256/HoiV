from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, rva_to_off, off_to_rva, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


def contains_call_to(fn_rva, target, limit=0x4000):
    off = rva_to_off(sec, fn_rva)
    for i in range(0, limit - 5):
        if data[off + i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", data, off + i + 1)[0]
        if fn_rva + i + 5 + rel == target:
            return fn_rva + i
    return None


for fn in (0x00D61090, 0x00D612F0, 0x00D616E0, 0x00D61910, 0x00D61800):
    hit = contains_call_to(fn, 0x01350350)
    print(f"fn 0x{fn:08x} ctor at {hex(hit) if hit else '-'}")

dump(0x00D61090, 48, "d61090")
print("callers d61090")
for rva, kind in calls_to(data, sec, 0x00D61090)[:15]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 20), 32)}")

dump(0x00D612F0, 48, "d612f0")
print("callers d612f0")
for rva, kind in calls_to(data, sec, 0x00D612F0)[:15]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 20), 32)}")

dump(0x002A7DC0, 64, "CountryAI calls StrategicAI")
dump(0x00BE8320, 48, "COrdersGroup[8]")
print("callers OG[8]")
for rva, kind in calls_to(data, sec, 0x00BE8320)[:8]:
    print(f"  {kind} 0x{rva:08x}")

# CCountryAI [21] [22]
dump(0x012D08B0, 40, "CountryAI[21]")
dump(0x002AA000, 40, "CountryAI[22]")
dump(0x012D06E0, 40, "CountryAI[23]")

# human_ai
from scan import find_cstr, lea_to
for k in (b"human_ai", b"Human AI is now", b"Enable human_ai", b"AI control"):
    offs = find_cstr(data, k)
    print("str", k, [hex(off_to_rva(sec, x)) for x in offs[:3]])
    if offs:
        for lea in lea_to(data, sec, off_to_rva(sec, offs[0]), 4):
            print("  lea", hex(lea), hexdump(data, sec, max(0, lea - 16), 40))
