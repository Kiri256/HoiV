from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def rel_call(rva):
    off = rva_to_off(sec, rva)
    if data[off] != 0xE8:
        return None
    return (rva + 5 + struct.unpack_from("<i", data, off + 1)[0]) & 0xFFFFFFFF


print("writer 0x646d00 context (zero 0x223D)")
print(hexdump(data, sec, 0x00646D00, 96))
print("set-1 0x65d840")
print(hexdump(data, sec, 0x0065D840, 80))
print("use 0x65d600")
print(hexdump(data, sec, 0x0065D600, 80))

print("\nwho calls set-1 site function")
# find function start: walk back to int3
fn = 0x0065D800
print("around", hexdump(data, sec, 0x0065D7E0, 32))
for rva, kind in calls_to(data, sec, 0x0065D6C0)[:8]:
    print(" call 65d6c0", kind, hex(rva))

print("\nCCountryAI Update later 0x2ad050")
print(hexdump(data, sec, 0x002AD050, 160))
print("\n0x1314f70")
print(hexdump(data, sec, 0x01314F70, 48))
print("0x13150e0")
print(hexdump(data, sec, 0x013150E0, 48))
print("0x204e100 CAICore[7]")
print(hexdump(data, sec, 0x0204E100, 48))
print("0x2a79a0")
print(hexdump(data, sec, 0x002A79A0, 32))
print("0x2a8d90 GetCountry?")
print(hexdump(data, sec, 0x002A8D90, 32))

print("\nCAIModule shared methods")
for rva, name in (
    (0x0204E5B0, "[14]"),
    (0x0204E7B0, "[13]"),
    (0x0204E800, "[16]"),
    (0x0204EB10, "[15]"),
    (0x0204EB60, "[17]"),
    (0x0204E850, "[11]"),
    (0x0204E8A0, "[12]"),
):
    print(name, hexdump(data, sec, rva, 40))

print("\nstrings control/theater/unassign")
for k in (
    b"unassign",
    b"Unassign",
    b"take_over",
    b"Take control",
    b"AI control",
    b"ai_controlled",
    b"Controlled by AI",
    b"Assign to AI",
    b"theater_ai",
    b"control_theater",
    b"AI_ARMY",
    b"army_group_ai",
    b"front_ai",
    b"auto_execute",
    b"EXECUTION_",
    b"orders_group",
):
    offs = find_cstr(data, k)
    if offs:
        print(k, [hex(off_to_rva(sec, x)) for x in offs[:4]])

print("\nCCountry lea/ptr getters 80-160")
vt = rva_to_off(sec, 0x027C0E80)
for i in range(80, 200):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
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
    if extra:
        print(f"  [{i:3d}] {hex(rva)}{extra}")
