from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)


def rel32_call(off):
    tgt_off = off + 5 + struct.unpack_from("<i", data, off + 1)[0]
    return off_to_rva(sec, tgt_off)


# 80 xx 3D 22 00 00 00  = cmp byte [reg+0x223D], 0
# 38 xx 3D 22 00 00     = cmp [reg+0x223D], r8b etc
# C6 80 3D 22 00 00     = mov byte [rax+0x223D], imm
print("uses of +0x223D")
pat = bytes([0x3D, 0x22, 0x00, 0x00])
start = raw0
n = 0
sites = []
while n < 80:
    i = data.find(pat, start, raw1)
    if i < 0:
        break
    rva = off_to_rva(sec, i)
    ctx = data[i - 3 : i + 8]
    sites.append((rva, ctx.hex(), hexdump(data, sec, max(0, rva - 8) if rva else 0, 24)))
    print(f"  {hex(rva)}  {data[i-4:i+5].hex()}  {hexdump(data, sec, rva - 12, 28)}")
    n += 1
    start = i + 1
print("count", n)

print("\nForeign [13] 0x12dfd10")
print(hexdump(data, sec, 0x012DFD10, 80))
print("\nForeign [14] 0x12decf0")
print(hexdump(data, sec, 0x012DECF0, 64))
print("\nInterior [13] 0x12fe110")
print(hexdump(data, sec, 0x012FE110, 80))
print("\nInterior [14] 0x12f6180")
print(hexdump(data, sec, 0x012F6180, 64))
print("\nPolitical [14] 0x130a7d0")
print(hexdump(data, sec, 0x0130A7D0, 80))

print("\nCCountry vtable getters around GetAI")
vt = rva_to_off(sec, 0x027C0E80)
for i in range(0, 80):
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

# CCountryAI ctor: find lea of ministers
print("\nCCountryAI ctor 0x2a7e60")
print(hexdump(data, sec, 0x002A7E60, 96))

print("\nGetAI string")
for k in (b"GetAI()", b"GetAI", b"pAI", b"_pAI"):
    offs = find_cstr(data, k)
    if offs:
        print(k, [hex(off_to_rva(sec, x)) for x in offs[:6]])
