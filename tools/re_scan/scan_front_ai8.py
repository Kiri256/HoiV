from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off, off_to_rva, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)
target = 0x00D61C30

print("d61c30+20", hexdump(data, sec, 0x00D61C30, 40))
print("jmps/calls to d61c30")
for off in range(raw0, raw1 - 5):
    if data[off] not in (0xE8, 0xE9):
        continue
    rel = struct.unpack_from("<i", data, off + 1)[0]
    rva = off_to_rva(sec, off)
    if rva is not None and rva + 5 + rel == target:
        print(hex(rva), "e8" if data[off] == 0xE8 else "e9", hexdump(data, sec, rva - 8, 16))

# which vtable has this
print("\nvtables with d61c30")
want = struct.pack("<Q", ib + target)
start = 0
n = 0
while n < 20:
    i = data.find(want, start)
    if i < 0:
        break
    rva = off_to_rva(sec, i)
    print(" qword at", hex(rva) if rva else i)
    start = i + 1
    n += 1
