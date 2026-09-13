from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

start, end = 0x00D618F0, 0x00D62200
off = rva_to_off(sec, start)
chunk = data[off : off + (end - start)]
print("int3/ret boundaries")
i = 0
while i < len(chunk) - 8:
    if chunk[i] == 0xCC and chunk[i + 1] != 0xCC:
        rva = start + i + 1
        print(f"  after int3 0x{rva:08x} {hexdump(data, sec, rva, 14)}")
        i += 2
        continue
    if chunk[i] == 0xC3 and i + 1 < len(chunk) and chunk[i + 1] == 0xCC:
        rva = start + i + 1
        # skip padding
        j = i + 1
        while j < len(chunk) and chunk[j] == 0xCC:
            j += 1
        if j < len(chunk):
            print(f"  after ret  0x{start+j:08x} {hexdump(data, sec, start+j, 14)}")
        i = j
        continue
    i += 1

print("\n0xd61bf0")
print(hexdump(data, sec, 0x00D61BF0, 48))
print("\n0x01a2f800-ish find prologues")
off = rva_to_off(sec, 0x01A2F400)
for delta in range(0, 0x800):
    o = off + delta
    if data[o - 1] == 0xCC and data[o : o + 4] in (
        bytes.fromhex("48 89 5c 24"),
        bytes.fromhex("40 55 53 56"),
        bytes.fromhex("48 8b c4 53"),
    ):
        print(hex(0x01A2F400 + delta), hexdump(data, sec, 0x01A2F400 + delta, 12))
