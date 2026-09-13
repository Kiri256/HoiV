from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(name, vt, n=16):
    print(f"\n{name} {hex(vt)}")
    off = rva_to_off(sec, vt)
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if ib <= va < ib + 0x4000000:
            print(f"  [{i:3d}] {hex(va-ib)} {hexdump(data, sec, va-ib, 12)}")


dump("OG primary", 0x0292BEC0)
dump("OG alt", 0x0292BF38)
dump("AG primary", 0x0292BF58)
dump("AG alt", 0x0292BFD0)
dump("CFront", 0x0294EE20, 12)

print("\nCFront +0x38/+0x160")
print(hexdump(data, sec, 0x00EEE430, 80))
