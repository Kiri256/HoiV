from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

vt = 0x0293C760
# slot index of 0xd61c30
off = rva_to_off(sec, vt)
print("vtable 0x293c760 slots")
for i in range(40):
    va = struct.unpack_from("<Q", data, off + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    mark = " <== issue" if rva == 0x00D61C30 else ""
    print(f"  [{i:3d}] 0x{rva:08x}{mark}")

# COL at vt-8
col = struct.unpack_from("<Q", data, off - 8)[0] - ib
print("col", hex(col))
# td rva at col+12
col_off = rva_to_off(sec, col)
td = struct.unpack_from("<I", data, col_off + 12)[0]
print("td", hex(td))
name_off = rva_to_off(sec, td + 16)
end = data.find(b"\0", name_off)
print("RTTI", data[name_off:end].decode("latin1", "replace"))

print("\nvt-0x40", hexdump(data, sec, vt - 16, 24))
