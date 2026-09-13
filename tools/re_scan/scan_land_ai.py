from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

keys = [
    b"army_ai",
    b"land_ai",
    b"military_ai",
    b"ai_army",
    b"research_ai",
    b"production_ai",
    b"focus_ai",
    b"IsCommandsAllowed",
    b"HandleAiMicroAttacks",
    b"CAIGeneral",
    b"Trying to post AI command",
    b"ai_enabled",
]
for k in keys:
    print("---", k.decode())
    start = 0
    n = 0
    while n < 6:
        i = data.find(k, start)
        if i < 0:
            if n == 0:
                print("  MISSING")
            break
        begin = i
        while begin > 0 and 32 <= data[begin - 1] < 127 and i - begin < 70:
            begin -= 1
        end = i + len(k)
        while end < len(data) and 32 <= data[end] < 127 and end - begin < 160:
            end += 1
        rva = off_to_rva(sec, i)
        text = data[begin:end].decode("latin1", "replace")
        print(f"  0x{rva:x} {text}")
        start = i + 1
        n += 1

print("\nCMoveCommand ctor callers")
for rva, kind in calls_to(data, sec, 0x01350350)[:30]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 8), 24)}")

print("\nCAIGeneral vt 0x029613d0")
vt = rva_to_off(sec, 0x029613D0)
for i in range(20):
    va = struct.unpack_from("<Q", data, vt + i * 8)[0]
    if not (ib <= va < ib + 0x4000000):
        continue
    rva = va - ib
    print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 20)}")
