from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def rip_target(rva, inst_len, rel):
    return (rva + inst_len + rel) & 0xFFFFFFFF


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


def vt_slots(vt_rva, n, name):
    off = rva_to_off(sec, vt_rva)
    print(f"\n{name} vt 0x{vt_rva:08x}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            print(f"  [{i:3d}] {va:016x}")
            continue
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 16)}")


# Locate post-AI function start (40 53 48 83 ec 30 80 3d)
raw0, raw1, _ = text_range(sec)
pat = bytes.fromhex("40 53 48 83 ec 30 80 3d")
off = data.find(pat, raw0, raw1)
post = off_to_rva(sec, off)
print("post fn", hex(post))
dump(post, 220, "post AI command")

# decode first two rip cmps
b = data[off : off + 16]
rel1 = struct.unpack_from("<i", b, 7)[0]
print("first cmp target", hex(rip_target(post + 4, 7, rel1)))

# find second 80 3d in first 40 bytes
chunk = data[off : off + 40]
i = chunk.find(bytes.fromhex("80 3d"), 8)
if i >= 0:
    rel2 = struct.unpack_from("<i", chunk, i + 2)[0]
    print("second cmp target", hex(rip_target(post + i, 7, rel2)))

print("\ncallers of post fn")
for rva, kind in calls_to(data, sec, post)[:40]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 16), 28)}")

print("\nCMoveCommand ctor callers")
for rva, kind in calls_to(data, sec, 0x01350350):
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 20), 36)}")

print("\nRTTI land/front/ai")
for part in (
    b"CAIGeneral",
    b"CFront@@",
    b"COrdersGroup@@",
    b"COrderInstance",
    b"CTheaterAI",
    b"CAITheater",
    b"CStrategicAI",
    b"CMilitaryAI",
    b"CArmyGroup",
    b"CBattlePlan",
    b"CPlan",
    b"CFrontAI",
    b"CAIFront",
    b"CUnitController",
    b"CMoveCommand",
    b"CAttackCommand",
    b"CAdvance",
):
    start = 0
    hits = []
    while len(hits) < 8:
        i = data.find(part, start)
        if i < 0:
            break
        begin = i
        while begin > 0 and 32 <= data[begin - 1] < 127 and i - begin < 40:
            begin -= 1
        end = i + len(part)
        while end < len(data) and 32 <= data[end] < 127 and end - begin < 60:
            end += 1
        text = data[begin:end].decode("latin1", "replace")
        if ".?AV" in text or "CAI" in text or "Front" in text or "Order" in text:
            hits.append((off_to_rva(sec, begin), text))
        start = i + 1
    print(part.decode(), hits[:6] if hits else "none")


def rtti_vt(name: bytes):
    i = data.find(name + b"\0")
    if i < 0:
        return 0
    rva = off_to_rva(sec, i)
    # type_desc at rva-0x10 typically; col then vtable. Use existing pattern from scan_rtti
    return rva


print("\nProcessAIHourlyUpdate")
for k in (b"ProcessAIHourlyUpdate", b"DoCountryHourlyUpdates", b"UpdateFronts", b"UpdateTheaters"):
    offs = find_cstr(data, k)
    print(k.decode(), [hex(off_to_rva(sec, x)) for x in offs[:3]])
    if offs:
        rva = off_to_rva(sec, offs[0])
        for lea in lea_to(data, sec, rva, 6):
            print("  lea", hex(lea), hexdump(data, sec, max(0, lea - 24), 48))

vt_slots(0x029613D0, 24, "CAIGeneral")
