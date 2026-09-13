from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump(rva, n, label):
    print(f"\n== {label} 0x{rva:08x}")
    print(hexdump(data, sec, rva, n))


def rtti_vt(name: bytes) -> int:
    i = data.find(name + b"\0")
    if i < 0:
        return 0
    # type_descriptor at i-16 typically; walk .rdata for col pointing here
    td = off_to_rva(sec, i) - 16
    raw0, raw1, _ = text_range(sec)
    # find complete object locator: +0x0C = td rva
    rdata = None
    for name_s, va, vsize, raw, raw_size in sec:
        if name_s.startswith(b".rdata") or name_s.startswith(b".data"):
            pass
    # brute: search packed td rva in file
    pat = struct.pack("<I", td)
    hits = []
    start = 0
    while len(hits) < 8:
        j = data.find(pat, start)
        if j < 0:
            break
        rva = off_to_rva(sec, j)
        hits.append(rva)
        start = j + 1
    print(name.decode(), "td", hex(td), "refs", [hex(x) for x in hits[:6]])
    return td


def vt_slots(vt_rva, n, name):
    off = rva_to_off(sec, vt_rva)
    if off is None:
        print(name, "bad vt")
        return
    print(f"\n{name} vt 0x{vt_rva:08x}")
    for i in range(n):
        va = struct.unpack_from("<Q", data, off + i * 8)[0]
        if not (ib <= va < ib + 0x4000000):
            continue
        rva = va - ib
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sec, rva, 16)}")


print("strings")
for k in (
    b"CAIFront",
    b"CAIGeneral",
    b"UpdateFront",
    b"ExecuteOrder",
    b"AssignUnitsToFront",
    b"BalanceUnitsOnFront",
    b"COrdersGroup",
    b"DoUnitAI",
    b"ProcessUnitAI",
    b"ArmyAI",
    b"land combat",
    b"front_ai",
    b"ai_front",
    b"EnableAI",
    b"DisableAI",
    b"IsAIEnabled",
):
    offs = find_cstr(data, k)
    if not offs:
        i = data.find(k)
        if i < 0:
            print(" ", k.decode(), "MISSING")
            continue
        rva = off_to_rva(sec, i)
        print(" ", k.decode(), "substr", hex(rva) if rva else "?")
        continue
    print(" ", k.decode(), hex(off_to_rva(sec, offs[0])))

print("\nRTTI")
for name in (
    b".?AVCAIGeneral@@",
    b".?AVCOrdersGroup@@",
    b".?AVCFront@@",
    b".?AVCOrderInstance@@",
    b".?AVCArmyGroup@@",
    b".?AVCStrategicAI@@",
    b".?AVCCountryAI@@",
):
    rtti_vt(name)

# function starts near move ctor 0xd62020
dump(0x00D61800, 48, "before d61800")
# find calls to a function that contains d62020 - find prologue
raw = rva_to_off(sec, 0x00D61000)
for delta in range(0, 0x1000):
    o = raw + delta
    if data[o : o + 7] in (
        bytes.fromhex("40 55 53 56 57"),
        bytes.fromhex("48 89 5c 24 08"),
    ) or data[o : o + 5] == bytes.fromhex("48 89 5c 24"):
        rva = 0x00D61000 + delta
        if rva < 0x00D62020:
            last = rva
print("last prologue before d62020", hex(last) if "last" in dir() else "?")

# callers of likely army move-issue function - try several candidates
for cand in (0x00D61C00, 0x00D61850, 0x00D61400, 0x00D61000):
    n = len(calls_to(data, sec, cand))
    if n:
        print("calls to", hex(cand), n)

dump(0x01074470, 96, "CAIGeneral[14]")
dump(0x0107D9C0, 80, "CAIGeneral[13]")
print("\ncallers CAIGeneral[14]")
for rva, kind in calls_to(data, sec, 0x01074470)[:15]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 12), 24)}")
print("\ncallers CAIGeneral[13]")
for rva, kind in calls_to(data, sec, 0x0107D9C0)[:15]:
    print(f"  {kind} 0x{rva:08x} {hexdump(data, sec, max(0, rva - 12), 24)}")

print("\nCCountryAI Update 0x002acf30")
dump(0x002ACF30, 160, "CCountryAI Update")
print("callers Update")
n = 0
for rva, kind in calls_to(data, sec, 0x002ACF30):
    print(f"  {kind} 0x{rva:08x}")
    n += 1
    if n >= 12:
        break

# HandleAiMicroAttacks function start
print("\nHandleAiMicro around 0x01079c19")
dump(0x01079B80, 80, "micro")
