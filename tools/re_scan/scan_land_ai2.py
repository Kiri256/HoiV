from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, find_cstr, hexdump, lea_to, load_pe, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)

print("move ctor sites")
for rva in (0x00D61F80, 0x00D62000, 0x014B8900, 0x014B8D80, 0x01A2FA80, 0x01A2FBE0):
    print(f"\n== 0x{rva:08x}")
    print(hexdump(data, sec, rva, 96))

print("\npost AI assert LEAs")
offs = find_cstr(data, b"PostingCountry.GetCountry().GetAI()->IsCommandsAllowed()")
if offs:
    rva = off_to_rva(sec, offs[0])
    print("str", hex(rva))
    for lea in lea_to(data, sec, rva, 8):
        print("lea", hex(lea))
        print(hexdump(data, sec, lea - 80, 128))

print("\nHasGameStarted AI post")
offs = find_cstr(
    data,
    b"CCurrentGameState::HasGameStarted() && \"Trying to post AI command when game hasn't started\"",
)
if offs:
    rva = off_to_rva(sec, offs[0])
    print("str", hex(rva))
    for lea in lea_to(data, sec, rva, 6):
        print("lea", hex(lea), hexdump(data, sec, lea - 40, 80))

print("\nai_enabled LEA")
offs = find_cstr(data, b"ai_enabled")
if offs:
    rva = off_to_rva(sec, offs[0])
    print("str", hex(rva))
    for lea in lea_to(data, sec, rva, 8):
        print("lea", hex(lea), hexdump(data, sec, lea - 16, 40))

print("\nCAIGeneral [14] 0x01074470")
print(hexdump(data, sec, 0x01074470, 80))
print("\nCAIGeneral [13] 0x0107d9c0")
print(hexdump(data, sec, 0x0107D9C0, 64))
