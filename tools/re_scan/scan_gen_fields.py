from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def fields(rva, n, label):
    off = rva_to_off(sec, rva)
    chunk = data[off : off + n]
    print(f"\n== {label} 0x{rva:08x} fields")
    i = 0
    while i + 7 < len(chunk):
        b = chunk[i : i + 8]
        # 48 8b 4b XX / 48 8b 43 XX / 48 8b 83 imm32
        if b[0] == 0x48 and b[1] == 0x8B and b[2] in (0x43, 0x4B, 0x53, 0x73, 0x7B):
            print(f"  +{i:3d} mov r64,[rbx/rsi/rdi+0x{b[3]:x}] {chunk[i:i+8].hex()}")
            i += 4
            continue
        if b[0] == 0x48 and b[1] == 0x8B and b[2] in (0x83, 0x8B, 0xB3, 0xBB):
            disp = struct.unpack_from("<I", b, 3)[0]
            print(f"  +{i:3d} mov r64,[rbx+0x{disp:x}]")
            i += 7
            continue
        if b[0] == 0x48 and b[1] == 0x8B and b[2] == 0x49:
            print(f"  +{i:3d} mov rcx,[rcx+0x{b[3]:x}]")
            i += 4
            continue
        if b[:3] == b"\x80\xbb":
            disp = struct.unpack_from("<I", b, 2)[0]
            print(f"  +{i:3d} cmp byte [rbx+0x{disp:x}], {chunk[i+6]:x}")
            i += 7
            continue
        if b[:2] == b"\x80\x7b":
            print(f"  +{i:3d} cmp byte [rbx+0x{b[2]:x}], {b[3]:x}")
            i += 4
            continue
        if b[:2] == b"\xc6\x43":
            print(f"  +{i:3d} mov byte [rbx+0x{b[2]:x}], {b[3]:x}")
            i += 4
            continue
        if b[:2] == b"\xc6\x83":
            disp = struct.unpack_from("<I", b, 2)[0]
            print(f"  +{i:3d} mov byte [rbx+0x{disp:x}], {chunk[i+6]:x}")
            i += 7
            continue
        i += 1


fields(0x01074470, 0x400, "CAIGeneral[14]")
fields(0x010699B0, 0x200, "CAIGeneral ctor")
print("\nctor hex")
print(hexdump(data, sec, 0x010699B0, 180))
print("\n[14] after parent")
print(hexdump(data, sec, 0x01074470, 48))
print(hexdump(data, sec, 0x010744A0, 80))

# minister +8 then vt[1]
print("\nminister[14] head")
print(hexdump(data, sec, 0x010ABA70, 48))
