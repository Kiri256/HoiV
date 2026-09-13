from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, off_to_rva, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)
raw0, raw1, _ = text_range(sec)

pats = [
    (bytes.fromhex("80 b8 20 0c 00 00"), "cmp [rax+0xc20]"),
    (bytes.fromhex("80 b9 20 0c 00 00"), "cmp [rcx+0xc20]"),
    (bytes.fromhex("80 bb 20 0c 00 00"), "cmp [rbx+0xc20]"),
    (bytes.fromhex("80 bf 20 0c 00 00"), "cmp [rdi+0xc20]"),
    (bytes.fromhex("c6 80 20 0c 00 00"), "mov [rax+0xc20]"),
    (bytes.fromhex("c6 81 20 0c 00 00"), "mov [rcx+0xc20]"),
    (bytes.fromhex("c6 83 20 0c 00 00"), "mov [rbx+0xc20]"),
    (bytes.fromhex("c6 87 20 0c 00 00"), "mov [rdi+0xc20]"),
    (bytes.fromhex("c6 41 20"), "mov [rcx+0x20] too short"),
]
for pat, label in pats:
    print("---", label)
    off = raw0
    n = 0
    while n < 12:
        i = data.find(pat, off, raw1)
        if i < 0:
            if n == 0:
                print("  none")
            break
        rva = off_to_rva(sec, i)
        print(f"  0x{rva:08x} {hexdump(data, sec, rva, 16)}")
        off = i + 1
        n += 1
