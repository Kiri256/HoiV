#!/usr/bin/env python3
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import hexdump, load_pe, rva_to_off

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
data, ib, sec = load_pe(EXE)


def dump_calls(start, stop, interesting):
    off = rva_to_off(sec, start)
    blob = data[off : off + stop - start]
    print(f"\n=== 0x{start:08x} .. 0x{stop:08x} ===")
    for i in range(0, len(blob) - 4):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (start + i + 5 + rel) & 0xFFFFFFFF
            if tgt in interesting:
                print(f"  0x{start + i:08x} call 0x{tgt:08x}")


interesting = {
    0x002A8D90,
    0x002A8E20,
    0x001DBB30,
    0x0181DA50,
    0x0029E7B0,
    0x0029E670,
    0x00F3EAE0,
    0x01077350,
    0x01077370,
}
print("idler around 0x00DC5F41")
print(hexdump(data, sec, 0x00DC5F20, 64))
dump_calls(0x00DC44C0, 0x00DC7000, interesting)
print("\nexec first 96")
print(hexdump(data, sec, 0x00F3EAE0, 96))
dump_calls(0x00F3EAE0, 0x00F41074, interesting)
print("\nprologues")
for rva, n in ((0x01A31660, 24), (0x002A7DE0, 40), (0x002AB450, 24), (0x00F3EAE0, 24)):
    print(f"0x{rva:08x} {hexdump(data, sec, rva, n)}")
off = rva_to_off(sec, 0x002A7DE0)
rel = struct.unpack_from("<i", data, off + 14)[0]
print(f"mass e8 at +13? byte13={data[off+13]:02x} byte14={data[off+14]:02x}")
print(f"if e8 at +13: tgt=0x{(0x002A7DE0 + 18 + struct.unpack_from('<i', data, off + 14)[0]) & 0xFFFFFFFF:08x}")
