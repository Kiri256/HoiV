#!/usr/bin/env python3
"""PE helpers for the hash-pinned HOI4 1.19.1.0 image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

IMAGE_BASE = 0x140000000
GET_PLAYER = 0x001DBB30
SINGLETON = 0x033048C0
COUNTRY_VT = 0x027C0E80


def load_pe(path: Path):
    data = path.read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt = e_lfanew + 24
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0]
        vsize, va, raw_size, raw = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, va, max(vsize, raw_size), raw, raw_size))
    return data, image_base, sections


def rva_to_off(sections, rva: int) -> int | None:
    for _name, va, vsize, raw, raw_size in sections:
        if va <= rva < va + vsize:
            rel = rva - va
            if rel < raw_size:
                return raw + rel
    return None


def off_to_rva(sections, off: int) -> int | None:
    for _name, va, _vsize, raw, raw_size in sections:
        if raw <= off < raw + raw_size:
            return va + (off - raw)
    return None


def text_range(sections):
    for name, va, vsize, raw, raw_size in sections:
        if name.startswith(b".text"):
            return raw, raw + raw_size, va
    raise SystemExit("no .text")


def find_cstr(data: bytes, s: bytes) -> list[int]:
    hits = []
    start = 0
    while True:
        i = data.find(s + b"\0", start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def calls_to(data, sections, target_rva: int):
    raw0, raw1, _va = text_range(sections)
    out = []
    for off in range(raw0, raw1 - 5):
        if data[off] not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        rva = off_to_rva(sections, off)
        if rva is None:
            continue
        if rva + 5 + rel == target_rva:
            out.append((rva, "call" if data[off] == 0xE8 else "jmp"))
    return out


def hexdump(data, sections, rva: int, n: int) -> str:
    off = rva_to_off(sections, rva)
    if off is None:
        return f"bad rva 0x{rva:x}"
    return " ".join(f"{b:02x}" for b in data[off : off + n])


def rip_loads(data, sections, target_rva: int):
    raw0, raw1, _va = text_range(sections)
    hits = []
    for off in range(raw0, raw1 - 7):
        if data[off] == 0x48 and data[off + 1] == 0x8B and data[off + 2] in (0x05, 0x0D, 0x15):
            rel = struct.unpack_from("<i", data, off + 3)[0]
            rva = off_to_rva(sections, off)
            if rva is not None and rva + 7 + rel == target_rva:
                hits.append(rva)
    return hits


def imm32_uses(data, sections, imm: int, limit=40):
    raw0, raw1, _va = text_range(sections)
    pat = struct.pack("<I", imm)
    hits = []
    start = raw0
    while len(hits) < limit:
        i = data.find(pat, start, raw1)
        if i < 0:
            break
        rva = off_to_rva(sections, i - 1)
        if rva is not None:
            hits.append((rva, hexdump(data, sections, rva, 12)))
        start = i + 1
    return hits


def cmd_player(path: Path):
    data, image_base, sections = load_pe(path)
    print(f"image_base=0x{image_base:x} size={len(data)}")
    print("GetPlayer bytes", hexdump(data, sections, GET_PLAYER, 16))
    print("\nGetPlayer calls:")
    for rva, kind in calls_to(data, sections, GET_PLAYER):
        print(f"  {kind} @0x{rva:08x}  context {hexdump(data, sections, rva - 16, 32)}")
    print("\nStores/loads around +0xA30:")
    for rva, hx in imm32_uses(data, sections, 0xA30, 30):
        print(f"  0x{rva:08x} {hx}")
    print("\nStores/loads around +0xA28:")
    for rva, hx in imm32_uses(data, sections, 0xA28, 15):
        print(f"  0x{rva:08x} {hx}")
    print("\nlea GetPlayer assert")
    for file_off in find_cstr(data, b"Tag == CCurrentGameState::GetInstance()->GetPlayer()"):
        rva = off_to_rva(sections, file_off)
        print(f"  str rva=0x{rva:x}" if rva else f"  file 0x{file_off:x}")
    print("\nCCountry small getters (first 40 vt slots)")
    vt = rva_to_off(sections, COUNTRY_VT)
    for i in range(40):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            continue
        rva = va - image_base
        off = rva_to_off(sections, rva)
        b = data[off : off + 8]
        if b[:2] == b"\x8b\x81" and b[6] == 0xC3:
            disp = struct.unpack_from("<I", b, 2)[0]
            print(f"  [{i}] mov eax,[rcx+0x{disp:x}]")
        elif b[:3] == b"\x48\x8b" and b[3] == 0x81 and len(b) >= 8 and b[7] == 0xC3:
            disp = struct.unpack_from("<I", b, 4)[0]
            print(f"  [{i}] mov rax,[rcx+0x{disp:x}]")


def describe_getter(b: bytes) -> str | None:
    if len(b) < 8:
        return None
    if b[0] == 0x8B and b[1] == 0x81 and b[6] == 0xC3:
        return f"mov eax,[rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}]"
    if b[0] == 0x8A and b[1] == 0x81 and b[6] == 0xC3:
        return f"mov al,[rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}]"
    if b[0] == 0x0F and b[1] == 0xB6 and b[2] == 0x81 and b[7] == 0xC3:
        return f"movzx eax,byte [rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]"
    if b[0] == 0x80 and b[1] == 0xB9 and b[6] == 0x00:
        return f"cmp byte [rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}],0"
    if b[:3] == b"\x48\x8b" and b[3] == 0x81 and b[7] == 0xC3:
        return f"mov rax,[rcx+0x{struct.unpack_from('<I', b, 4)[0]:x}]"
    if b[0] == 0x32 and b[1] == 0xC0 and b[2] == 0xC3:
        return "xor al,al; ret"
    if b[0] == 0xB0 and b[1] == 0x01 and b[2] == 0xC3:
        return "mov al,1; ret"
    if b[:3] == b"\x48\x8d" and b[3] == 0x81 and b[7] == 0xC3:
        return f"lea rax,[rcx+0x{struct.unpack_from('<I', b, 4)[0]:x}]"
    if b[:3] == b"\x48\x8b" and b[3] == 0x41 and b[5] == 0xC3:
        return f"mov rax,[rcx+0x{b[4]:x}]"
    if b[:3] == b"\x48\x8d" and b[3] == 0x41 and b[5] == 0xC3:
        return f"lea rax,[rcx+0x{b[4]:x}]"
    return None


def cmd_ai(path: Path):
    data, image_base, sections = load_pe(path)
    dump_vt_getters(data, image_base, sections, "CCountry", COUNTRY_VT, 220)
    dump_vt_getters(data, image_base, sections, "CCountryAI", 0x02710C90, 80)
    dump_vt_getters(data, image_base, sections, "CStrategicAI", 0x027BBAD8, 40)
    print("\nCCountry[8]")
    print(" ", hexdump(data, sections, 0x006F1440, 48))
    print("\nCCountryAI vt heads")
    vt = rva_to_off(sections, 0x02710C90)
    for i in range(16):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            continue
        rva = va - image_base
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 24)}")
    keys = [
        b"AI is now ON",
        b"AI is now OFF",
        b"Human AI is now ON",
        b"human_ai",
        b"Enable human_ai",
        b"PostingCountry.GetCountry().GetAI()->IsCommandsAllowed()",
        b"DoCountryHourlyUpdates",
        b"ProcessAIHourlyUpdate",
        b"ai_enabled",
    ]
    for k in keys:
        offs = find_cstr(data, k)
        print(f"\n{k.decode()}")
        if not offs:
            print("  missing")
            continue
        rva = off_to_rva(sections, offs[0])
        print(f"  str 0x{rva:x}")
        for lea in lea_to(data, sections, rva, 6):
            print(f"  lea @0x{lea:08x}  {hexdump(data, sections, max(0, lea - 32), 64)}")
    raw0, raw1, _va = text_range(sections)
    print("\nset byte [rcx+0x60]")
    for pat, label in (
        (bytes.fromhex("c6 41 60 00"), "set0"),
        (bytes.fromhex("c6 41 60 01"), "set1"),
        (bytes.fromhex("80 79 60 00"), "cmp_this+60"),
        (bytes.fromhex("80 7f 60 00"), "cmp_rdi+60"),
    ):
        off = raw0
        n = 0
        while n < 20:
            i = data.find(pat, off, raw1)
            if i < 0:
                break
            print(f"  {label} @0x{off_to_rva(sections, i):08x} {hexdump(data, sections, off_to_rva(sections, i), 16)}")
            off = i + 1
            n += 1
    print("\ncalls to CCountryAI[15] 0x002acf20")
    for rva, kind in calls_to(data, sections, 0x002ACF20):
        print(f"  {kind} @0x{rva:08x} {hexdump(data, sections, rva - 12, 24)}")
    print("\ncalls to CCountryAI GetCountry 0x002a8d90")
    n = 0
    for rva, kind in calls_to(data, sections, 0x002A8D90):
        print(f"  {kind} @0x{rva:08x} {hexdump(data, sections, rva, 12)}")
        n += 1
        if n >= 15:
            break
    print("\nGetCountry 0x002a8d90")
    print(" ", hexdump(data, sections, 0x002A8D90, 48))
    print("\nCCountryAI[2] Update 0x002acf30")
    print(" ", hexdump(data, sections, 0x002ACF30, 128))
    print("\npost-AI assert fn 0x0029e580")
    print(" ", hexdump(data, sections, 0x0029E580, 160))
    print("\nconsole ai 0x00292000")
    print(" ", hexdump(data, sections, 0x00292000, 160))
    print("\nconsole ai 0x00292200")
    print(" ", hexdump(data, sections, 0x00292200, 160))
    print("\nCCountry +0x484 uses")
    for rva, hx in imm32_uses(data, sections, 0x484, 20):
        print(f"  0x{rva:08x} {hx}")
    print("\nCCountry first 80 vt")
    vt = rva_to_off(sections, COUNTRY_VT)
    for i in range(80):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            continue
        rva = va - image_base
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")
    print("\nLEA CCountryAI vtable")
    for lea in lea_to(data, sections, 0x02710C90, 12):
        print(f"  0x{lea:08x} {hexdump(data, sections, max(0, lea - 8), 40)}")
    print("\nset1 0x002acc70 callers")
    for rva, kind in calls_to(data, sections, 0x002ACC70):
        print(f"  {kind} @0x{rva:08x} {hexdump(data, sections, rva - 8, 20)}")


def dump_vt_getters(data, image_base, sections, name: str, vt_rva: int, count: int):
    print(f"\n{name} getters")
    vt = rva_to_off(sections, vt_rva)
    for i in range(count):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            continue
        rva = va - image_base
        off = rva_to_off(sections, rva)
        if off is None:
            continue
        desc = describe_getter(data[off : off + 8])
        if desc:
            print(f"  [{i:3d}] 0x{rva:08x} {desc}")


def cmd_human(path: Path):
    data, image_base, sections = load_pe(path)
    keys = [
        b"IsHuman",
        b"IsPlayer",
        b"IsLocalPlayer",
        b"GetHuman",
        b"human_ai",
        b"_IsHuman",
        b"IsAI",
        b"GetAI",
        b"PLAYER",
        b"GetTrueOwnerTag",
        b"GetController",
        b"Idler.GetPlayer",
        b"GetPlayer()",
        b"local_player",
        b"HumanPlayer",
        b"PlayAs",
    ]
    print("string hits:")
    for k in keys:
        hits = []
        start = 0
        while len(hits) < 6:
            i = data.find(k, start)
            if i < 0:
                break
            begin = i
            while begin > 0 and 32 <= data[begin - 1] < 127 and i - begin < 50:
                begin -= 1
            end = i + len(k)
            while end < len(data) and 32 <= data[end] < 127 and end - begin < 90:
                end += 1
            rva = off_to_rva(sections, begin)
            hits.append((rva, data[begin:end].decode("latin1", "replace")))
            start = i + 1
        if not hits:
            print(f"  MISS {k.decode()}")
        else:
            for rva, text in hits:
                loc = f"0x{rva:x}" if rva is not None else "?"
                print(f"  {loc} {text}")
    dump_vt_getters(data, image_base, sections, "CCountry", COUNTRY_VT, 80)
    dump_vt_getters(data, image_base, sections, "CCurrentGameState", 0x026FB148, 80)
    dump_vt_getters(data, image_base, sections, "CGameIdler", 0x02710270, 40)


def lea_to(data, sections, target_rva: int, limit=8):
    raw0, raw1, _va = text_range(sections)
    hits = []
    for off in range(raw0, raw1 - 7):
        if data[off] == 0x48 and data[off + 1] == 0x8D and data[off + 2] in (0x05, 0x0D, 0x15, 0x1D):
            rel = struct.unpack_from("<i", data, off + 3)[0]
            rva = off_to_rva(sections, off)
            if rva is not None and rva + 7 + rel == target_rva:
                hits.append(rva)
                if len(hits) >= limit:
                    break
    return hits


def cmd_idler(path: Path):
    data, image_base, sections = load_pe(path)
    keys = [
        b"_Country.GetCountry().IsHumanControlled()",
        b"Idler.GetPlayer() == Country.GetCountryTag()",
        b"_Idler.GetPlayer() == _Division.GetPtr()->GetTrueOwnerTag()",
    ]
    for k in keys:
        offs = find_cstr(data, k)
        print(f"\n{k.decode()}")
        if not offs:
            print("  missing")
            continue
        rva = off_to_rva(sections, offs[0])
        print(f"  str 0x{rva:x}")
        for lea in lea_to(data, sections, rva):
            print(f"  lea @0x{lea:08x}  {hexdump(data, sections, lea - 24, 48)}")
    print("\nCCountry[8] 0x006f1440")
    print(" ", hexdump(data, sections, 0x006F1440, 32))
    print("\nIsHumanControlled call context 0x00b9b6e0")
    print(" ", hexdump(data, sections, 0x00B9B6E0, 80))
    print("\nIdler singleton RIP 0x03304d10")
    for rva in rip_loads(data, sections, 0x03304D10)[:25]:
        print(f"  0x{rva:08x} {hexdump(data, sections, rva, 16)}")
    print("\nIdler.GetPlayer substring")
    key = b"Idler.GetPlayer()"
    start = 0
    while True:
        i = data.find(key, start)
        if i < 0:
            break
        rva = off_to_rva(sections, i)
        print(f"  str 0x{rva:x} {data[i:i+80].split(chr(0).encode(),1)[0]}")
        if rva:
            for lea in lea_to(data, sections, rva, 4):
                print(f"    lea @0x{lea:08x} {hexdump(data, sections, max(0, lea-20), 40)}")
        start = i + 1
    print("\nIdler.GetPlayer compare site 0x01aad3c0")
    print(" ", hexdump(data, sections, 0x01AAD3C0, 160))
    print("\nmov rax,[rcx+0x4F0]; ret")
    raw0, raw1, _va = text_range(sections)
    pat = bytes.fromhex("48 8b 81 f0 04 00 00 c3")
    off = raw0
    while True:
        i = data.find(pat, off, raw1)
        if i < 0:
            break
        print(f"  0x{off_to_rva(sections, i):08x}")
        off = i + 1
    pat2 = bytes.fromhex("48 8b 81 f8 04 00 00 c3")
    print("mov rax,[rcx+0x4F8]; ret")
    off = raw0
    while True:
        i = data.find(pat2, off, raw1)
        if i < 0:
            break
        print(f"  0x{off_to_rva(sections, i):08x}")
        off = i + 1
    print("\n+0x145C uses")
    for rva, hx in imm32_uses(data, sections, 0x145C, 25):
        print(f"  0x{rva:08x} {hx}")
    print("\nCGameIdler vt heads")
    vt = rva_to_off(sections, 0x02710270)
    for i in range(30):
        va = struct.unpack_from("<Q", data, vt + i * 8)[0]
        if not (image_base <= va < image_base + 0x4000000):
            continue
        rva = va - image_base
        print(f"  [{i:3d}] 0x{rva:08x} {hexdump(data, sections, rva, 16)}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("exe")
    p.add_argument("cmd", nargs="?", default="player")
    args = p.parse_args()
    path = Path(args.exe)
    if args.cmd == "player":
        cmd_player(path)
    elif args.cmd == "human":
        cmd_human(path)
    elif args.cmd == "idler":
        cmd_idler(path)
    elif args.cmd == "ai":
        cmd_ai(path)
    else:
        sys.exit(f"unknown cmd {args.cmd}")


if __name__ == "__main__":
    main()
