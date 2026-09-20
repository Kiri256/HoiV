#!/usr/bin/env python3
"""Follow-up: identify 0x01A2ED80 caller, country source, other land order ctors."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"
IMAGE_SPAN = 0x4000000

CAND = 0x01A2ED80
CALLER = 0x01A31660
ARMY_VT = 0x02933D20
THEATRE_VT = 0x0294ED28
THEATER_GROUP_VT = 0x029BE6C0
FRONT_VT = 0x0294EE20
ORDER_INST_VT = 0x0295FA08
ORDERS_GROUP_VT = 0x0292BEC0
ARMY_GROUP_VT = 0x0292BF58


def parse_pdata(data, sections):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    dd = e_lfanew + 24 + 112
    exc_rva, exc_size = struct.unpack_from("<II", data, dd + 3 * 8)
    off = rva_to_off(sections, exc_rva)
    out = []
    for i in range(exc_size // 12):
        begin, end, _u = struct.unpack_from("<III", data, off + i * 12)
        if begin < end:
            out.append((begin, end))
    out.sort()
    return out


def fn_for(funcs, rva):
    lo, hi = 0, len(funcs)
    while lo < hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= rva:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    begin, end = funcs[lo - 1]
    return (begin, end) if begin <= rva < end else None


def slot(data, ib, sections, vt, i):
    off = rva_to_off(sections, vt + i * 8)
    if off is None:
        return 0
    va = struct.unpack_from("<Q", data, off)[0]
    return va - ib if ib <= va < ib + IMAGE_SPAN else 0


def describe_getter(data, sections, rva):
    hx = hexdump(data, sections, rva, 16)
    off = rva_to_off(sections, rva)
    b = data[off : off + 16]
    if b[:3] == b"\x48\x8b\xc1" and b[3] == 0xC3:
        return "identity this"
    if b[0] == 0x33 and b[1] == 0xC0 and b[2] == 0xC3:
        return "xor eax,eax"
    if b[:2] == b"\x8b\x81" and b[6] == 0xC3:
        return f"mov eax,[rcx+0x{struct.unpack_from('<I', b, 2)[0]:x}]"
    if b[:3] == b"\x48\x8b\x81" and b[7] == 0xC3:
        return f"mov rax,[rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]"
    if b[:3] == b"\x48\x8d\x81" and b[7] == 0xC3:
        return f"lea rax,[rcx+0x{struct.unpack_from('<I', b, 3)[0]:x}]"
    if b[:3] == b"\x48\x8b\x41" and b[4] == 0xC3:
        return f"mov rax,[rcx+0x{b[3]:x}]"
    if b[:3] == b"\x48\x8d\x41" and b[4] == 0xC3:
        return f"lea rax,[rcx+0x{b[3]:x}]"
    if b[:2] == b"\x8b\x41" and b[3] == 0xC3:
        return f"mov eax,[rcx+0x{b[2]:x}]"
    return hx


def find_qword(data, ib, sections, fn_rva):
    needle = struct.pack("<Q", ib + fn_rva)
    hits = []
    for name, _va, _vs, raw, raw_size in sections:
        if not (name.startswith(b".rdata") or name.startswith(b".data")):
            continue
        off = raw
        end = raw + raw_size
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            hits.append(off_to_rva(sections, i))
            off = i + 8
    return hits


def vt_near(vt_map, slot_rva):
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x800:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def rel32_call(data, sections, rva):
    off = rva_to_off(sections, rva)
    if off is None or data[off] not in (0xE8, 0xE9):
        return None
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return (rva + 5 + rel) & 0xFFFFFFFF


def dump_calls(data, sections, funcs, start, stop, interesting):
    off = rva_to_off(sections, start)
    blob = data[off : off + stop - start]
    for i, b in enumerate(blob):
        if b != 0xE8 or i + 5 > len(blob):
            continue
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = (start + i + 5 + rel) & 0xFFFFFFFF
        label = interesting.get(tgt, "")
        if label:
            print(f"  0x{start + i:08x} call 0x{tgt:08x} {label}")


def main():
    data, ib, sections = load_pe(EXE)
    funcs = parse_pdata(data, sections)
    vt_map = {int(k, 16): v for k, v in json.loads(CACHE.read_text(encoding="utf-8"))["vt_map"].items()}
    name_to_vt = {}
    for vt, name in vt_map.items():
        name_to_vt.setdefault(name, vt)

    print("== extra actor types ==")
    for name in (
        ".?AVCTheatre@@",
        ".?AVCTheaterGroup@@",
        ".?AVCAirTheatre@@",
        ".?AVCNavyTheater@@",
        ".?AVCOrderInstance@@",
        ".?AVCOrdersGroup@@",
        ".?AVCFront@@",
        ".?AVCArmyGroup@@",
        ".?AVCStrategicAI@@",
    ):
        print(f"  {name} 0x{name_to_vt.get(name, 0):08x}")
    print("TheatreAI-like names:")
    for vt, name in sorted(vt_map.items(), key=lambda kv: kv[1]):
        if "TheatreAI" in name or "TheaterAI" in name or "NAITheatre" in name:
            if "DefineRegistry" in name:
                continue
            print(f"  {name} 0x{vt:08x}")

    print("\n== CArmy simple getters ==")
    for i in range(80):
        rva = slot(data, ib, sections, ARMY_VT, i)
        desc = describe_getter(data, sections, rva) if rva else "none"
        if "rcx+" in desc or desc in ("identity this", "xor eax,eax"):
            print(f"  [{i:3d}] 0x{rva:08x} {desc}")

    print("\n== CTheatre / CTheaterGroup / CFront / COrderInstance / COrdersGroup slot[0:24] ==")
    for name, vt in (
        ("CTheatre", THEATRE_VT),
        ("CTheaterGroup", THEATER_GROUP_VT),
        ("CFront", FRONT_VT),
        ("COrderInstance", ORDER_INST_VT),
        ("COrdersGroup", ORDERS_GROUP_VT),
        ("CArmyGroup", ARMY_GROUP_VT),
    ):
        print(f"\n{name} 0x{vt:08x}")
        for i in range(24):
            rva = slot(data, ib, sections, vt, i)
            print(f"  [{i:3d}] 0x{rva:08x} {describe_getter(data, sections, rva) if rva else 'none'}")

    print("\n== 0x01A2ED80 first call target (this+0x18) ==")
    first_call = None
    off = rva_to_off(sections, CAND)
    blob = data[off : off + 0x80]
    for i, b in enumerate(blob):
        if b == 0xE8:
            first_call = (CAND + i + 5 + struct.unpack_from("<i", blob, i + 1)[0]) & 0xFFFFFFFF
            print(f"  site 0x{CAND + i:08x} -> 0x{first_call:08x} {hexdump(data, sections, first_call, 24)}")
            break

    print("\n== caller 0x01A31660 ==")
    caller_fn = fn_for(funcs, CALLER)
    print("pdata", tuple(f"0x{x:08x}" for x in caller_fn) if caller_fn else None)
    print("prologue", hexdump(data, sections, CALLER, 96))
    print("call-site window", hexdump(data, sections, 0x01A31780, 64))

    print("\ncallers of 0x01A31660")
    for rva, kind in calls_to(data, sections, CALLER):
        fn = fn_for(funcs, rva)
        print(
            f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'} {hexdump(data, sections, max(0, rva - 16), 36)}"
        )

    print("\nvtable membership of 0x01A31660")
    for q in find_qword(data, ib, sections, CALLER):
        info = vt_near(vt_map, q)
        if info:
            vt, name, idx = info
            print(f"  qword@0x{q:08x} {name} [{idx}] vt=0x{vt:08x}")
        else:
            print(f"  qword@0x{q:08x}")

    print("\nvtable membership of 0x01A2ED80 (recheck)")
    for q in find_qword(data, ib, sections, CAND):
        info = vt_near(vt_map, q)
        print(f"  qword@0x{q:08x} {info}")

    interesting = {
        CAND: "candidate 0x01A2ED80",
        0x01350350: "CMoveCommand",
        0x01351750: "maybe SupportAttack ctor",
        0x01353710: "maybe SupportAttack 2",
        0x01355250: "maybe SupportAttack 3",
        0x0029E7B0: "post 29e7b0",
        0x0029E670: "post 29e670",
        0x002A8D90: "GetCountry",
        0x001DBB30: "GetPlayer",
        0x002ACF30: "CCountryAI Update",
        0x010ABA70: "mil min [14]",
        0x01074470: "general [14]",
    }
    if caller_fn:
        print("\ninteresting calls inside 0x01A31660")
        dump_calls(data, sections, funcs, caller_fn[0], caller_fn[1], interesting)
        print("all calls (first 40) in 0x01A31660")
        off = rva_to_off(sections, caller_fn[0])
        blob = data[off : off + caller_fn[1] - caller_fn[0]]
        n = 0
        for i, b in enumerate(blob):
            if b != 0xE8 or i + 5 > len(blob):
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (caller_fn[0] + i + 5 + rel) & 0xFFFFFFFF
            fn = fn_for(funcs, tgt)
            print(f"  0x{caller_fn[0] + i:08x} -> 0x{tgt:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
            n += 1
            if n >= 40:
                break

    print("\n== other land order ctor callers ==")
    for name, ctor in (
        ("CSupportAttack 0x1351750", 0x01351750),
        ("CSupportAttack 0x1353710", 0x01353710),
        ("CSupportAttack 0x1355250", 0x01355250),
        ("CMassMove 0x134fda0", 0x0134FDA0),
        ("CStrategicRedeploy lea-ctor guess", 0),
        ("CQueueUnitAction", 0),
    ):
        if ctor:
            print(f"\n{name}")
            for rva, kind in calls_to(data, sections, ctor)[:20]:
                fn = fn_for(funcs, rva)
                print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")

    for cmd_name in (
        ".?AVCSupportAttackCommand@@",
        ".?AVCStrategicRedeploymentCommand@@",
        ".?AVCQueueUnitActionCommand@@",
        ".?AVCMassMoveCommand@@",
        ".?AVCOrderExecuteCommand@@",
    ):
        vt = name_to_vt.get(cmd_name, 0)
        print(f"\n{cmd_name} vt=0x{vt:08x} [0]={slot(data, ib, sections, vt, 0):08x} [1]={slot(data, ib, sections, vt, 1):08x}")

    print("\n== parent callers of 0x01A31660: vtable membership ==")
    for rva, _kind in calls_to(data, sections, CALLER):
        fn = fn_for(funcs, rva)
        if not fn:
            continue
        print(f"\nparent [0x{fn[0]:08x},0x{fn[1]:08x}) site 0x{rva:08x}")
        print("  prologue", hexdump(data, sections, fn[0], 48))
        for q in find_qword(data, ib, sections, fn[0]):
            info = vt_near(vt_map, q)
            if info:
                vt, name, idx = info
                print(f"  method of {name} [{idx}] vt=0x{vt:08x}")
            else:
                print(f"  qword@0x{q:08x}")


if __name__ == "__main__":
    main()
