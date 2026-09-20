#!/usr/bin/env python3
"""Command-type index + 0x01A2ED80 three-check for the pinned HOI4 build.

Cache is bound to the pinned SHA-256. This is static evidence only.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import calls_to, hexdump, load_pe, off_to_rva, rva_to_off, text_range

PINNED_SHA = "16022851eaa571728aa3a0b5fd5f990a56da57e2249a4c1b9cfb30336f59b120"
EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")
CACHE = Path(__file__).resolve().parents[2] / "build" / "re_cmd_index.json"

KNOWN = {
    "CMoveCommand": 0x01350350,
    "post_ai_29e670": 0x0029E670,
    "post_ai_29e7b0": 0x0029E7B0,
    "candidate": 0x01A2ED80,
    "get_country": 0x002A8D90,
    "get_player": 0x001DBB30,
    "country_ai_update": 0x002ACF30,
    "mil_min_14": 0x010ABA70,
    "general_14": 0x01074470,
}

ARMY_VT = 0x02933D20
UNIT_VT = 0x0292CCE8
TASKFORCE_VT = 0x0293C6D0
COUNTRY_VT = 0x027C0E80
COUNTRY_AI_VT = 0x02710C90

LAND_KEEP = (
    "Move",
    "Attack",
    "Support",
    "Advance",
    "Retreat",
    "Withdraw",
    "Redeploy",
    "Division",
    "Army",
    "Front",
    "Theater",
    "Order",
    "Battle",
    "Plan",
    "Invade",
    "Assign",
    "Attach",
    "Detach",
    "Strategic",
    "Micro",
    "Execute",
)
LAND_DROP = (
    "Navy",
    "Naval",
    "Fleet",
    "Ship",
    "TaskForce",
    "Air",
    "Wing",
    "Plane",
    "Ace",
    "Diplomacy",
    "Trade",
    "Focus",
    "Research",
    "Production",
    "Construction",
    "Politics",
    "Ideology",
    "Occupation",
    "Spy",
    "Intel",
    "lambda",
    "Allocator",
    "Iterator",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_pdata(data: bytes, image_base: int, sections) -> list[tuple[int, int]]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt = e_lfanew + 24
    dd = opt + 112
    exc_rva, exc_size = struct.unpack_from("<II", data, dd + 3 * 8)
    off = rva_to_off(sections, exc_rva)
    if off is None or exc_size < 12:
        return []
    out = []
    for i in range(exc_size // 12):
        begin, end, _unwind = struct.unpack_from("<III", data, off + i * 12)
        if begin < end:
            out.append((begin, end))
    out.sort()
    return out


def fn_for(funcs: list[tuple[int, int]], rva: int) -> tuple[int, int] | None:
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
    if begin <= rva < end:
        return begin, end
    return None


def collect_rtti(data: bytes, image_base: int, sections) -> dict[int, str]:
    """Return vtable RVA -> type name for MSVC RTTI CompleteObjectLocator layout."""
    names: dict[int, str] = {}
    start = 0
    tds: dict[int, str] = {}
    while True:
        i = data.find(b".?AV", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        if 0 < end - i < 96:
            name = data[i:end].decode("latin1", "replace")
            rva = off_to_rva(sections, i)
            if rva and rva >= 16:
                tds[rva - 16] = name
        start = i + 4

    rdata = None
    for name, va, _vsize, raw, raw_size in sections:
        if name.startswith(b".rdata"):
            rdata = (raw, raw + raw_size, va)
            break
    if rdata is None:
        return names
    raw0, raw1, _va = rdata
    cols: dict[int, str] = {}
    for off in range(raw0, raw1 - 16, 4):
        sig = struct.unpack_from("<I", data, off)[0]
        if sig != 1:
            continue
        td = struct.unpack_from("<I", data, off + 12)[0]
        name = tds.get(td)
        if name is None:
            continue
        col_rva = off_to_rva(sections, off)
        if col_rva:
            cols[col_rva] = name

    want = {image_base + col for col in cols}
    for off in range(raw0, raw1 - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if q not in want:
            continue
        col_rva = q - image_base
        vt = off_to_rva(sections, off + 8)
        if vt:
            names[vt] = cols[col_rva]
    return names


def slot_rva(data, image_base, sections, vt: int, index: int) -> int:
    off = rva_to_off(sections, vt + index * 8)
    if off is None:
        return 0
    va = struct.unpack_from("<Q", data, off)[0]
    return va - image_base if image_base <= va < image_base + 0x4000000 else 0


def describe_fn(data, sections, rva: int) -> str:
    if not rva:
        return "none"
    return f"0x{rva:08x} {hexdump(data, sections, rva, 16)}"


def landish(name: str) -> bool:
    if any(x in name for x in LAND_DROP):
        return False
    return any(x in name for x in LAND_KEEP) or name.endswith("Command@@")


def find_lea_to(data, sections, targets: set[int]) -> dict[int, list[int]]:
    raw0, raw1, _ = text_range(sections)
    hits: dict[int, list[int]] = defaultdict(list)
    for off in range(raw0, raw1 - 7):
        if data[off] != 0x48 or data[off + 1] != 0x8D:
            continue
        if data[off + 2] not in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
            continue
        rva = off_to_rva(sections, off)
        if rva is None:
            continue
        rel = struct.unpack_from("<i", data, off + 3)[0]
        dest = (rva + 7 + rel) & 0xFFFFFFFF
        if dest in targets:
            hits[dest].append(rva)
    return hits


def find_qword_fn(data, image_base, sections, fn_rva: int) -> list[tuple[int, int]]:
    """Find .rdata qwords equal to image_base+fn; return (slot_rva, slot_index_guess via nearby COL)."""
    raw_hits = []
    needle = struct.pack("<Q", image_base + fn_rva)
    for name, va, _vsize, raw, raw_size in sections:
        if not (name.startswith(b".rdata") or name.startswith(b".data")):
            continue
        start = raw
        end = raw + raw_size
        off = start
        while True:
            i = data.find(needle, off, end)
            if i < 0:
                break
            slot_rva = off_to_rva(sections, i)
            raw_hits.append(slot_rva)
            off = i + 8
    return [(x, 0) for x in raw_hits if x]


def vt_name_near(vt_map: dict[int, str], slot_rva: int) -> tuple[int, str, int] | None:
    best = None
    for vt, name in vt_map.items():
        if vt <= slot_rva < vt + 0x800:
            idx = (slot_rva - vt) // 8
            if best is None or vt > best[0]:
                best = (vt, name, idx)
    return best


def try_capstone():
    capstone_root = Path(os.environ.get("HOIV_CAPSTONE", ""))
    if capstone_root:
        sys.path.insert(0, str(capstone_root))
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        return md
    except Exception:
        return None


def disasm_range(md, data, image_base, sections, start: int, stop: int):
    off = rva_to_off(sections, start)
    if off is None or md is None:
        print(hexdump(data, sections, start, min(stop - start, 96)))
        return
    code = data[off : off + stop - start]
    for insn in md.disasm(code, image_base + start):
        rva = insn.address - image_base
        extra = ""
        if insn.bytes and insn.bytes[0] in (0xE8, 0xE9) and insn.size >= 5:
            rel = struct.unpack_from("<i", insn.bytes, 1)[0]
            extra = f"  ; -> 0x{(rva + insn.size + rel) & 0xFFFFFFFF:08x}"
        print(f"  0x{rva:08x}: {insn.mnemonic:7} {insn.op_str}{extra}")


def main() -> None:
    if not EXE.is_file():
        raise SystemExit(f"missing exe: {EXE}")
    digest = sha256_file(EXE)
    print(f"sha256={digest}")
    if digest != PINNED_SHA:
        raise SystemExit("exe hash mismatch; refuse to reuse this index")

    data, image_base, sections = load_pe(EXE)
    funcs = parse_pdata(data, image_base, sections)
    print(f"pdata functions={len(funcs)}")

    cache = None
    if CACHE.is_file():
        try:
            cache = json.loads(CACHE.read_text(encoding="utf-8"))
            if cache.get("sha256") != digest:
                cache = None
        except Exception:
            cache = None

    if cache and "vt_map" in cache:
        vt_map = {int(k, 16): v for k, v in cache["vt_map"].items()}
        print(f"cached rtti types={len(vt_map)}")
    else:
        print("building rtti map...")
        vt_map = collect_rtti(data, image_base, sections)
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(
            json.dumps(
                {
                    "sha256": digest,
                    "vt_map": {f"0x{k:08x}": v for k, v in sorted(vt_map.items())},
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        print(f"rtti types={len(vt_map)} cached -> {CACHE}")

    name_to_vt = {}
    for vt, name in vt_map.items():
        name_to_vt.setdefault(name, vt)

    print("\n== known actor vtables ==")
    for name in (
        ".?AVCArmy@@",
        ".?AVCUnit@@",
        ".?AVCTaskForce@@",
        ".?AVCFront@@",
        ".?AVCArmyGroup@@",
        ".?AVCTheater@@",
        ".?AVCOrdersGroup@@",
        ".?AVCOrderInstance@@",
        ".?AVCBattlePlan@@",
        ".?AVCAITheater@@",
        ".?AVCTheaterAI@@",
        ".?AVCFrontAI@@",
        ".?AVCAIFront@@",
        ".?AVCAIGeneral@@",
        ".?AVCAIMilitaryMinister@@",
        ".?AVCCountryAI@@",
        ".?AVCStrategicAI@@",
        ".?AVCUnitController@@",
    ):
        vt = name_to_vt.get(name, 0)
        print(f"  {name} vt=0x{vt:08x}" if vt else f"  {name} MISSING")

    print("\n== slot[8] (+0x40) of candidate objects ==")
    for name, vt in (
        (".?AVCArmy@@", ARMY_VT),
        (".?AVCUnit@@", UNIT_VT),
        (".?AVCTaskForce@@", TASKFORCE_VT),
        (".?AVCFront@@", name_to_vt.get(".?AVCFront@@", 0)),
        (".?AVCArmyGroup@@", name_to_vt.get(".?AVCArmyGroup@@", 0)),
        (".?AVCTheater@@", name_to_vt.get(".?AVCTheater@@", 0)),
        (".?AVCOrdersGroup@@", name_to_vt.get(".?AVCOrdersGroup@@", 0)),
    ):
        if not vt:
            print(f"  {name} no vt")
            continue
        print(f"  {name} [8]={describe_fn(data, sections, slot_rva(data, image_base, sections, vt, 8))}")

    print("\n== land-ish command types ==")
    cmds = []
    for vt, name in sorted(vt_map.items(), key=lambda kv: kv[1]):
        if "Command" not in name:
            continue
        if not landish(name):
            continue
        cmds.append((name, vt))
        print(f"  {name} vt=0x{vt:08x}")

    cmd_vts = {vt for _n, vt in cmds}
    print("\nbuilding LEA-to-command-vtable index...")
    lea_hits = find_lea_to(data, sections, cmd_vts | {ARMY_VT, UNIT_VT, TASKFORCE_VT})
    ctor_by_fn: dict[tuple[int, int], list[tuple[str, int]]] = defaultdict(list)
    for name, vt in cmds:
        sites = lea_hits.get(vt, [])
        print(f"\nLEA {name} count={len(sites)}")
        for site in sites[:12]:
            fn = fn_for(funcs, site)
            fns = f"[0x{fn[0]:08x},0x{fn[1]:08x})" if fn else "?"
            print(f"  0x{site:08x} fn={fns} {hexdump(data, sections, max(0, site - 8), 24)}")
            if fn:
                ctor_by_fn[fn].append((name, site))

    print("\n== CMoveCommand ctor callers mapped to functions ==")
    move_fns: dict[tuple[int, int], list[int]] = defaultdict(list)
    for rva, kind in calls_to(data, sections, KNOWN["CMoveCommand"]):
        fn = fn_for(funcs, rva)
        print(f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'}")
        if fn:
            move_fns[fn].append(rva)

    print("\n== functions that both construct land commands and call post-AI ==")
    post_sites = set()
    for tgt in (KNOWN["post_ai_29e670"], KNOWN["post_ai_29e7b0"]):
        for rva, _kind in calls_to(data, sections, tgt):
            post_sites.add(rva)
    post_fns = set()
    for rva in post_sites:
        fn = fn_for(funcs, rva)
        if fn:
            post_fns.add(fn)

    ranked = []
    for fn, names in ctor_by_fn.items():
        kinds = sorted({n for n, _s in names})
        score = 0
        if fn in move_fns:
            score += 4
        if fn in post_fns:
            score += 3
        if any("Move" in n or "Attack" in n or "Support" in n for n in kinds):
            score += 2
        ranked.append((score, fn, kinds, move_fns.get(fn, [])))
    ranked.sort(reverse=True)
    for score, fn, kinds, moves in ranked[:25]:
        print(
            f"  score={score} fn=[0x{fn[0]:08x},0x{fn[1]:08x}) cmds={kinds[:6]} moves={[hex(x) for x in moves]}"
        )

    cand = KNOWN["candidate"]
    cand_fn = fn_for(funcs, cand)
    print(f"\n== THREE CHECKS for 0x{cand:08x} pdata={cand_fn} ==")

    print("\n-- 1) direct callers --")
    callers = calls_to(data, sections, cand)
    if not callers:
        print("  no direct E8/E9")
    for rva, kind in callers:
        fn = fn_for(funcs, rva)
        print(
            f"  {kind} 0x{rva:08x} fn={f'[0x{fn[0]:08x},0x{fn[1]:08x})' if fn else '?'} {hexdump(data, sections, max(0, rva - 16), 32)}"
        )

    print("\n-- 1b) vtable membership --")
    slots = find_qword_fn(data, image_base, sections, cand)
    if not slots:
        print("  not present as a vtable/data qword")
    for slot_rva_x, _ in slots:
        info = vt_name_near(vt_map, slot_rva_x)
        if info:
            vt, name, idx = info
            print(f"  qword@0x{slot_rva_x:08x} -> {name} vt=0x{vt:08x} slot[{idx}]")
        else:
            print(f"  qword@0x{slot_rva_x:08x} (no nearby typed vtable)")

    print("\n-- 2/3) prologue, r15 path, country --")
    md = try_capstone()
    print("capstone", "yes" if md else "no")
    print("\nprologue")
    disasm_range(md, data, image_base, sections, cand, cand + 0x80)
    print("\nfirst CMoveCommand site window")
    disasm_range(md, data, image_base, sections, 0x01A2FA80, 0x01A2FB80)
    print("\nsecond CMoveCommand site window")
    disasm_range(md, data, image_base, sections, 0x01A2FC00, 0x01A2FD00)

    if cand_fn:
        start, stop = cand_fn
        off = rva_to_off(sections, start)
        blob = data[off : off + stop - start]
        print(f"\nfunction size 0x{stop - start:x}")
        interesting = {
            KNOWN["CMoveCommand"]: "CMoveCommand ctor",
            KNOWN["post_ai_29e670"]: "post 29e670",
            KNOWN["post_ai_29e7b0"]: "post 29e7b0",
            KNOWN["get_country"]: "GetCountry",
            KNOWN["get_player"]: "GetPlayer",
            0x002A6C50: "copy handle 0x2a6c50",
            0x01223A10: "inner handle 0x1223a10",
        }
        print("direct calls inside candidate:")
        for i, b in enumerate(blob):
            if b != 0xE8 or i + 5 > len(blob):
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = (start + i + 5 + rel) & 0xFFFFFFFF
            label = interesting.get(tgt, "")
            if label or tgt in {slot_rva(data, image_base, sections, ARMY_VT, 8)}:
                print(f"  0x{start + i:08x} call 0x{tgt:08x} {label}")
        print("indirect slot calls inside candidate:")
        i = 0
        while i + 6 < len(blob):
            if blob[i] == 0xFF and blob[i + 1] in (0x50, 0x51, 0x52, 0x53, 0x56, 0x57):
                disp = blob[i + 2]
                print(f"  0x{start + i:08x} call [reg+0x{disp:x}] slot~{disp // 8}")
                i += 3
                continue
            if blob[i] == 0xFF and blob[i + 1] == 0x90:
                disp = struct.unpack_from("<i", blob, i + 2)[0]
                if 0 < disp < 0x800 and disp % 8 == 0:
                    print(f"  0x{start + i:08x} call [rax+0x{disp:x}] slot={disp // 8}")
                i += 6
                continue
            i += 1
        print("imm32 field/id uses in candidate:")
        for imm, label in (
            (0x08, "maybe tag"),
            (0x18, "army handle"),
            (0x1F0, "army location"),
            (0x228, "country AI"),
            (0x290, "armies"),
            (0xA30, "player tag"),
            (0x428, "org"),
        ):
            pat = struct.pack("<I", imm)
            n = 0
            p = 0
            while n < 8:
                j = blob.find(pat, p)
                if j < 0:
                    break
                # only count as displacement-ish if preceded by 81/89/8b style
                print(f"  {label} @0x{start + j:08x} ctx {blob[max(0, j - 3) : j + 4].hex()}")
                n += 1
                p = j + 1

    print("\n== next static candidates after 0x01A2ED80 ==")
    for score, fn, kinds, moves in ranked:
        if fn and fn[0] == cand:
            continue
        if score < 3:
            continue
        print(
            f"  score={score} [0x{fn[0]:08x},0x{fn[1]:08x}) {kinds[:8]} moves={[hex(x) for x in moves]}"
        )


if __name__ == "__main__":
    main()
