#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import load_pe, off_to_rva

EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe")


def main():
    data, ib, sections = load_pe(EXE)
    start = 0
    names = []
    while True:
        i = data.find(b".?AVC", start)
        if i < 0:
            break
        end = data.find(b"\0", i)
        if end < 0 or end - i > 200:
            start = i + 1
            continue
        name = data[i:end].decode("ascii", "replace")
        low = name.lower()
        if "command" in low and (
            "theat" in low
            or "army" in low
            or "front" in low
            or "group" in low
            or "order" in low
        ):
            rva = off_to_rva(sections, i)
            names.append((rva or 0, name))
        start = i + 1
    for rva, name in names:
        print(f"0x{rva:08x} {name}")

    print("\nutf16 contains THEAT")
    needle = "THEAT".encode("utf-16le")
    start = 0
    n = 0
    while n < 40:
        i = data.find(needle, start)
        if i < 0:
            break
        # walk back to even alignment start of string
        j = i
        while j >= 2 and data[j - 2 : j] != b"\x00\x00" and j > i - 80:
            j -= 2
        chunk = data[j : i + 40]
        try:
            s = chunk.decode("utf-16le", "replace").split("\0", 1)[0]
        except Exception:
            s = "?"
        if s.isascii() and ("THEAT" in s.upper() or "theat" in s.lower()):
            print(f"  0x{off_to_rva(sections, j) or 0:08x} {s[:80]}")
            n += 1
        start = i + 2

    print("\nascii THEATRE/theater")
    for pat in (b"THEATRE", b"THEATER", b"theatre", b"theater"):
        start = 0
        c = 0
        while c < 12:
            i = data.find(pat, start)
            if i < 0:
                break
            chunk = data[max(0, i - 16) : i + 48]
            s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {pat.decode()} 0x{off_to_rva(sections, i) or 0:08x} {s}")
            c += 1
            start = i + 1


if __name__ == "__main__":
    main()
