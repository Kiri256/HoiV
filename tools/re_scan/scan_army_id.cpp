#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;
static uint64_t image_base = 0;
static uint32_t text_rva = 0;
static uint32_t text_size = 0;

static uint32_t file_to_rva(size_t off) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t raw = sections[i].PointerToRawData;
        if (off >= raw && off < raw + sections[i].SizeOfRawData) {
            return sections[i].VirtualAddress + static_cast<uint32_t>(off - raw);
        }
    }
    return 0;
}

static size_t rva_to_file(uint32_t rva) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t va = sections[i].VirtualAddress;
        const uint32_t vsize = (sections[i].Misc.VirtualSize > sections[i].SizeOfRawData)
            ? sections[i].Misc.VirtualSize
            : sections[i].SizeOfRawData;
        if (rva >= va && rva < va + vsize) {
            return sections[i].PointerToRawData + (rva - va);
        }
    }
    return static_cast<size_t>(-1);
}

static void hexdump(uint32_t rva, int nbytes) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        std::printf("bad 0x%x\n", rva);
        return;
    }
    std::printf("\nHEX 0x%08x\n", rva);
    for (int i = 0; i < nbytes; i += 16) {
        std::printf("%08x  ", rva + i);
        for (int j = 0; j < 16 && i + j < nbytes; ++j) {
            std::printf("%02x ", buf[file + i + j]);
        }
        std::printf("\n");
    }
}

static uint32_t find_string_rva(const char* s) {
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && (i + n >= buf.size() || buf[i + n] == 0)) {
            return file_to_rva(i);
        }
    }
    return 0;
}

static void find_contains(const char* part) {
    const size_t n = std::strlen(part);
    std::printf("\nCONTAINS %s\n", part);
    int hits = 0;
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, part, n) != 0) {
            continue;
        }
        if (i > 0 && buf[i - 1] >= 32 && buf[i - 1] < 127 && buf[i - 1] != '.') {
            continue;
        }
        size_t end = i + n;
        while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - i < 80) {
            ++end;
        }
        std::printf("  rva=0x%08x %.*s\n", file_to_rva(i), static_cast<int>(end - i),
                    reinterpret_cast<const char*>(buf.data() + i));
        ++hits;
        if (hits >= 16) {
            return;
        }
    }
    if (hits == 0) {
        std::printf("  none\n");
    }
}

static void find_leas(const char* s) {
    const uint32_t target = find_string_rva(s);
    if (target == 0) {
        std::printf("NOLEA %s\n", s);
        return;
    }
    std::printf("\nLEA %s rva=0x%08x\n", s, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] != 0x48 || buf[off + 1] != 0x8d || (buf[off + 2] & 0x07) != 0x05) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t cur = file_to_rva(off);
            if (cur + 7 + rel != target) {
                continue;
            }
            std::printf("  @0x%08x\n", cur);
            hexdump(cur > 32 ? cur - 32 : cur, 96);
            ++hits;
            if (hits >= 6) {
                return;
            }
        }
    }
}

static uint32_t rtti_vtable(const char* type_name) {
    const size_t n = std::strlen(type_name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, type_name, n) != 0 || buf[i + n] != 0) {
            continue;
        }
        const uint32_t name_rva = file_to_rva(i);
        const uint32_t td_rva = name_rva > 16 ? name_rva - 16 : 0;
        for (int s = 0; s < nsections; ++s) {
            if (std::memcmp(sections[s].Name, ".rdata", 6) != 0 &&
                std::memcmp(sections[s].Name, ".data", 5) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t end = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 16 < end; off += 4) {
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off + 12) != td_rva) {
                    continue;
                }
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off) != 1) {
                    continue;
                }
                const uint64_t col_va = image_base + file_to_rva(off);
                for (int t = 0; t < nsections; ++t) {
                    if (std::memcmp(sections[t].Name, ".rdata", 6) != 0) {
                        continue;
                    }
                    const size_t tstart = sections[t].PointerToRawData;
                    const size_t tend = tstart + sections[t].SizeOfRawData;
                    for (size_t vt = tstart; vt + 8 < tend; vt += 8) {
                        if (*reinterpret_cast<const uint64_t*>(buf.data() + vt) == col_va) {
                            return file_to_rva(vt) + 8;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    if (file == static_cast<size_t>(-1)) {
        return 0;
    }
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    return va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
}

static void dump_simple(const char* name, uint32_t vt, int count) {
    std::printf("\nSIMPLE %s\n", name);
    for (int i = 0; i < count; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1)) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 2));
        } else if (q[0] == 0x8b && q[1] == 0x41 && q[3] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, q[2]);
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x0f && q[1] == 0xb7 && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] movzx eax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        }
    }
}

static void find_rtti_part(const char* part) {
    std::printf("\nRTTI %s\n", part);
    int hits = 0;
    for (size_t i = 0; i + 8 < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, ".?AV", 4) != 0) {
            continue;
        }
        size_t end = i;
        while (end < buf.size() && buf[end] != 0 && end - i < 90) {
            ++end;
        }
        if (std::strstr(reinterpret_cast<const char*>(buf.data() + i), part) == nullptr) {
            continue;
        }
        std::printf("  %s vt=0x%08x\n", reinterpret_cast<const char*>(buf.data() + i),
                    rtti_vtable(reinterpret_cast<const char*>(buf.data() + i)));
        ++hits;
        if (hits >= 24) {
            return;
        }
    }
    if (hits == 0) {
        std::printf("  none\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    image_base = nt->OptionalHeader.ImageBase;
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) == 0) {
            text_rva = sections[i].VirtualAddress;
            text_size = sections[i].Misc.VirtualSize;
        }
    }

    dump_simple("CArmy", 0x02933d20, 90);
    dump_simple("CUnit", 0x0292cce8, 90);

    std::printf("\nCArmy slots 0-20\n");
    for (int i = 0; i <= 20; ++i) {
        const uint32_t rva = slot_rva(0x02933d20, i);
        std::printf("  [%d] 0x%08x\n", i, rva);
        hexdump(rva, 48);
    }

    find_rtti_part("UnitID");
    find_rtti_part("ArmyID");
    find_rtti_part("CToken");
    find_rtti_part("MoveOrder");
    find_rtti_part("COrder");
    find_rtti_part("GiveOrder");
    find_rtti_part("UnitCommand");

    const char* names[] = {
        "GetUnitID",
        "unit_id",
        "unique_id",
        "GetUniqueID",
        "CUnitID",
        "Invalid unit",
        "division_id",
        "GetID()",
        "pUnit->GetID",
        "GetArmyID",
    };
    for (const char* name : names) {
        find_contains(name);
    }

    find_leas("unit_id");
    find_leas("GetUnitID");
    find_leas("%s: Invalid unit in has_unit_organization trigger");
    return 0;
}
