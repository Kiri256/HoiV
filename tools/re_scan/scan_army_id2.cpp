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
            hexdump(cur > 64 ? cur - 64 : cur, 160);
            ++hits;
            if (hits >= 8) {
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
            if (std::memcmp(sections[s].Name, ".rdata", 6) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t end = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 16 < end; off += 4) {
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off) != 1) {
                    continue;
                }
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off + 12) != td_rva) {
                    continue;
                }
                const uint64_t col_va = image_base + file_to_rva(off);
                for (size_t vt = start; vt + 8 < end; vt += 8) {
                    if (*reinterpret_cast<const uint64_t*>(buf.data() + vt) == col_va) {
                        return file_to_rva(vt) + 8;
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
    if (vt == 0) {
        std::printf("\nNO VT %s\n", name);
        return;
    }
    std::printf("\nSIMPLE %s vt=0x%08x\n", name, vt);
    for (int i = 0; i < count; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1)) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x] @0x%08x\n", i, *reinterpret_cast<const uint32_t*>(q + 2), rva);
        } else if (q[0] == 0x8b && q[1] == 0x41 && q[3] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x] @0x%08x\n", i, q[2], rva);
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x] @0x%08x\n", i, *reinterpret_cast<const uint32_t*>(q + 3), rva);
        } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x] @0x%08x\n", i, *reinterpret_cast<const uint32_t*>(q + 3), rva);
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0xc1 && q[3] == 0xc3) {
            std::printf("  [%d] mov rax,rcx; ret @0x%08x\n", i, rva);
        }
    }
}

static void find_rtti_part(const char* part) {
    std::printf("\nRTTI %s\n", part);
    int hits = 0;
    for (size_t i = 0; i + 8 < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, ".?AVC", 5) != 0) {
            continue;
        }
        size_t end = i;
        while (end < buf.size() && buf[end] != 0 && end - i < 80) {
            ++end;
        }
        const char* name = reinterpret_cast<const char*>(buf.data() + i);
        if (std::strstr(name, part) == nullptr) {
            continue;
        }
        if (std::strstr(name, "lambda") != nullptr || std::strstr(name, "Func_impl") != nullptr ||
            std::strstr(name, "Allocator") != nullptr) {
            continue;
        }
        std::printf("  %s vt=0x%08x\n", name, rtti_vtable(name));
        ++hits;
        if (hits >= 30) {
            return;
        }
    }
}

static void walk_calls(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x800) {
                std::printf("  +%d mov rax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x2000) {
                std::printf("  +%d lea rax,[rcx+0x%x]\n", k, off);
            }
        }
    }
}

static void find_contains(const char* part) {
    const size_t n = std::strlen(part);
    std::printf("\nCONTAINS %s\n", part);
    int hits = 0;
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, part, n) != 0) {
            continue;
        }
        size_t begin = i;
        while (begin > 0 && buf[begin - 1] >= 32 && buf[begin - 1] < 127 && i - begin < 60) {
            --begin;
        }
        size_t end = i + n;
        while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - begin < 120) {
            ++end;
        }
        std::printf("  rva=0x%08x %.*s\n", file_to_rva(begin), static_cast<int>(end - begin),
                    reinterpret_cast<const char*>(buf.data() + begin));
        ++hits;
        if (hits >= 12) {
            return;
        }
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

    find_leas("You are probably not allowed to do this here");
    find_leas("GetID() == 0 ) && \"You are probably not allowed to do this here");
    find_contains("GetID()");
    find_contains("probably not allowed");

    dump_simple("CDeleteUnitCommand", rtti_vtable(".?AVCDeleteUnitCommand@@"), 40);
    dump_simple("CTransportUnitCommand", rtti_vtable(".?AVCTransportUnitCommand@@"), 40);
    dump_simple("COrderInstance", rtti_vtable(".?AVCOrderInstance@@"), 40);
    dump_simple("COrdersGroup", rtti_vtable(".?AVCOrdersGroup@@"), 40);
    dump_simple("COrdersGroupMember", rtti_vtable(".?AVCOrdersGroupMember@@"), 40);

    find_rtti_part("UnitCommand");
    find_rtti_part("Command@@");
    find_rtti_part("CMove");
    find_rtti_part("SelectUnit");
    find_rtti_part("CUnitHandle");
    find_rtti_part("CPdxID");

    hexdump(slot_rva(0x02933d20, 84), 32);
    hexdump(slot_rva(0x02933d20, 85), 32);
    hexdump(0x00c78d00, 32);

    walk_calls(slot_rva(rtti_vtable(".?AVCDeleteUnitCommand@@"), 0), 200, "Delete[0]");
    for (int i = 0; i < 16; ++i) {
        char label[32];
        std::snprintf(label, sizeof(label), "Delete[%d]", i);
        walk_calls(slot_rva(rtti_vtable(".?AVCDeleteUnitCommand@@"), i), 120, label);
    }
    return 0;
}
