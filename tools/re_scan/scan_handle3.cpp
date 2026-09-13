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

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    return va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
}

static uint32_t rtti_vtable(const char* type_name) {
    const size_t n = std::strlen(type_name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, type_name, n) != 0 || buf[i + n] != 0) {
            continue;
        }
        const uint32_t td_rva = file_to_rva(i) > 16 ? file_to_rva(i) - 16 : 0;
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

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || rva == 0) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            std::printf("  +%d lea rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x91) {
            std::printf("  +%d lea rdx,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x89) {
            std::printf("  +%d lea rcx,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x41) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x51) {
            std::printf("  +%d mov rdx,[rcx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x47) {
            std::printf("  +%d mov rax,[rdi+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x43) {
            std::printf("  +%d mov rax,[rbx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x83) {
            std::printf("  +%d mov rax,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x87) {
            std::printf("  +%d mov rax,[rdi+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x41) {
            std::printf("  +%d mov [rcx+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x43) {
            std::printf("  +%d mov [rbx+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x47) {
            std::printf("  +%d mov [rdi+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x81) {
            std::printf("  +%d mov [rcx+0x%x],rax\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x8b && q[k + 1] == 0x41) {
            std::printf("  +%d mov eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x83 && q[k + 2] == 0xe8 && q[k + 3] == 0x10) {
            std::printf("  +%d sub rax,0x10\n", k);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x83 && q[k + 2] == 0xc0 && q[k + 3] == 0xf0) {
            std::printf("  +%d add rax,-0x10\n", k);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x81 && q[k + 2] == 0xc1) {
            std::printf("  +%d add rcx,0x%x\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0xff && q[k + 1] == 0x50) {
            std::printf("  +%d call [rax+0x%x] slot=%u\n", k, q[k + 2], q[k + 2] / 8);
        }
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            const uint32_t dest = rva + k + 5 + rel;
            if (dest >= text_rva && dest < text_rva + text_size) {
                std::printf("  +%d call 0x%08x\n", k, dest);
            }
        }
        if (q[k] == 0xe9 && k < 16) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            std::printf("  +%d jmp 0x%08x\n", k, rva + k + 5 + rel);
        }
        if (q[k] == 0xc3 && k > 20) {
            std::printf("  +%d ret\n", k);
            break;
        }
    }
}

static void find_calls_to(uint32_t target, const char* label, int max_hits) {
    std::printf("\nCALLS %s 0x%08x\n", label, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 5 < end; ++off) {
            if (buf[off] != 0xe8) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 1);
            const uint32_t cur = file_to_rva(off);
            if (cur + 5 + rel != target) {
                continue;
            }
            std::printf("  from 0x%08x\n", cur);
            hexdump(cur > 32 ? cur - 32 : cur, 80);
            ++hits;
            if (hits >= max_hits) {
                return;
            }
        }
    }
}

static void find_disp32(uint32_t disp, const char* label) {
    std::printf("\nDISP %s 0x%x\n", label, disp);
    int hits = 0;
    const uint8_t d0 = static_cast<uint8_t>(disp);
    const uint8_t d1 = static_cast<uint8_t>(disp >> 8);
    const uint8_t d2 = static_cast<uint8_t>(disp >> 16);
    const uint8_t d3 = static_cast<uint8_t>(disp >> 24);
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start + 3; off + 4 < end; ++off) {
            if (buf[off] != d0 || buf[off + 1] != d1 || buf[off + 2] != d2 || buf[off + 3] != d3) {
                continue;
            }
            const uint8_t modrm = buf[off - 1];
            const uint8_t opcode = buf[off - 2];
            const uint8_t rex = buf[off - 3];
            const bool lea = (opcode == 0x8d && (rex == 0x48 || rex == 0x4c || rex == 0x49));
            const bool movq = (opcode == 0x8b && (rex == 0x48 || rex == 0x4c || rex == 0x49));
            if (!lea && !movq) {
                continue;
            }
            if ((modrm & 0xC0) != 0x80) {
                continue;
            }
            std::printf("  rva=0x%08x %s modrm=%02x rex=%02x\n", file_to_rva(off - 3),
                lea ? "lea" : "mov", modrm, rex);
            ++hits;
            if (hits >= 24) {
                return;
            }
        }
    }
}

static void dump_slots(uint32_t vt, const char* name, int begin, int end) {
    std::printf("\nSLOTS %s\n", name);
    for (int i = begin; i <= end; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        std::printf("  [%d] 0x%08x\n", i, rva);
        hexdump(rva, 16);
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

    dump_slots(0x02933d20, "CArmy 13 and 80-89", 13, 13);
    dump_slots(0x02933d20, "CArmy 80-89", 80, 89);
    dump_slots(0x0292cce8, "CUnit 10-15", 10, 15);
    walk(slot_rva(0x02933d20, 13), 80, "CArmy[13]");
    walk(slot_rva(0x02933d20, 86), 40, "CArmy[86]");
    walk(slot_rva(0x02933d20, 87), 40, "CArmy[87]");
    walk(0x00c78d10, 16, "thunk86");
    walk(0x00c78d20, 16, "thunk87");

    walk(0x013596b0, 220, "Move[9]");
    hexdump(0x013596b0, 192);
    walk(0x01356600, 180, "Move[10]");
    hexdump(0x01356600, 160);

    const uint32_t set_name = rtti_vtable(".?AVCSetDivisionNameCommand@@");
    const uint32_t del_unit = rtti_vtable(".?AVCDeleteUnitCommand@@");
    const uint32_t cancel = rtti_vtable(".?AVCCancelMovementCommand@@");
    std::printf("\nVT SetDivisionName=0x%08x Delete=0x%08x Cancel=0x%08x\n", set_name, del_unit, cancel);
    if (set_name != 0) {
        walk(slot_rva(set_name, 9), 200, "SetName[9]");
        walk(slot_rva(set_name, 13), 200, "SetName[13]");
        hexdump(slot_rva(set_name, 13), 128);
    }
    if (del_unit != 0) {
        walk(slot_rva(del_unit, 9), 200, "Delete[9]");
        walk(slot_rva(del_unit, 13), 200, "Delete[13]");
        hexdump(slot_rva(del_unit, 13), 128);
    }

    find_calls_to(0x00bf3cb0, "CUnit[13] GetID-like", 12);
    find_calls_to(0x00c78d00, "copy +0x5B0", 8);
    walk(0x006f1e80, 80, "caller_5B0");
    hexdump(0x006f1e80, 64);

    find_disp32(0x258, "+0x258");
    find_disp32(0xF8, "+0xF8");
    find_disp32(0x5B0, "+0x5B0");

    return 0;
}
