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

static uint32_t file_to_rva(size_t off) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t raw = sections[i].PointerToRawData;
        if (off >= raw && off < raw + sections[i].SizeOfRawData) {
            return sections[i].VirtualAddress + static_cast<uint32_t>(off - raw);
        }
    }
    return 0;
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

static void classify(uint32_t rva) {
    const size_t ff = rva_to_file(rva);
    if (ff == static_cast<size_t>(-1)) {
        std::printf(" bad");
        return;
    }
    const uint8_t* q = buf.data() + ff;
    if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
        std::printf(" mov rax,[rcx+0x%x]; ret", *reinterpret_cast<const uint32_t*>(q + 3));
        return;
    }
    if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
        std::printf(" lea rax,[rcx+0x%x]; ret", *reinterpret_cast<const uint32_t*>(q + 3));
        return;
    }
    if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
        std::printf(" mov eax,[rcx+0x%x]; ret", *reinterpret_cast<const uint32_t*>(q + 2));
        return;
    }
    if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x81 && q[8] == 0xc3) {
        std::printf(" movss [rcx+0x%x]; ret", *reinterpret_cast<const uint32_t*>(q + 4));
        return;
    }
    if (q[0] == 0x33 && q[1] == 0xc0 && q[2] == 0xc3) {
        std::printf(" xor eax,eax; ret");
        return;
    }
    std::printf(" %02x %02x %02x %02x %02x %02x %02x %02x",
                q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7]);
}

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            std::printf("  +%03d call [rax+0x%x] slot=%u\n", k, off, off / 8);
        }
        if (q[k] == 0xff && q[k + 1] == 0x50) {
            std::printf("  +%03d call [rax+0x%x] slot=%u\n", k, q[k + 2], q[k + 2] / 8);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%03d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x89) {
            std::printf("  +%03d mov rcx,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0xbb) {
            std::printf("  +%03d mov rdi,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x8b) {
            std::printf("  +%03d mov rcx,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x8f) {
            std::printf("  +%03d mov rcx,[rdi+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x87) {
            std::printf("  +%03d mov rax,[rdi+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x83) {
            std::printf("  +%03d mov rax,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%03d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x83) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%03d mov eax,[rbx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x88) {
            std::printf("  +%03d mov rcx,[rax+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x80) {
            std::printf("  +%03d mov rax,[rax+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            const uint32_t dest = rva + k + 5 + rel;
            if (dest >= text_rva && dest < text_rva + text_size) {
                std::printf("  +%03d call 0x%08x\n", k, dest);
            }
        }
        if (q[k] == 0x69 && q[k + 2] == 0xa0 && q[k + 3] == 0x86 && q[k + 4] == 0x01) {
            std::printf("  +%03d imul *100000\n", k);
        }
        if (q[k] == 0xb8 && q[k + 1] == 0x64 && q[k + 2] == 0x00 && q[k + 3] == 0x00) {
            std::printf("  +%03d mov eax,100\n", k);
        }
        if (q[k] == 0xbe && q[k + 1] == 0xa0 && q[k + 2] == 0x86 && q[k + 3] == 0x01) {
            std::printf("  +%03d mov esi,100000\n", k);
        }
        if (q[k] == 0xc3) {
            std::printf("  +%03d ret\n", k);
            if (k > 16) {
                break;
            }
        }
    }
}

static void find_disp32_loads(uint32_t disp, const char* label) {
    std::printf("\nDISP32 %s 0x%x in CArmy-ish methods\n", label, disp);
    int hits = 0;
    const uint32_t vt = 0x02933d20;
    const size_t vtfile = rva_to_file(vt);
    for (int i = 0; i < 120; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + vtfile + i * 8);
        if (va < image_base) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1) || ff + 200 >= buf.size()) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        for (int k = 0; k + 7 < 160; ++k) {
            if ((q[k] == 0x8b || q[k] == 0x89) && (q[k + 1] & 0xC7) == 0x81) {
                if (*reinterpret_cast<const uint32_t*>(q + k + 2) == disp) {
                    std::printf("  CArmy[%d]+%d 0x%08x opcode=%02x%02x\n", i, k, rva, q[k], q[k + 1]);
                    ++hits;
                    break;
                }
            }
            if (q[k] == 0x48 && (q[k + 1] == 0x8b || q[k + 1] == 0x89) && (q[k + 2] & 0xC7) == 0x81) {
                if (*reinterpret_cast<const uint32_t*>(q + k + 3) == disp) {
                    std::printf("  CArmy[%d]+%d 0x%08x rex 48%02x%02x\n", i, k, rva, q[k + 1], q[k + 2]);
                    ++hits;
                    break;
                }
            }
        }
    }
    std::printf("  hits=%d\n", hits);
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

    const uint32_t army = 0x02933d20;
    std::printf("CArmy slots 30-45\n");
    for (int i = 30; i <= 45; ++i) {
        const uint32_t rva = slot_rva(army, i);
        std::printf("  [%d] 0x%08x", i, rva);
        classify(rva);
        std::printf("\n");
    }

    for (int i = 30; i <= 42; ++i) {
        char label[32];
        std::snprintf(label, sizeof(label), "CArmy[%d]", i);
        walk(slot_rva(army, i), 220, label);
        hexdump(slot_rva(army, i), 96);
    }

    walk(0x0045aad0, 220, "HasOrg[21]");
    hexdump(0x0045aad0, 160);
    walk(0x0045a2a0, 220, "HasOrg[23]");
    hexdump(0x0045a2a0, 160);
    walk(0x0045e530, 220, "SetOrg[7]");
    hexdump(0x0045e530, 160);
    walk(0x0045cd60, 220, "SetOrg[13]");
    hexdump(0x0045cd60, 160);

    find_disp32_loads(0x138, "+0x138");
    find_disp32_loads(0x280, "+0x280");
    find_disp32_loads(0x448, "+0x448");

    const uint32_t strength = 0x02786000;  // CHasUnitStrengthTrigger from previous scan
    std::printf("\nCHasUnitStrengthTrigger slots 20-24\n");
    for (int i = 20; i <= 24; ++i) {
        const uint32_t rva = slot_rva(strength, i);
        std::printf("  [%d] 0x%08x", i, rva);
        classify(rva);
        std::printf("\n");
        if (rva) {
            char label[32];
            std::snprintf(label, sizeof(label), "HasStr[%d]", i);
            walk(rva, 180, label);
        }
    }
    return 0;
}
