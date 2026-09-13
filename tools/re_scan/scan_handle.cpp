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

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    return va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
}

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8b && (q[k + 2] & 0xC7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d mov r64,[rip+ -> 0x%08x]\n", k, rva + k + 7 + rel);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x02) {
            std::printf("  +%d mov eax,[rdx]\n", k);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x42) {
            std::printf("  +%d mov eax,[rdx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x4a) {
            std::printf("  +%d mov ecx,[rdx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x39 && q[k + 1] == 0x41) {
            std::printf("  +%d cmp [rcx+0x%x],eax\n", k, q[k + 2]);
        }
        if (q[k] == 0x3b && q[k + 1] == 0x41) {
            std::printf("  +%d cmp eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x3b && q[k + 1] == 0x42) {
            std::printf("  +%d cmp eax,[rdx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x39 && q[k + 1] == 0x50) {
            std::printf("  +%d cmp [rax+0x%x],edx\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x1000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x41) {
            std::printf("  +%d mov eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            std::printf("  +%d lea rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            std::printf("  +%d call 0x%08x\n", k, rva + k + 5 + rel);
        }
        if (q[k] == 0xc3 && k > 8) {
            std::printf("  +%d ret\n", k);
            if (k > 24) {
                break;
            }
        }
    }
}

static void dump_leas(uint32_t vt, const char* name, int count) {
    std::printf("\nLEA/MOV %s\n", name);
    const size_t file = rva_to_file(vt);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1)) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 2));
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
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

    walk(0x021fdd60, 240, "lookup_slot");
    hexdump(0x021fdd60, 192);
    walk(0x021ffd50, 80, "resolve");

    dump_leas(0x02933d20, "CArmy", 120);
    dump_leas(0x0292cce8, "CUnit", 120);

    hexdump(slot_rva(0x0292cce8, 13), 16);
    hexdump(0x00bf3fa0, 16);

    // Find mov [reg+0x40], r64 / two dwords near CMoveCommand create
    std::printf("\nCArmy[80-90]\n");
    for (int i = 80; i <= 95; ++i) {
        const uint32_t rva = slot_rva(0x02933d20, i);
        std::printf("  [%d] 0x%08x\n", i, rva);
    }
    return 0;
}
