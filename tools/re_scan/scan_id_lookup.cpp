#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;

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
        if (q[k] == 0x48 && q[k + 1] == 0x8d && (q[k + 2] & 0xC7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d lea r64,[rip+ -> 0x%08x]\n", k, rva + k + 7 + rel);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x01) {
            std::printf("  +%d mov eax,[rcx]\n", k);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x41) {
            std::printf("  +%d mov eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x51) {
            std::printf("  +%d mov edx,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            std::printf("  +%d call 0x%08x\n", k, rva + k + 5 + rel);
        }
        if (q[k] == 0xc3 && k > 8) {
            std::printf("  +%d ret\n", k);
            break;
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
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    walk(0x0220fd4c, 220, "id_lookup");
    hexdump(0x0220fd4c, 192);
    walk(0x0135ab70, 180, "SetDivName[9]");
    walk(0x013596b0, 180, "Move[9]");
    hexdump(0x013596b0, 96);
    walk(0x01358190, 180, "CancelMove[9]");
    hexdump(0x01358190, 96);
    walk(0x00c64e60, 80, "CArmy[83]");
    hexdump(0x00c64e60, 64);
    walk(0x00bf3f70, 120, "CArmy[80]");
    hexdump(0x00bf3f70, 96);
    return 0;
}
