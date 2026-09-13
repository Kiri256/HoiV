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
            std::printf("  +%d mov r64,[rip+ -> 0x%08x] mod=%02x\n", k, rva + k + 7 + rel, q[k + 2]);
        }
        if (q[k] == 0x4c && q[k + 1] == 0x8b && (q[k + 2] & 0xC7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d mov r64,[rip+ -> 0x%08x] rex4c mod=%02x\n", k, rva + k + 7 + rel, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x01) {
            std::printf("  +%d mov eax,[rcx]\n", k);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x11) {
            std::printf("  +%d mov edx,[rcx]\n", k);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x41) {
            std::printf("  +%d mov eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x51) {
            std::printf("  +%d mov edx,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x3b && q[k + 1] == 0x41) {
            std::printf("  +%d cmp eax,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0x3b && q[k + 1] == 0x51) {
            std::printf("  +%d cmp edx,[rcx+0x%x]\n", k, q[k + 2]);
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            std::printf("  +%d call 0x%08x\n", k, rva + k + 5 + rel);
        }
        if (q[k] == 0xc3 && k > 4) {
            std::printf("  +%d ret\n", k);
            if (k > 20) {
                break;
            }
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

    walk(0x021ffd50, 200, "resolve");
    hexdump(0x021ffd50, 160);
    walk(0x013596c0, 160, "Move_handle");
    hexdump(0x013596c0, 80);
    return 0;
}
