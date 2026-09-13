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

static void dump_getters(const char* name, uint32_t vt_rva, int count) {
    const size_t file = rva_to_file(vt_rva);
    std::printf("\nGETTERS %s\n", name);
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
        if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 2));
        } else if (q[0] == 0x8b && q[1] == 0x41 && q[3] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, q[2]);
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x41 && q[4] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x]\n", i, q[3]);
        } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x41 && q[4] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x]\n", i, q[3]);
        }
    }
}

int main(int argc, char** argv) {
    std::ifstream in(argv[1], std::ios::binary);
    buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    image_base = nt->OptionalHeader.ImageBase;
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    dump_getters("CProvince", 0x0294ae78, 80);
    dump_getters("CArmy", 0x02933d20, 80);
    dump_getters("CUnit", 0x0292cce8, 120);
    dump_getters("CCountry", 0x027c0e80, 200);
    hexdump(0x01697c90, 80);
    hexdump(0x01aad430, 80);
    hexdump(0x006c3380, 80);
    return 0;
}
