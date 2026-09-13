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

static void find_bytes(const uint8_t* pat, size_t n, const char* name) {
    int count = 0;
    std::printf("\nPAT %s\n", name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, pat, n) == 0) {
            uint32_t rva = 0;
            for (int s = 0; s < nsections; ++s) {
                const uint32_t raw = sections[s].PointerToRawData;
                if (i >= raw && i < raw + sections[s].SizeOfRawData) {
                    rva = sections[s].VirtualAddress + static_cast<uint32_t>(i - raw);
                    break;
                }
            }
            std::printf("  0x%08x\n", rva);
            ++count;
            if (count >= 15) {
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

    hexdump(0x0107b4f0, 96);
    hexdump(0x01a5aa50, 96);
    hexdump(0x013ca1c0, 160);

    const uint8_t get_a30[] = {0x8b, 0x81, 0x30, 0x0a, 0x00, 0x00};
    const uint8_t get_a30_rax[] = {0x8b, 0x80, 0x30, 0x0a, 0x00, 0x00};
    const uint8_t lea_a30[] = {0x48, 0x8d, 0x81, 0x30, 0x0a, 0x00, 0x00};
    find_bytes(get_a30, sizeof(get_a30), "mov eax,[rcx+0xA30]");
    find_bytes(get_a30_rax, sizeof(get_a30_rax), "mov eax,[rax+0xA30]");
    find_bytes(lea_a30, sizeof(lea_a30), "lea rax,[rcx+0xA30]");

    const char* keys[] = {"STAT_ORGANISATION", "STAT_ORGANIZATION", "current_org", "ORG_LOSS", "organisation_tooltip", "DIVISION_ORG"};
    for (const char* k : keys) {
        bool hit = false;
        const size_t n = std::strlen(k);
        for (size_t i = 0; i + n < buf.size(); ++i) {
            if (std::memcmp(buf.data() + i, k, n) == 0) {
                std::printf("KEY %s at file 0x%zx\n", k, i);
                hit = true;
                break;
            }
        }
        if (!hit) {
            std::printf("KEY missing %s\n", k);
        }
    }
    return 0;
}
