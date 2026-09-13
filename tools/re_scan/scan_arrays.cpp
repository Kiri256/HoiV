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

static void hexdump(uint32_t rva, int n) {
    const size_t f = rva_to_file(rva);
    if (f == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nHEX 0x%08x\n", rva);
    for (int i = 0; i < n; i += 16) {
        std::printf("%08x  ", rva + i);
        for (int j = 0; j < 16 && i + j < n; ++j) {
            std::printf("%02x ", buf[f + i + j]);
        }
        std::printf("\n");
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

    const char* parts[] = {
        "CPdxArray@PEAVCUnit",
        "CPdxArray@PEAVCArmy",
        "CPdxArray@PEAVCProvince",
        "CPdxArray@VCCountryTag",
        "PEAVCUnit@@",
        "PEAVCArmy@@",
    };
    for (const char* part : parts) {
        std::printf("--- %s ---\n", part);
        const size_t n = std::strlen(part);
        int count = 0;
        for (size_t i = 0; i + n < buf.size(); ++i) {
            if (std::memcmp(buf.data() + i, part, n) == 0) {
                size_t begin = i;
                while (begin > 0 && buf[begin - 1] >= 32 && buf[begin - 1] < 127 && i - begin < 70) {
                    --begin;
                }
                size_t end = i + n;
                while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - begin < 160) {
                    ++end;
                }
                std::printf("0x%08zx %.*s\n", i, static_cast<int>(end - begin), reinterpret_cast<const char*>(buf.data() + begin));
                ++count;
                if (count >= 8) {
                    break;
                }
            }
        }
        if (count == 0) {
            std::printf("MISSING\n");
        }
    }

    const size_t vt = rva_to_file(0x027c0e80);
    const uint64_t fnva = *reinterpret_cast<const uint64_t*>(buf.data() + vt + 20 * 8);
    const uint32_t fnrva = static_cast<uint32_t>(fnva - image_base);
    std::printf("CCountry vtbl[20] rva=0x%08x\n", fnrva);
    hexdump(fnrva, 32);

    hexdump(0x006c33f0, 64);
    return 0;
}
