#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;

static uint32_t file_to_rva(size_t off) {
    for (int i = 0; i < nsections; ++i) {
        if (off >= sections[i].PointerToRawData &&
            off < sections[i].PointerToRawData + sections[i].SizeOfRawData) {
            return sections[i].VirtualAddress + static_cast<uint32_t>(off - sections[i].PointerToRawData);
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

static void hexdump(uint32_t rva, int n) {
    const size_t f = rva_to_file(rva);
    if (f == static_cast<size_t>(-1)) {
        std::printf("bad %x\n", rva);
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
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    const char* parts[] = {"DoCountryHourlyUpdates", "GetArmies", "GetProvinceID()"};
    for (const char* part : parts) {
        const size_t n = std::strlen(part);
        std::printf("--- %s ---\n", part);
        int c = 0;
        for (size_t i = 0; i + n < buf.size(); ++i) {
            if (std::memcmp(buf.data() + i, part, n) == 0) {
                size_t b = i;
                while (b > 0 && buf[b - 1] >= 32 && buf[b - 1] < 127 && i - b < 80) {
                    --b;
                }
                size_t e = i + n;
                while (e < buf.size() && buf[e] >= 32 && buf[e] < 127 && e - b < 180) {
                    ++e;
                }
                std::printf("0x%08zx rva=0x%08x %.*s\n", i, file_to_rva(i), static_cast<int>(e - b),
                    reinterpret_cast<const char*>(buf.data() + b));
                ++c;
                if (c >= 6) {
                    break;
                }
            }
        }
    }

    hexdump(0x006c33c0, 160);

    // CProvince first 16 vtable functions hex
    return 0;
}
