#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>

static const uint8_t* data = nullptr;
static size_t g_size = 0;
static uint32_t g_pe = 0;
static uint64_t g_image_base = 0;
static IMAGE_SECTION_HEADER* g_sections = nullptr;
static int g_nsections = 0;

static uint32_t file_to_rva(size_t file_off) {
    for (int i = 0; i < g_nsections; ++i) {
        const uint32_t raw = g_sections[i].PointerToRawData;
        const uint32_t raw_size = g_sections[i].SizeOfRawData;
        if (file_off >= raw && file_off < raw + raw_size) {
            return g_sections[i].VirtualAddress + static_cast<uint32_t>(file_off - raw);
        }
    }
    return 0;
}

static size_t rva_to_file(uint32_t rva) {
    for (int i = 0; i < g_nsections; ++i) {
        const uint32_t va = g_sections[i].VirtualAddress;
        const uint32_t vsize = g_sections[i].Misc.VirtualSize;
        if (rva >= va && rva < va + vsize) {
            return g_sections[i].PointerToRawData + (rva - va);
        }
    }
    return static_cast<size_t>(-1);
}

static void find_exact(const char* name) {
    const size_t n = std::strlen(name);
    int count = 0;
    for (size_t i = 0; i + n < g_size; ++i) {
        if (std::memcmp(data + i, name, n) == 0 && (i + n >= g_size || data[i + n] == 0)) {
            std::printf("STR 0x%08zx rva=0x%08x %s\n", i, file_to_rva(i), name);
            ++count;
            if (count >= 8) {
                break;
            }
        }
    }
    if (count == 0) {
        std::printf("MISSING %s\n", name);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    data = buf.data();
    g_size = buf.size();

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    g_pe = dos->e_lfanew;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + g_pe);
    g_image_base = nt->OptionalHeader.ImageBase;
    g_nsections = nt->FileHeader.NumberOfSections;
    g_sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + g_pe + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    std::printf("image_base=0x%llx sections=%d\n", static_cast<unsigned long long>(g_image_base), g_nsections);

    const char* names[] = {
        ".?AVCGameState@@",
        ".?AVCCurrentGameState@@",
        ".?AVCCountry@@",
        ".?AVCCountryTag@@",
        ".?AVCUnit@@",
        ".?AVCArmy@@",
        ".?AVCDivision@@",
        ".?AVCLandUnit@@",
        ".?AVCLandDivision@@",
        ".?AVCTheater@@",
        ".?AVCGameIdler@@",
        "CCurrentGameState::GetInstance",
        "GetPlayer()",
        "GetTrueOwnerTag",
        "GetOrganisation",
        "GetOrganization",
        "organisation.cpp",
        "division.cpp",
        "unit.cpp",
        "gamestate.cpp",
        "country.cpp",
    };
    for (const char* name : names) {
        find_exact(name);
    }

    // Broader contains search for source paths
    const char* parts[] = {
        "source\\military\\",
        "source\\game\\",
        "CLandDivision",
        "CCurrentGameState",
        "GetCurrentStrength",
        "GetOrg",
    };
    for (const char* part : parts) {
        std::printf("--- contains %s ---\n", part);
        const size_t n = std::strlen(part);
        int count = 0;
        for (size_t i = 0; i + n < g_size; ++i) {
            if (std::memcmp(data + i, part, n) == 0) {
                size_t begin = i;
                while (begin > 0 && data[begin - 1] >= 32 && data[begin - 1] < 127 && i - begin < 90) {
                    --begin;
                }
                size_t end = i + n;
                while (end < g_size && data[end] >= 32 && data[end] < 127 && end - begin < 180) {
                    ++end;
                }
                std::printf("0x%08zx %.*s\n", i, static_cast<int>(end - begin), reinterpret_cast<const char*>(data + begin));
                ++count;
                if (count >= 12) {
                    break;
                }
            }
        }
        if (count == 0) {
            std::printf("MISSING\n");
        }
    }
    return 0;
}
