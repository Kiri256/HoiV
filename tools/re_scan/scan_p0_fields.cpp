#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;

static uint32_t file_to_rva(size_t file_off) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t raw = sections[i].PointerToRawData;
        if (file_off >= raw && file_off < raw + sections[i].SizeOfRawData) {
            return sections[i].VirtualAddress + static_cast<uint32_t>(file_off - raw);
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

static void find_exact(const char* s) {
    const size_t n = std::strlen(s);
    int count = 0;
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && (i + n >= buf.size() || buf[i + n] == 0 || buf[i + n] < 32)) {
            std::printf("STR 0x%08zx rva=0x%08x %s\n", i, file_to_rva(i), s);
            ++count;
            if (count >= 8) {
                return;
            }
        }
    }
    if (count == 0) {
        std::printf("MISSING %s\n", s);
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

    hexdump(0x001dbb30, 32);
    hexdump(0x00db61d0, 32);

    find_exact(".?AVCProvince@@");
    find_exact("GetProvinceID");
    find_exact("organisation_strength");
    find_exact(".?AVCUnitStats@@");
    find_exact("CUnit::");
    find_exact("GetCurrentOrganisation");
    find_exact("GetOrganisation");
    find_exact("_Organisation");
    find_exact("current_strength");
    find_exact("GetStrength");

    const char* parts[] = {
        "GetProvinceID()",
        "organisation_strength",
        "UNIT_MAX_ORG",
        "max_organisation",
        "current_organisation",
        "GetTrueOwnerTag",
        ".?AVCCountryTag",
    };
    for (const char* part : parts) {
        const size_t n = std::strlen(part);
        bool hit = false;
        for (size_t i = 0; i + n < buf.size(); ++i) {
            if (std::memcmp(buf.data() + i, part, n) == 0) {
                size_t begin = i;
                while (begin > 0 && buf[begin - 1] >= 32 && buf[begin - 1] < 127 && i - begin < 60) {
                    --begin;
                }
                size_t end = i + n;
                while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - begin < 140) {
                    ++end;
                }
                std::printf("HIT 0x%08zx %.*s\n", i, static_cast<int>(end - begin), reinterpret_cast<const char*>(buf.data() + begin));
                hit = true;
                break;
            }
        }
        if (!hit) {
            std::printf("MISS %s\n", part);
        }
    }
    return 0;
}
