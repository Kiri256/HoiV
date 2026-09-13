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
        const uint32_t raw_size = sections[i].SizeOfRawData;
        if (file_off >= raw && file_off < raw + raw_size) {
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

static const IMAGE_SECTION_HEADER* section_for_rva(uint32_t rva) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t va = sections[i].VirtualAddress;
        if (rva >= va && rva < va + sections[i].Misc.VirtualSize) {
            return &sections[i];
        }
    }
    return nullptr;
}

static void find_rip_to(uint32_t target) {
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 8 < end; ++off) {
            if (buf[off] == 0x48 && buf[off + 1] == 0x8b && (buf[off + 2] & 0x07) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                const uint32_t dest = cur + 7 + rel;
                if (dest == target) {
                    const uint8_t* next = buf.data() + off + 7;
                    uint32_t call_dest = 0;
                    if (next[0] == 0xe8) {
                        const int32_t crel = *reinterpret_cast<const int32_t*>(next + 1);
                        call_dest = cur + 7 + 5 + crel;
                    }
                    std::printf("LOAD 0x%08x mod=%02x next=%02x call=0x%08x\n", cur, buf[off + 2], next[0], call_dest);
                    ++hits;
                    if (hits >= 40) {
                        return;
                    }
                }
            }
            if (buf[off] == 0x48 && buf[off + 1] == 0x83 && buf[off + 2] == 0x3d && off + 8 < end) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                const uint32_t dest = cur + 8 + rel;
                if (dest == target) {
                    std::printf("CMP0 0x%08x\n", cur);
                    ++hits;
                }
            }
        }
    }
    std::printf("hits reported (cap 40)\n");
}

static void find_contains(const char* part) {
    const size_t n = std::strlen(part);
    int count = 0;
    std::printf("--- %s ---\n", part);
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
            if (count >= 15) {
                break;
            }
        }
    }
    if (count == 0) {
        std::printf("MISSING\n");
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

    const uint32_t singleton = 0x033048c0;
    const auto* sec = section_for_rva(singleton);
    if (sec != nullptr) {
        char name[9] {};
        std::memcpy(name, sec->Name, 8);
        std::printf("singleton 0x%08x section=%s chars=0x%x\n", singleton, name, sec->Characteristics);
    }
    find_rip_to(singleton);

    const char* parts[] = {
        "current_organisation",
        "organisation=",
        "org_loss",
        "GetMaxOrganisation",
        "division_organisation",
        "UNIT_ORGANISATION",
        "location=",
        "GetLocation",
        "GetProvince",
        "CPdxArray",
        "GetUnits(",
        "GetArmies",
        "num_divisions",
        "source\\units",
        "source/units",
        "land_unit",
    };
    for (const char* part : parts) {
        find_contains(part);
    }
    return 0;
}
