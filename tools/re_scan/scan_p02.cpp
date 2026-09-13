#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;
static uint64_t image_base = 0;

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

static bool decode_getter(uint32_t rva, char* out, size_t out_n) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || file + 16 >= buf.size()) {
        return false;
    }
    const uint8_t* p = buf.data() + file;
    if (p[0] == 0x8b && p[1] == 0x81 && p[6] == 0xc3) {
        std::snprintf(out, out_n, "mov eax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(p + 2));
        return true;
    }
    if (p[0] == 0x8b && p[1] == 0x41 && p[3] == 0xc3) {
        std::snprintf(out, out_n, "mov eax,[rcx+0x%x]", p[2]);
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x81 && p[7] == 0xc3) {
        std::snprintf(out, out_n, "mov rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(p + 3));
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x41 && p[4] == 0xc3) {
        std::snprintf(out, out_n, "mov rax,[rcx+0x%x]", p[3]);
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x81 && p[7] == 0xc3) {
        std::snprintf(out, out_n, "lea rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(p + 3));
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x41 && p[4] == 0xc3) {
        std::snprintf(out, out_n, "lea rax,[rcx+0x%x]", p[3]);
        return true;
    }
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x81 && p[8] == 0xc3) {
        std::snprintf(out, out_n, "movss xmm0,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(p + 4));
        return true;
    }
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x10 && p[3] == 0x41 && p[5] == 0xc3) {
        std::snprintf(out, out_n, "movss xmm0,[rcx+0x%x]", p[4]);
        return true;
    }
    return false;
}

static void dump_vt(const char* name, uint32_t vt_rva, int count) {
    const size_t file = rva_to_file(vt_rva);
    std::printf("\nVTABLE %s 0x%08x\n", name, vt_rva);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base || va > image_base + 0x04000000) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        char getter[80];
        if (decode_getter(rva, getter, sizeof(getter))) {
            std::printf("  [%3d] rva=0x%08x %s\n", i, rva, getter);
        }
    }
}

static void find_lea_to_rva(uint32_t target_rva, const char* label) {
    std::printf("\nLEA to %s rva=0x%08x\n", label, target_rva);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (!(buf[off] == 0x48 && buf[off + 1] == 0x8d && (buf[off + 2] == 0x0d || buf[off + 2] == 0x15 ||
                                                              buf[off + 2] == 0x05 || buf[off + 2] == 0x1d))) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - start);
            if (rva + 7 + rel != target_rva) {
                continue;
            }
            std::printf("  lea@0x%08x next:", rva);
            for (int k = 0; k < 20 && off + 7 + k < end; ++k) {
                std::printf(" %02x", buf[off + 7 + k]);
            }
            std::printf("\n");
            ++hits;
            if (hits >= 12) {
                return;
            }
        }
    }
}

static uint32_t find_string_rva(const char* s) {
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && (i + n >= buf.size() || buf[i + n] == 0)) {
            return file_to_rva(i);
        }
    }
    return 0;
}

static void find_imm32(uint32_t imm, const char* label) {
    std::printf("\nIMM32 %s = 0x%x (first 20 in .text)\n", label, imm);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 6 < end; ++off) {
            if (*reinterpret_cast<const uint32_t*>(buf.data() + off) != imm) {
                continue;
            }
            const uint8_t prev = buf[off - 1];
            if (!(prev == 0x81 || prev == 0x05 || prev == 0x0d || prev == 0x15 || prev == 0x1d || prev == 0x25 ||
                  prev == 0x2d || prev == 0x35 || prev == 0x3d || prev == 0x85 || prev == 0x8d || prev == 0xb8 ||
                  prev == 0xb9 || prev == 0xba || prev == 0xbb || prev == 0xbc || prev == 0xbd || prev == 0xbe ||
                  prev == 0xbf)) {
                continue;
            }
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - 1 - start);
            std::printf("  0x%08x :", rva);
            for (int k = 0; k < 12; ++k) {
                std::printf(" %02x", buf[off - 1 + k]);
            }
            std::printf("\n");
            ++hits;
            if (hits >= 20) {
                return;
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
    image_base = nt->OptionalHeader.ImageBase;
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    dump_vt("CCountry", 0x027c0e80, 180);
    dump_vt("CArmy", 0x02933d20, 120);
    dump_vt("CUnit", 0x0292cce8, 200);
    dump_vt("CProvince", 0x0294ae78, 80);

    const uint32_t armies_str = find_string_rva("!GetCountry().GetCountry().GetArmies().Contains( this )");
    const uint32_t org_str = find_string_rva("organisation_strength");
    const uint32_t max_org = find_string_rva("max_organisation");
    const uint32_t get_prov = find_string_rva("Prov.GetProvinceID() != 0");
    std::printf("\nSTR armies=0x%x org=0x%x max_org=0x%x get_prov=0x%x\n", armies_str, org_str, max_org, get_prov);
    if (armies_str) {
        find_lea_to_rva(armies_str, "GetArmies assert");
    }
    if (org_str) {
        find_lea_to_rva(org_str, "organisation_strength");
    }
    if (max_org) {
        find_lea_to_rva(max_org, "max_organisation");
    }

    find_imm32(0x1F0, "unit location");
    hexdump(0x01697cb0, 64);
    return 0;
}
