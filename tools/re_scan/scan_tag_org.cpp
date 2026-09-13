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

static uint32_t file_to_rva(size_t off) {
    for (int i = 0; i < nsections; ++i) {
        const uint32_t raw = sections[i].PointerToRawData;
        if (off >= raw && off < raw + sections[i].SizeOfRawData) {
            return sections[i].VirtualAddress + static_cast<uint32_t>(off - raw);
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

static void find_leas(const char* s) {
    const size_t n = std::strlen(s);
    size_t found = static_cast<size_t>(-1);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0) {
            found = i;
            break;
        }
    }
    if (found == static_cast<size_t>(-1)) {
        std::printf("NO %s\n", s);
        return;
    }
    const uint32_t target = file_to_rva(found);
    std::printf("STR rva=0x%08x %s\n", target, s);
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] == 0x48 && buf[off + 1] == 0x8d && (buf[off + 2] & 0x07) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                if (cur + 7 + rel == target) {
                    std::printf("  LEA 0x%08x\n", cur);
                    const size_t f = rva_to_file(cur > 48 ? cur - 48 : cur);
                    std::printf("  prev: ");
                    for (int k = 0; k < 48; ++k) {
                        std::printf("%02x ", buf[f + k]);
                    }
                    std::printf("\n");
                }
            }
        }
    }
}

static void find_vtable(const char* type_name) {
    size_t name_off = static_cast<size_t>(-1);
    const size_t n = std::strlen(type_name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, type_name, n) == 0 && buf[i + n] == 0) {
            name_off = i;
            break;
        }
    }
    if (name_off == static_cast<size_t>(-1)) {
        std::printf("NO TYPE %s\n", type_name);
        return;
    }
    const uint32_t td_rva = file_to_rva(name_off) - 16;
    for (size_t i = 0; i + 24 < buf.size(); i += 4) {
        const uint32_t* p = reinterpret_cast<const uint32_t*>(buf.data() + i);
        if (p[0] == 1 && p[3] == td_rva && p[1] == 0) {
            const uint32_t col_rva = file_to_rva(i);
            const uint64_t col_va = image_base + col_rva;
            for (size_t j = 0; j + 8 < buf.size(); j += 8) {
                if (*reinterpret_cast<const uint64_t*>(buf.data() + j) == col_va) {
                    const uint32_t vtable_rva = file_to_rva(j) + 8;
                    std::printf("VTABLE %s 0x%08x\n", type_name, vtable_rva);
                    const size_t vt = rva_to_file(vtable_rva);
                    for (int k = 0; k < 24; ++k) {
                        const uint64_t fn = *reinterpret_cast<const uint64_t*>(buf.data() + vt + k * 8);
                        if (fn < image_base) {
                            continue;
                        }
                        const uint32_t frva = static_cast<uint32_t>(fn - image_base);
                        const size_t ff = rva_to_file(frva);
                        if (ff == static_cast<size_t>(-1)) {
                            continue;
                        }
                        const uint8_t* q = buf.data() + ff;
                        if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
                            std::printf("  [%d] mov eax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + 2));
                        } else if (q[0] == 0x8b && q[1] == 0x41 && q[3] == 0xc3) {
                            std::printf("  [%d] mov eax,[rcx+0x%x]\n", k, q[2]);
                        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
                            std::printf("  [%d] mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + 3));
                        }
                    }
                    return;
                }
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

    find_leas("Prov.GetProvinceID() != 0");
    find_leas("Idler.GetPlayer() == Country.GetCountryTag()");
    find_leas("GetCountry().GetCountry().GetArmies().Contains( this )");
    find_leas("organisation_strength");
    find_leas("max_organisation");
    find_vtable(".?AVCProvince@@");
    find_vtable(".?AVCArmy@@");
    return 0;
}
