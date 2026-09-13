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

static void find_string(const char* s) {
    const size_t n = std::strlen(s);
    int hits = 0;
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) != 0) {
            continue;
        }
        if (i + n < buf.size() && buf[i + n] != 0 && buf[i + n] >= 32) {
            continue;
        }
        std::printf("STR rva=0x%08x %s\n", file_to_rva(i), s);
        ++hits;
        if (hits >= 4) {
            return;
        }
    }
    if (hits == 0) {
        std::printf("MISSING %s\n", s);
    }
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
        std::printf("NOLEA %s\n", s);
        return;
    }
    const uint32_t target = file_to_rva(found);
    std::printf("\nLEA %s rva=0x%08x\n", s, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] != 0x48 || buf[off + 1] != 0x8d || (buf[off + 2] & 0x07) != 0x05) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t cur = file_to_rva(off);
            if (cur + 7 + rel != target) {
                continue;
            }
            std::printf("  @0x%08x prev:", cur);
            const size_t back = off >= 24 ? off - 24 : off;
            for (size_t k = back; k < off + 16 && k < end; ++k) {
                std::printf(" %02x", buf[k]);
            }
            std::printf("\n");
            ++hits;
            if (hits >= 8) {
                return;
            }
        }
    }
}

static uint32_t rtti_vtable(const char* type_name) {
    const size_t n = std::strlen(type_name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, type_name, n) != 0 || buf[i + n] != 0) {
            continue;
        }
        const uint32_t name_rva = file_to_rva(i);
        const uint32_t td_rva = name_rva > 16 ? name_rva - 16 : 0;
        for (int s = 0; s < nsections; ++s) {
            if (std::memcmp(sections[s].Name, ".rdata", 6) != 0 &&
                std::memcmp(sections[s].Name, ".data", 5) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t end = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 16 < end; off += 4) {
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off + 12) != td_rva) {
                    continue;
                }
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off) != 1) {
                    continue;
                }
                const uint32_t col_rva = file_to_rva(off);
                const uint64_t col_va = image_base + col_rva;
                for (int t = 0; t < nsections; ++t) {
                    if (std::memcmp(sections[t].Name, ".rdata", 6) != 0) {
                        continue;
                    }
                    const size_t tstart = sections[t].PointerToRawData;
                    const size_t tend = tstart + sections[t].SizeOfRawData;
                    for (size_t vt = tstart; vt + 8 < tend; vt += 8) {
                        if (*reinterpret_cast<const uint64_t*>(buf.data() + vt) == col_va) {
                            return file_to_rva(vt) + 8;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static void dump_getters(const char* name, uint32_t vt_rva, int count) {
    if (vt_rva == 0) {
        std::printf("\nNO VT %s\n", name);
        return;
    }
    const size_t file = rva_to_file(vt_rva);
    std::printf("\nGETTERS %s vt=0x%08x\n", name, vt_rva);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1) || ff + 16 >= buf.size()) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x81 && q[8] == 0xc3) {
            std::printf("  [%d] movss xmm0,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 4));
        } else if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x41 && q[5] == 0xc3) {
            std::printf("  [%d] movss xmm0,[rcx+0x%x]\n", i, q[4]);
        } else if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 2));
        } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea rax,[rcx+0x%x]\n", i, *reinterpret_cast<const uint32_t*>(q + 3));
        }
    }
}

static void dump_slot_fields(const char* name, uint32_t vt_rva, int count) {
    if (vt_rva == 0) {
        return;
    }
    const size_t file = rva_to_file(vt_rva);
    std::printf("\nFIELDS %s\n", name);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1) || ff + 96 >= buf.size()) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0x33 && q[1] == 0xc0 && q[2] == 0xc3) {
            continue;
        }
        if (q[0] == 0xc2) {
            continue;
        }
        if (q[0] == 0x32 && q[1] == 0xc0 && q[2] == 0xc3) {
            continue;
        }
        for (int k = 0; k + 8 < 80; ++k) {
            if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x10 && q[k + 3] == 0x81) {
                std::printf("  [%d]+%d movss [rcx+0x%x]\n", i, k, *reinterpret_cast<const uint32_t*>(q + k + 4));
            }
            if (q[k] == 0x8b && q[k + 1] == 0x81) {
                const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
                if (off < 0x2000) {
                    std::printf("  [%d]+%d mov eax,[rcx+0x%x]\n", i, k, off);
                }
            }
        }
    }
}

static void find_contains(const char* part) {
    const size_t n = std::strlen(part);
    int hits = 0;
    std::printf("\nCONTAINS %s\n", part);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, part, n) != 0) {
            continue;
        }
        size_t begin = i;
        while (begin > 0 && buf[begin - 1] >= 32 && buf[begin - 1] < 127 && i - begin < 70) {
            --begin;
        }
        size_t end = i + n;
        while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - begin < 140) {
            ++end;
        }
        std::printf("  rva=0x%08x %.*s\n", file_to_rva(begin), static_cast<int>(end - begin),
                    reinterpret_cast<const char*>(buf.data() + begin));
        ++hits;
        if (hits >= 10) {
            return;
        }
    }
    if (hits == 0) {
        std::printf("  none\n");
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

    const char* names[] = {
        ".?AVCUnitStats@@",
        ".?AVCLandUnit@@",
        ".?AVCCombatUnit@@",
        ".?AVCDivision@@",
        ".?AVCLandDivision@@",
        "GetCurrentOrganisation",
        "GetOrganisation",
        "current_organisation",
        "organisation_strength",
        "max_organisation",
        "STAT_ORGANISATION",
    };
    for (const char* name : names) {
        find_string(name);
    }

    find_leas("organisation_strength");
    find_leas("max_organisation");
    find_leas("current_organisation");
    find_leas("STAT_ORGANISATION");

    dump_getters("CUnitStats", rtti_vtable(".?AVCUnitStats@@"), 80);
    dump_getters("CLandUnit", rtti_vtable(".?AVCLandUnit@@"), 80);
    dump_getters("CUnit", 0x0292cce8, 160);
    dump_slot_fields("CUnit", 0x0292cce8, 160);
    dump_slot_fields("CArmy", 0x02933d20, 80);
    std::printf("\nCArmy movss in first 192 bytes\n");
    {
        const size_t file = rva_to_file(0x02933d20);
        for (int i = 0; i < 90; ++i) {
            const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
            if (va < image_base) {
                continue;
            }
            const uint32_t rva = static_cast<uint32_t>(va - image_base);
            const size_t ff = rva_to_file(rva);
            if (ff == static_cast<size_t>(-1) || ff + 200 >= buf.size()) {
                continue;
            }
            const uint8_t* q = buf.data() + ff;
            for (int k = 0; k + 8 < 192; ++k) {
                if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x10 && q[k + 3] == 0x81) {
                    std::printf("  [%d]+%d load [rcx+0x%x]\n", i, k, *reinterpret_cast<const uint32_t*>(q + k + 4));
                }
                if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x11 && q[k + 3] == 0x81) {
                    std::printf("  [%d]+%d store [rcx+0x%x]\n", i, k, *reinterpret_cast<const uint32_t*>(q + k + 4));
                }
            }
        }
    }
    find_contains("organisation");
    find_contains("Organization");
    find_contains("unit_id");
    find_contains("GetUnitID");
    find_contains("unique_id");
    hexdump(0x01697c40, 200);
    hexdump(0x01697cb0, 96);
    hexdump(0x00bf3cb0, 16);

    const size_t unit_vt = rva_to_file(0x0292cce8);
    const int id_slots[] = {46, 57, 79};
    std::printf("\nCUnit id-like slots\n");
    for (int s : id_slots) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + unit_vt + s * 8);
        if (va < image_base) {
            continue;
        }
        hexdump(static_cast<uint32_t>(va - image_base), 64);
    }

    const uint32_t has_org = rtti_vtable(".?AVCHasUnitOrganizationTrigger@@");
    const uint32_t set_org = rtti_vtable(".?AVCSetUnitOrganization@@");
    dump_getters("CHasUnitOrganizationTrigger", has_org, 40);
    dump_slot_fields("CHasUnitOrganizationTrigger", has_org, 40);
    dump_getters("CSetUnitOrganization", set_org, 40);
    dump_slot_fields("CSetUnitOrganization", set_org, 40);
    find_contains("HasUnitOrganization");
    find_contains("SetUnitOrganization");
    find_contains("unit_organization");

    std::printf("\nCArmy slot 39 and nearby\n");
    const size_t army_vt = rva_to_file(0x02933d20);
    for (int i = 35; i <= 45; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + army_vt + i * 8);
        if (va < image_base) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        std::printf("  [%d] rva=0x%08x\n", i, rva);
        hexdump(rva, 96);
    }

    find_leas("%s: Invalid unit in has_unit_organization trigger");
    hexdump(0x0045a2a0, 256);
    hexdump(0x0045aad0, 192);
    hexdump(0x0045a480, 128);
    return 0;
}
