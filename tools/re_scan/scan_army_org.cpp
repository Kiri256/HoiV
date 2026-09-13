#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;
static uint64_t image_base = 0;
static uint32_t text_rva = 0;
static uint32_t text_size = 0;

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

static bool in_text(uint32_t rva) {
    return rva >= text_rva && rva < text_rva + text_size;
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

static uint32_t find_string_rva(const char* s) {
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && (i + n >= buf.size() || buf[i + n] == 0)) {
            return file_to_rva(i);
        }
    }
    return 0;
}

static void find_leas(const char* s) {
    const uint32_t target = find_string_rva(s);
    if (target == 0) {
        std::printf("NOLEA %s\n", s);
        return;
    }
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
            std::printf("  @0x%08x\n", cur);
            hexdump(cur > 48 ? cur - 48 : cur, 160);
            ++hits;
            if (hits >= 6) {
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

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    if (file == static_cast<size_t>(-1)) {
        return 0;
    }
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    if (va < image_base) {
        return 0;
    }
    return static_cast<uint32_t>(va - image_base);
}

static void scan_accesses(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nACCESS %s @0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x10 && q[k + 3] == 0x81) {
            std::printf("  +%d movss load [rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 4));
        }
        if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x11 && q[k + 3] == 0x81) {
            std::printf("  +%d movss store [rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 4));
        }
        if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x10 && (q[k + 3] & 0xC7) == 0x41) {
            std::printf("  +%d movss load [rcx+0x%x] mod=%02x\n", k, q[k + 4], q[k + 3]);
        }
        if (q[k] == 0xf3 && q[k + 1] == 0x0f && q[k + 2] == 0x11 && (q[k + 3] & 0xC7) == 0x41) {
            std::printf("  +%d movss store [rcx+0x%x] mod=%02x\n", k, q[k + 4], q[k + 3]);
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x2000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x2000) {
                std::printf("  +%d mov rax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x89) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x2000) {
                std::printf("  +%d mov rcx,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x2000) {
                std::printf("  +%d lea rax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            const uint32_t dest = rva + k + 5 + rel;
            if (in_text(dest)) {
                std::printf("  +%d call 0x%08x\n", k, dest);
            }
        }
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0xff && q[k + 1] == 0x50) {
            std::printf("  +%d call [rax+0x%x] slot=%u\n", k, q[k + 2], q[k + 2] / 8);
        }
        if (q[k] == 0x69 && q[k + 2] == 0xa0 && q[k + 3] == 0x86 && q[k + 4] == 0x01 && q[k + 5] == 0x00) {
            std::printf("  +%d imul *100000\n", k);
        }
        if (q[k] == 0xb8 && q[k + 1] == 0xa0 && q[k + 2] == 0x86 && q[k + 3] == 0x01 && q[k + 4] == 0x00) {
            std::printf("  +%d mov eax,100000\n", k);
        }
        if (q[k] == 0x68 && q[k + 1] == 0xa0 && q[k + 2] == 0x86 && q[k + 3] == 0x01 && q[k + 4] == 0x00) {
            std::printf("  +%d push 100000\n", k);
        }
        // cvtsi2ss / mulss with 100000.0f = 0x47c35000
        if (q[k] == 0x00 && q[k + 1] == 0x50 && q[k + 2] == 0xc3 && q[k + 3] == 0x47) {
            std::printf("  +%d float 100000.0 nearby\n", k);
        }
    }
}

static void dump_vt_slots(const char* name, uint32_t vt, int begin, int end) {
    if (vt == 0) {
        std::printf("\nNO VT %s\n", name);
        return;
    }
    std::printf("\nVT %s 0x%08x slots %d-%d\n", name, vt, begin, end);
    for (int i = begin; i <= end; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        std::printf("  [%d] 0x%08x", i, rva);
        const size_t ff = rva_to_file(rva);
        if (ff != static_cast<size_t>(-1)) {
            const uint8_t* q = buf.data() + ff;
            if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x81 && q[8] == 0xc3) {
                std::printf(" movss xmm0,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 4));
            } else if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x41 && q[5] == 0xc3) {
                std::printf(" movss xmm0,[rcx+0x%x]", q[4]);
            } else if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
                std::printf(" mov eax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 2));
            } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
                std::printf(" mov rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
            } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
                std::printf(" lea rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
            } else if (q[0] == 0x33 && q[1] == 0xc0 && q[2] == 0xc3) {
                std::printf(" xor eax,eax; ret");
            } else if (q[0] == 0xb0 && q[2] == 0xc3) {
                std::printf(" mov al,0x%02x; ret", q[1]);
            }
        }
        std::printf("\n");
    }
}

static void find_rtti_part(const char* part) {
    const size_t n = std::strlen(part);
    std::printf("\nRTTI %s\n", part);
    int hits = 0;
    for (size_t i = 0; i + n + 8 < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, ".?AV", 4) != 0) {
            continue;
        }
        size_t end = i;
        while (end < buf.size() && buf[end] != 0 && end - i < 90) {
            ++end;
        }
        if (std::strstr(reinterpret_cast<const char*>(buf.data() + i), part) == nullptr) {
            continue;
        }
        const uint32_t vt = rtti_vtable(reinterpret_cast<const char*>(buf.data() + i));
        std::printf("  %s vt=0x%08x\n", reinterpret_cast<const char*>(buf.data() + i), vt);
        ++hits;
        if (hits >= 30) {
            return;
        }
    }
    if (hits == 0) {
        std::printf("  none\n");
    }
}

static void find_calls_to(uint32_t target, const char* label) {
    std::printf("\nCALLS %s 0x%08x\n", label, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 5 < end; ++off) {
            if (buf[off] != 0xe8) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 1);
            const uint32_t cur = file_to_rva(off);
            if (cur + 5 + rel != target) {
                continue;
            }
            std::printf("  from 0x%08x\n", cur);
            ++hits;
            if (hits >= 12) {
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
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) == 0) {
            text_rva = sections[i].VirtualAddress;
            text_size = sections[i].Misc.VirtualSize;
        }
    }

    find_rtti_part("Organ");
    find_rtti_part("Strength");
    find_rtti_part("UnitStat");
    find_rtti_part("CFixedPoint");

    dump_vt_slots("CArmy", 0x02933d20, 0, 80);
    dump_vt_slots("CUnit", 0x0292cce8, 30, 50);

    const uint32_t army36 = slot_rva(0x02933d20, 36);
    const uint32_t army37 = slot_rva(0x02933d20, 37);
    const uint32_t army38 = slot_rva(0x02933d20, 38);
    const uint32_t army39 = slot_rva(0x02933d20, 39);
    const uint32_t army40 = slot_rva(0x02933d20, 40);
    const uint32_t army13 = slot_rva(0x02933d20, 13);
    std::printf("\nCArmy[13]=0x%08x [36]=0x%08x [37]=0x%08x [38]=0x%08x [39]=0x%08x [40]=0x%08x\n",
                army13, army36, army37, army38, army39, army40);
    scan_accesses(army13, 64, "CArmy[13]");
    scan_accesses(army36, 256, "CArmy[36]");
    scan_accesses(army37, 256, "CArmy[37]");
    scan_accesses(army38, 256, "CArmy[38]");
    scan_accesses(army39, 400, "CArmy[39]");
    scan_accesses(army40, 256, "CArmy[40]");
    hexdump(army36, 128);
    hexdump(army38, 128);
    hexdump(army39, 256);

    const uint32_t has_org = rtti_vtable(".?AVCHasUnitOrganizationTrigger@@");
    const uint32_t set_org = rtti_vtable(".?AVCSetUnitOrganization@@");
    const uint32_t add_org = rtti_vtable(".?AVCAddUnitOrganization@@");
    std::printf("\nTRIGGER vt has=0x%08x set=0x%08x add=0x%08x\n", has_org, set_org, add_org);
    dump_vt_slots("CHasUnitOrganizationTrigger", has_org, 0, 24);
    dump_vt_slots("CSetUnitOrganization", set_org, 0, 24);
    dump_vt_slots("CAddUnitOrganization", add_org, 0, 24);
    if (has_org) {
        for (int i = 0; i <= 16; ++i) {
            char label[64];
            std::snprintf(label, sizeof(label), "HasOrg[%d]", i);
            scan_accesses(slot_rva(has_org, i), 320, label);
        }
    }
    if (set_org) {
        for (int i = 0; i <= 16; ++i) {
            char label[64];
            std::snprintf(label, sizeof(label), "SetOrg[%d]", i);
            scan_accesses(slot_rva(set_org, i), 320, label);
        }
    }

    find_leas("has_unit_organization");
    find_leas("set_unit_organization");
    find_leas("add_unit_organization");
    find_leas("unit_organization");
    find_leas("%s: Invalid unit in has_unit_organization trigger");
    find_leas("%s: Invalid unit in set_unit_organization effect");

    if (army39) {
        find_calls_to(army39, "CArmy[39]");
    }
    if (army36) {
        find_calls_to(army36, "CArmy[36]");
    }
    if (army38) {
        find_calls_to(army38, "CArmy[38]");
    }
    return 0;
}
