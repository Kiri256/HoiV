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

static void dump(uint32_t rva, int n) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        std::printf("bad 0x%x\n", rva);
        return;
    }
    std::printf("HEX 0x%08x ", rva);
    for (int i = 0; i < n; ++i) {
        std::printf("%02x ", buf[file + i]);
    }
    std::printf("\n");
}

static void find_calls_to(uint32_t target, const char* name) {
    std::printf("\nCALL/JMP %s 0x%08x\n", name, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 5 < end; ++off) {
            if (buf[off] != 0xe8 && buf[off] != 0xe9) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 1);
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - start);
            if (rva + 5 + rel != target) {
                continue;
            }
            std::printf("  %s @0x%08x\n", buf[off] == 0xe8 ? "call" : "jmp", rva);
            ++hits;
            if (hits >= 40) {
                std::printf("  ...\n");
                return;
            }
        }
    }
    std::printf("  hits=%d\n", hits);
}

static void find_rip_load(uint32_t target, const char* name) {
    std::printf("\nRIP load %s 0x%08x\n", name, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            // rex? 48 8b 05/0d/15 disp32  or 48 83 3d disp32 00
            bool ok = false;
            int oplen = 7;
            if (buf[off] == 0x48 && buf[off + 1] == 0x8b &&
                (buf[off + 2] == 0x05 || buf[off + 2] == 0x0d || buf[off + 2] == 0x15)) {
                ok = true;
            } else if (buf[off] == 0x48 && buf[off + 1] == 0x83 && buf[off + 2] == 0x3d) {
                ok = true;
                oplen = 8;
            } else if (buf[off] == 0x48 && buf[off + 1] == 0x39 &&
                       (buf[off + 2] == 0x05 || buf[off + 2] == 0x0d || buf[off + 2] == 0x15)) {
                ok = true;
            }
            if (!ok) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - start);
            if (rva + oplen + rel != target && rva + 7 + rel != target) {
                continue;
            }
            std::printf("  @0x%08x ", rva);
            for (int k = 0; k < 12; ++k) {
                std::printf("%02x ", buf[off + k]);
            }
            std::printf("\n");
            ++hits;
            if (hits >= 30) {
                std::printf("  ...\n");
                return;
            }
        }
    }
    std::printf("  hits=%d\n", hits);
}

static void dump_vt(const char* name, uint32_t vt, int count) {
    const size_t file = rva_to_file(vt);
    std::printf("\nVTABLE %s\n", name);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base || va > image_base + 0x04000000) {
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        std::printf("  [%3d] 0x%08x ", i, rva);
        for (int k = 0; k < 16; ++k) {
            std::printf("%02x ", buf[ff + k]);
        }
        std::printf("\n");
    }
}

static uint32_t find_string(const char* s) {
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && buf[i + n] == 0) {
            return file_to_rva(i);
        }
    }
    return 0;
}

static void find_lea(uint32_t target, const char* name) {
    std::printf("\nLEA %s 0x%08x\n", name, target);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (!(buf[off] == 0x48 && buf[off + 1] == 0x8d &&
                  (buf[off + 2] == 0x0d || buf[off + 2] == 0x15 || buf[off + 2] == 0x05))) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - start);
            if (rva + 7 + rel != target) {
                continue;
            }
            std::printf("  @0x%08x next:", rva);
            for (int k = 0; k < 24; ++k) {
                std::printf(" %02x", buf[off + 7 + k]);
            }
            std::printf("\n");
            ++hits;
            if (hits >= 8) {
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
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader);

    find_calls_to(0x001dbb30, "GetPlayer");
    find_calls_to(0x00db61d0, "GetPlayerPtr lea");
    find_rip_load(0x033048c0, "CCurrentGameState singleton");

    // tiny GetInstance: mov rax,[rip+singleton]; ret
    std::printf("\nLooking for GetInstance-sized loaders\n");
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 8 < end; ++off) {
            if (!(buf[off] == 0x48 && buf[off + 1] == 0x8b && buf[off + 2] == 0x05)) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t rva = sections[i].VirtualAddress + static_cast<uint32_t>(off - start);
            if (rva + 7 + rel != 0x033048c0) {
                continue;
            }
            if (buf[off + 7] == 0xc3) {
                std::printf("  GetInstance? 0x%08x : 48 8b 05 ... c3\n", rva);
                dump(rva, 16);
            }
        }
    }

    dump_vt("CGameIdler", 0x02710270, 24);
    const uint32_t idler = find_string("Idler.GetPlayer() == Country.GetCountryTag()");
    const uint32_t tagp = find_string("Tag == CCurrentGameState::GetInstance()->GetPlayer()");
    std::printf("\nSTR idler_player=0x%x tag_player=0x%x\n", idler, tagp);
    if (idler) {
        find_lea(idler, "Idler.GetPlayer assert");
    }
    if (tagp) {
        find_lea(tagp, "GetInstance()->GetPlayer assert");
    }
    return 0;
}
