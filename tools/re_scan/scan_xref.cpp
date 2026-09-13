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
static uint32_t pe = 0;

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

static bool in_text(uint32_t rva) {
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) == 0) {
            return rva >= sections[i].VirtualAddress &&
                rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        }
    }
    return false;
}

static size_t find_cstr(const char* s) {
    const size_t n = std::strlen(s);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && buf[i + n] == 0) {
            return i;
        }
    }
    return static_cast<size_t>(-1);
}

static void find_leas_to_rva(uint32_t target_rva, const char* label) {
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] == 0x48 && buf[off + 1] == 0x8d &&
                (buf[off + 2] == 0x0d || buf[off + 2] == 0x15 || buf[off + 2] == 0x1d ||
                 buf[off + 2] == 0x05 || buf[off + 2] == 0x35 || buf[off + 2] == 0x3d)) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t instr_rva = file_to_rva(off);
                const uint32_t dest = static_cast<uint32_t>(static_cast<int64_t>(instr_rva) + 7 + rel);
                if (dest == target_rva) {
                    std::printf("LEA %s instr_rva=0x%08x dest=0x%08x op=%02x\n", label, instr_rva, dest, buf[off + 2]);
                    ++hits;
                }
            }
        }
    }
    if (hits == 0) {
        std::printf("NO LEA to %s\n", label);
    }
}

static void find_vtable(const char* type_name) {
    const size_t name_off = find_cstr(type_name);
    if (name_off == static_cast<size_t>(-1)) {
        std::printf("NO TYPE %s\n", type_name);
        return;
    }
    const uint32_t name_rva = file_to_rva(name_off);
    const uint32_t td_rva = name_rva - 16;
    std::printf("TYPE %s name_rva=0x%08x td_rva=0x%08x\n", type_name, name_rva, td_rva);

    int cols = 0;
    for (size_t i = 0; i + 24 < buf.size(); i += 4) {
        const uint32_t* p = reinterpret_cast<const uint32_t*>(buf.data() + i);
        if (p[3] != td_rva) {
            continue;
        }
        if (p[0] != 1) {
            continue;
        }
        const uint32_t col_rva = file_to_rva(i);
        if (p[5] != 0 && p[5] != col_rva) {
            continue;
        }
        std::printf("  COL file=0x%08zx rva=0x%08x offset=0x%x\n", i, col_rva, p[1]);
        const uint64_t col_va = image_base + col_rva;
        int vhits = 0;
        for (size_t j = 0; j + 8 < buf.size(); j += 8) {
            const uint64_t val = *reinterpret_cast<const uint64_t*>(buf.data() + j);
            if (val == col_va) {
                const uint32_t slot_rva = file_to_rva(j);
                const uint32_t vtable_rva = slot_rva + 8;
                std::printf("  VTABLE rva=0x%08x (col slot 0x%08x)\n", vtable_rva, slot_rva);
                const size_t vt_file = rva_to_file(vtable_rva);
                if (vt_file != static_cast<size_t>(-1)) {
                    for (int k = 0; k < 8; ++k) {
                        const uint64_t fn = *reinterpret_cast<const uint64_t*>(buf.data() + vt_file + k * 8);
                        std::printf("    [%d] 0x%llx\n", k, static_cast<unsigned long long>(fn));
                    }
                }
                ++vhits;
                if (vhits >= 3) {
                    break;
                }
            }
        }
        ++cols;
        if (cols >= 3) {
            break;
        }
    }
    if (cols == 0) {
        std::printf("  NO COL\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
    pe = dos->e_lfanew;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + pe);
    image_base = nt->OptionalHeader.ImageBase;
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + pe + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    find_vtable(".?AVCCurrentGameState@@");
    find_vtable(".?AVCGameState@@");
    find_vtable(".?AVCCountry@@");
    find_vtable(".?AVCUnit@@");
    find_vtable(".?AVCGameIdler@@");

    const char* asserts[] = {
        "Tag == CCurrentGameState::GetInstance()->GetPlayer()",
        "CCurrentGameState::GetInstance()->HasGameStarted() && \"Trying to post AI command when game hasn't started\"",
        "CCurrentGameState::HasInstance() == false || _pVariables",
        "CCurrentGameState::GetInstance()->IsInUnitDelete( this )",
    };
    for (const char* s : asserts) {
        const size_t off = find_cstr(s);
        if (off == static_cast<size_t>(-1)) {
            std::printf("NOSTR start %.40s\n", s);
            continue;
        }
        const uint32_t rva = file_to_rva(off);
        std::printf("ASSERT rva=0x%08x %s\n", rva, s);
        find_leas_to_rva(rva, s);
    }
    return 0;
}
