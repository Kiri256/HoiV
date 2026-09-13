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

static bool looks_small_getter(uint32_t rva) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || file + 16 >= buf.size()) {
        return false;
    }
    const uint8_t* p = buf.data() + file;
    // mov eax, [rcx+imm32]; ret
    if (p[0] == 0x8b && p[1] == 0x81 && p[6] == 0xc3) {
        return true;
    }
    // mov eax, [rcx+imm8]; ret
    if (p[0] == 0x8b && p[1] == 0x41 && p[3] == 0xc3) {
        return true;
    }
    // mov rax, [rcx+imm32]; ret
    if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x81 && p[7] == 0xc3) {
        return true;
    }
    // mov rax, [rcx+imm8]; ret
    if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x41 && p[4] == 0xc3) {
        return true;
    }
    // lea rax, [rcx+imm]; ret
    if (p[0] == 0x48 && p[1] == 0x8d && (p[2] == 0x81 || p[2] == 0x41) &&
        ((p[2] == 0x81 && p[7] == 0xc3) || (p[2] == 0x41 && p[4] == 0xc3))) {
        return true;
    }
    return false;
}

static void describe_getter(uint32_t rva) {
    const uint8_t* p = buf.data() + rva_to_file(rva);
    if (p[0] == 0x8b && p[1] == 0x81) {
        const uint32_t off = *reinterpret_cast<const uint32_t*>(p + 2);
        std::printf("    mov eax,[rcx+0x%x]\n", off);
    } else if (p[0] == 0x8b && p[1] == 0x41) {
        std::printf("    mov eax,[rcx+0x%x]\n", p[2]);
    } else if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x81) {
        const uint32_t off = *reinterpret_cast<const uint32_t*>(p + 3);
        std::printf("    mov rax,[rcx+0x%x]\n", off);
    } else if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x41) {
        std::printf("    mov rax,[rcx+0x%x]\n", p[3]);
    } else if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x81) {
        const uint32_t off = *reinterpret_cast<const uint32_t*>(p + 3);
        std::printf("    lea rax,[rcx+0x%x]\n", off);
    } else if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x41) {
        std::printf("    lea rax,[rcx+0x%x]\n", p[3]);
    }
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
        if (looks_small_getter(rva)) {
            std::printf("  [%d] rva=0x%08x GETTER\n", i, rva);
            describe_getter(rva);
        }
    }
}

static void dump_after_loads() {
    const uint32_t target = 0x033048c0;
    std::printf("\nAfter singleton loads:\n");
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 16 < end; ++off) {
            if (!(buf[off] == 0x48 && buf[off + 1] == 0x8b && (buf[off + 2] & 0x07) == 0x05)) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t cur = 0;
            uint32_t rva = 0;
            for (int s = 0; s < nsections; ++s) {
                const uint32_t raw = sections[s].PointerToRawData;
                const uint32_t raw_size = sections[s].SizeOfRawData;
                if (off >= raw && off < raw + raw_size) {
                    rva = sections[s].VirtualAddress + static_cast<uint32_t>(off - raw);
                    break;
                }
            }
            (void)cur;
            if (rva + 7 + rel != target) {
                continue;
            }
            const uint8_t* n = buf.data() + off + 7;
            std::printf("  load@0x%08x next:", rva);
            for (int k = 0; k < 12; ++k) {
                std::printf(" %02x", n[k]);
            }
            std::printf("\n");
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

    dump_vt("CCurrentGameState", 0x026fb148, 120);
    dump_vt("CGameState", 0x026fb0d0, 120);
    dump_vt("CCountry", 0x027c0e80, 160);
    dump_vt("CUnit", 0x0292cce8, 160);
    dump_vt("CGameIdler", 0x02710270, 80);
    dump_after_loads();
    return 0;
}
