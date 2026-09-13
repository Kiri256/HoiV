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

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    return va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
}

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || rva == 0) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8d && (q[k + 2] == 0x81 || q[k + 2] == 0x91 || q[k + 2] == 0x89)) {
            const char* r = q[k + 2] == 0x81 ? "rax" : (q[k + 2] == 0x91 ? "rdx" : "rcx");
            std::printf("  +%d lea %s,[rcx+0x%x]\n", k, r, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d lea rax,[rip+ -> 0x%08x]\n", k, rva + k + 7 + rel);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x41) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x47) {
            std::printf("  +%d mov rax,[rdi+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x43) {
            std::printf("  +%d mov rax,[rbx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x43) {
            std::printf("  +%d mov [rbx+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x47) {
            std::printf("  +%d mov [rdi+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x41) {
            std::printf("  +%d mov [rcx+0x%x],rax\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x40 && q[k + 3] == 0xf0) {
            std::printf("  +%d lea rax,[rax-0x10]\n", k);
        }
        if (q[k] == 0x4c && q[k + 1] == 0x8d && q[k + 2] == 0x68 && q[k + 3] == 0xf0) {
            std::printf("  +%d lea r13,[rax-0x10]\n", k);
        }
        if (q[k] == 0x4c && q[k + 1] == 0x8d && q[k + 2] == 0x78 && q[k + 3] == 0xf0) {
            std::printf("  +%d lea r15,[rax-0x10]\n", k);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x83 && q[k + 2] == 0xc0 && q[k + 3] == 0xf0) {
            std::printf("  +%d add rax,-0x10\n", k);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x81 && q[k + 2] == 0xc1) {
            std::printf("  +%d add rcx,0x%x\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
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
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            const uint32_t dest = rva + k + 5 + rel;
            if (dest >= text_rva && dest < text_rva + text_size) {
                std::printf("  +%d call 0x%08x\n", k, dest);
            }
        }
        if (q[k] == 0xe9) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            std::printf("  +%d jmp 0x%08x\n", k, rva + k + 5 + rel);
            if (k < 24) {
                break;
            }
        }
        if (q[k] == 0xc3 && k > 12) {
            std::printf("  +%d ret\n", k);
            break;
        }
    }
}

static void find_lea_vt(uint32_t vt_rva, const char* label) {
    std::printf("\nLEA_VT %s 0x%08x\n", label, vt_rva);
    int hits = 0;
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] != 0x48 || buf[off + 1] != 0x8d || buf[off + 2] != 0x05) {
                continue;
            }
            const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
            const uint32_t cur = file_to_rva(off);
            if (cur + 7 + rel != vt_rva) {
                continue;
            }
            std::printf("  from 0x%08x\n", cur);
            hexdump(cur > 48 ? cur - 48 : cur, 96);
            walk(cur > 80 ? cur - 80 : cur, 200, "around_vt");
            ++hits;
            if (hits >= 8) {
                return;
            }
        }
    }
}

static void find_simple_leas(uint32_t vt, const char* name, int count) {
    std::printf("\nSIMPLE_LEA %s\n", name);
    for (int i = 0; i < count; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        const size_t ff = rva_to_file(rva);
        if (ff == static_cast<size_t>(-1)) {
            continue;
        }
        const uint8_t* q = buf.data() + ff;
        if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + 3);
            if (off == 0x10 || off == 0x08 || off == 0x18 || off == 0x20 || off == 0xF8 ||
                off == 0x258 || off == 0x150 || off < 0x40) {
                std::printf("  [%d] lea [rcx+0x%x]\n", i, off);
            }
        }
        if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x41 && q[3] == 0x10 && q[4] == 0xc3) {
            std::printf("  [%d] mov rax,[rcx+0x10]\n", i);
        }
        if (q[0] == 0x8b && q[1] == 0x41 && q[2] == 0x10 && q[3] == 0xc3) {
            std::printf("  [%d] mov eax,[rcx+0x10]\n", i);
        }
    }
}

static void find_str_xref(const char* needle) {
    std::printf("\nSTR %s\n", needle);
    const size_t n = std::strlen(needle);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, needle, n) != 0) {
            continue;
        }
        const uint32_t str_rva = file_to_rva(i);
        std::printf("  str rva=0x%08x\n", str_rva);
        int hits = 0;
        for (int s = 0; s < nsections; ++s) {
            if (std::memcmp(sections[s].Name, ".text", 5) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t end = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 7 < end; ++off) {
                if (buf[off] != 0x48 || buf[off + 1] != 0x8d ||
                    (buf[off + 2] != 0x0d && buf[off + 2] != 0x15 && buf[off + 2] != 0x05)) {
                    continue;
                }
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                if (cur + 7 + rel != str_rva) {
                    continue;
                }
                std::printf("  xref 0x%08x\n", cur);
                hexdump(cur > 32 ? cur - 32 : cur, 80);
                ++hits;
                if (hits >= 6) {
                    return;
                }
            }
        }
        return;
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

    walk(0x00bab570, 160, "CArmy86_target");
    hexdump(0x00bab570, 128);
    walk(0x00bf3f70, 80, "CArmy[80]");
    hexdump(0x00bf3f70, 48);
    walk(0x00c78d20, 48, "CArmy[87]");
    hexdump(0x00c78d20, 32);
    walk(0x01352d60, 220, "Move[13] factory");
    hexdump(0x01352d60, 192);
    walk(0x0135ab70, 180, "SetName[9]");
    hexdump(0x0135ab70, 160);

    find_simple_leas(0x02933d20, "CArmy", 160);
    find_simple_leas(0x0292cce8, "CUnit", 160);

    find_lea_vt(0x0298a3c0, "CMoveCommand");
    find_lea_vt(0x0298aac8, "CSetDivisionNameCommand");
    find_lea_vt(0x0298a938, "CDeleteUnitCommand");

    find_str_xref("GetID()");
    find_str_xref("_ID.GetID()");
    return 0;
}
