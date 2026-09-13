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
            hexdump(cur > 24 ? cur - 24 : cur, 64);
            ++hits;
            if (hits >= 10) {
                return;
            }
        }
    }
}

static void dump_qword_copies(uint32_t vt, const char* name, int count) {
    std::printf("\nQWORD_COPY %s\n", name);
    const size_t file = rva_to_file(vt);
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
        // mov rax,[rcx+disp32]; mov [rdx],rax; mov rax,rdx; ret
        if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0x48 && q[8] == 0x89 &&
            q[9] == 0x02 && q[10] == 0x48 && q[11] == 0x8b && q[12] == 0xc2 && q[13] == 0xc3) {
            std::printf("  [%d] copy [rcx+0x%x] @0x%08x\n", i, *reinterpret_cast<const uint32_t*>(q + 3), rva);
        }
        // lea rax,[rcx+disp]; ret
        if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
            std::printf("  [%d] lea [rcx+0x%x] @0x%08x\n", i, *reinterpret_cast<const uint32_t*>(q + 3), rva);
        }
        // search first 80 bytes for copy of two dwords
        for (int k = 0; k + 14 < 80; ++k) {
            if (q[k] == 0x8b && q[k + 1] == 0x81 && q[k + 6] == 0x89 && q[k + 7] == 0x02 &&
                q[k + 8] == 0x8b && q[k + 9] == 0x81) {
                const uint32_t a = *reinterpret_cast<const uint32_t*>(q + k + 2);
                const uint32_t b = *reinterpret_cast<const uint32_t*>(q + k + 10);
                if (b == a + 4 && a < 0x1000) {
                    std::printf("  [%d]+%d dword pair [rcx+0x%x]/+4 @0x%08x\n", i, k, a, rva);
                }
            }
        }
    }
}

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x1000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x89 && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x1000) {
                std::printf("  +%d mov [rcx+0x%x],eax\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x81) {
            std::printf("  +%d mov [rcx+0x%x],rax\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 1);
            const uint32_t dest = rva + k + 5 + rel;
            if (dest >= text_rva && dest < text_rva + text_size) {
                std::printf("  +%d call 0x%08x\n", k, dest);
            }
        }
        if (q[k] == 0xc3 && k > 16) {
            std::printf("  +%d ret\n", k);
            break;
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

    dump_qword_copies(0x02933d20, "CArmy", 120);
    dump_qword_copies(0x0292cce8, "CUnit", 120);

    find_calls_to(0x021ffd50, "resolve");
    find_calls_to(0x021fdd60, "hash_lookup");

    walk(0x021fde10, 200, "lookup_twin");
    hexdump(0x021fde10, 128);
    hexdump(0x00c78d00, 16);
    hexdump(slot_rva(0x0292cce8, 13), 16);

    // CMoveCommand slot 13 looked like a factory; dump more of 0x01352d60
    walk(0x01352d60, 220, "Move[13]");
    hexdump(0x01352d60, 128);
    walk(0x013596c0, 200, "Move_handle_fill");
    return 0;
}
