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

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || rva == 0) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            std::printf("  +%d lea rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x91) {
            std::printf("  +%d lea rdx,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x51) {
            std::printf("  +%d lea rdx,[rcx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x87) {
            std::printf("  +%d lea rax,[rdi+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x93) {
            std::printf("  +%d lea rdx,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x53) {
            std::printf("  +%d lea rdx,[rbx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x56) {
            std::printf("  +%d lea rdx,[rsi+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x57) {
            std::printf("  +%d lea rdx,[rdi+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x41) {
            std::printf("  +%d mov rax,[rcx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x83) {
            std::printf("  +%d mov rax,[rbx+0x%x]\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x43) {
            std::printf("  +%d mov rax,[rbx+0x%x]\n", k, q[k + 3]);
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x46) {
            std::printf("  +%d mov rax,[rsi+0x%x]\n", k, q[k + 3]);
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
        if (q[k] == 0x48 && q[k + 1] == 0x89 && q[k + 2] == 0x81) {
            std::printf("  +%d mov [rcx+0x%x],rax\n", k, *reinterpret_cast<const uint32_t*>(q + k + 3));
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
        if (q[k] == 0xc3 && k > 24) {
            std::printf("  +%d ret\n", k);
            break;
        }
    }
}

static void find_calls_to(uint32_t target, const char* label, int max_hits) {
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
            hexdump(cur > 48 ? cur - 48 : cur, 112);
            walk(cur > 96 ? cur - 96 : cur, 220, "caller");
            ++hits;
            if (hits >= max_hits) {
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

    walk(0x01350350, 280, "Move_ctor");
    hexdump(0x01350350, 256);
    walk(0x01354c40, 120, "Move_ctor2");
    hexdump(0x01354c40, 96);

    walk(0x01223930, 80, "copy_cmd_28");
    hexdump(0x01223930, 64);
    walk(0x01223b70, 80, "init_cmd_28");
    hexdump(0x01223b70, 64);
    walk(0x006bca20, 64, "setname_handle");
    hexdump(0x006bca20, 48);
    walk(0x002a6c50, 64, "delete_handle");
    hexdump(0x002a6c50, 48);

    find_calls_to(0x01350350, "Move_ctor", 8);
    find_calls_to(0x0134fbe0, "Delete_ctor", 8);
    find_calls_to(0x01351200, "SetName_ctor", 6);
    find_calls_to(0x006bca20, "handle_assign", 10);
    return 0;
}
