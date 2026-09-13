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

static uint32_t rtti_vtable(const char* type_name) {
    const size_t n = std::strlen(type_name);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, type_name, n) != 0 || buf[i + n] != 0) {
            continue;
        }
        const uint32_t td_rva = file_to_rva(i) > 16 ? file_to_rva(i) - 16 : 0;
        for (int s = 0; s < nsections; ++s) {
            if (std::memcmp(sections[s].Name, ".rdata", 6) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t end = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 16 < end; off += 4) {
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off) != 1) {
                    continue;
                }
                if (*reinterpret_cast<const uint32_t*>(buf.data() + off + 12) != td_rva) {
                    continue;
                }
                const uint64_t col_va = image_base + file_to_rva(off);
                for (size_t vt = start; vt + 8 < end; vt += 8) {
                    if (*reinterpret_cast<const uint64_t*>(buf.data() + vt) == col_va) {
                        return file_to_rva(vt) + 8;
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
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x1000) {
                std::printf("  +%d mov rax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x1000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x2000) {
                std::printf("  +%d lea rax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x89) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x1000) {
                std::printf("  +%d mov rcx,[rcx+0x%x]\n", k, off);
            }
        }
    }
}

static void dump_class(const char* name) {
    const uint32_t vt = rtti_vtable(name);
    std::printf("\n==== %s vt=0x%08x ====\n", name, vt);
    if (vt == 0) {
        return;
    }
    for (int i = 0; i < 28; ++i) {
        const uint32_t rva = slot_rva(vt, i);
        const size_t ff = rva_to_file(rva);
        std::printf("  [%d] 0x%08x", i, rva);
        if (ff != static_cast<size_t>(-1)) {
            const uint8_t* q = buf.data() + ff;
            if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
                std::printf(" mov eax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 2));
            } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
                std::printf(" mov rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
            } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
                std::printf(" lea rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
            }
        }
        std::printf("\n");
    }
    for (int i = 8; i <= 14; ++i) {
        char label[64];
        std::snprintf(label, sizeof(label), "%s[%d]", name, i);
        walk(slot_rva(vt, i), 220, label);
        hexdump(slot_rva(vt, i), 80);
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

    dump_class(".?AVCSetDivisionNameCommand@@");
    dump_class(".?AVCSetUnitNameCommand@@");
    dump_class(".?AVCCancelMovementCommand@@");
    dump_class(".?AVCQueueUnitActionCommand@@");
    dump_class(".?AVCMassMoveCommand@@");

    hexdump(0x00c64e60, 80);
    hexdump(0x00bf3f70, 96);
    hexdump(0x00be5ba0, 64);
    hexdump(0x00c78d10, 32);
    hexdump(0x00c78d20, 48);
    return 0;
}
