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

static void classify_slot(int i, uint32_t rva) {
    const size_t ff = rva_to_file(rva);
    std::printf("  [%d] 0x%08x", i, rva);
    if (ff == static_cast<size_t>(-1)) {
        std::printf("\n");
        return;
    }
    const uint8_t* q = buf.data() + ff;
    if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
        std::printf(" mov eax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 2));
    } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
        std::printf(" mov rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
    } else if (q[0] == 0x48 && q[1] == 0x8d && q[2] == 0x81 && q[7] == 0xc3) {
        std::printf(" lea rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
    } else if (q[0] == 0x33 && q[1] == 0xc0 && q[2] == 0xc3) {
        std::printf(" xor eax,eax; ret");
    } else if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0xc1 && q[3] == 0xc3) {
        std::printf(" mov rax,rcx; ret");
    }
    std::printf("\n");
}

static void dump_vt(const char* name, uint32_t vt, int count) {
    if (vt == 0) {
        std::printf("\nNO VT %s\n", name);
        return;
    }
    std::printf("\nVT %s 0x%08x\n", name, vt);
    for (int i = 0; i < count; ++i) {
        classify_slot(i, slot_rva(vt, i));
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
        if (q[k] == 0xff && q[k + 1] == 0x90) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x800 && (off % 8) == 0) {
                std::printf("  +%d call [rax+0x%x] slot=%u\n", k, off, off / 8);
            }
        }
        if (q[k] == 0x8b && q[k + 1] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 2);
            if (off < 0x1000) {
                std::printf("  +%d mov eax,[rcx+0x%x]\n", k, off);
            }
        }
        if (q[k] == 0x48 && q[k + 1] == 0x8b && q[k + 2] == 0x81) {
            const uint32_t off = *reinterpret_cast<const uint32_t*>(q + k + 3);
            if (off < 0x1000) {
                std::printf("  +%d mov rax,[rcx+0x%x]\n", k, off);
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
            std::printf("  +%d call 0x%08x\n", k, rva + k + 5 + rel);
        }
    }
}

static void find_calls_to(uint32_t target) {
    std::printf("\nCALLS to 0x%08x\n", target);
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

static void find_rtti_unit_cmd() {
    std::printf("\nRTTI Unit+Command\n");
    int hits = 0;
    for (size_t i = 0; i + 16 < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, ".?AVC", 5) != 0) {
            continue;
        }
        const char* name = reinterpret_cast<const char*>(buf.data() + i);
        size_t end = i;
        while (end < buf.size() && buf[end] != 0 && end - i < 80) {
            ++end;
        }
        if (std::strstr(name, "Command") == nullptr) {
            continue;
        }
        if (std::strstr(name, "Unit") == nullptr && std::strstr(name, "Army") == nullptr &&
            std::strstr(name, "Division") == nullptr && std::strstr(name, "Move") == nullptr &&
            std::strstr(name, "Order") == nullptr) {
            continue;
        }
        if (std::strstr(name, "lambda") != nullptr || std::strstr(name, "Allocator") != nullptr) {
            continue;
        }
        std::printf("  %s vt=0x%08x\n", name, rtti_vtable(name));
        ++hits;
        if (hits >= 40) {
            return;
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

    find_rtti_unit_cmd();

    const uint32_t move = rtti_vtable(".?AVCMoveCommand@@");
    dump_vt("CMoveCommand", move, 36);
    for (int i = 0; i < 24; ++i) {
        char label[32];
        std::snprintf(label, sizeof(label), "Move[%d]", i);
        walk(slot_rva(move, i), 180, label);
    }

    hexdump(0x00c64eb0, 16);
    find_calls_to(0x00c64eb0);
    find_calls_to(0x00c78d00);

    dump_vt("CArmy 80-89", 0x02933d20, 0);
    std::printf("\nCArmy 80-89\n");
    for (int i = 80; i <= 89; ++i) {
        classify_slot(i, slot_rva(0x02933d20, i));
    }
    return 0;
}
