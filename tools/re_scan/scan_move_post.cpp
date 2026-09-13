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

static uint32_t slot_rva(uint32_t vt, int index) {
    const size_t file = rva_to_file(vt);
    const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + index * 8);
    return va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
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

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || rva == 0) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8d && q[k + 2] == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d lea rax,[rip+ -> 0x%08x]\n", k, rva + k + 7 + rel);
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
            hexdump(cur > 16 ? cur - 16 : cur, 96);
            ++hits;
            if (hits >= max_hits) {
                return;
            }
        }
    }
}

static void find_str(const char* needle) {
    const size_t n = std::strlen(needle);
    std::printf("\nSTR %s\n", needle);
    int found = 0;
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, needle, n) != 0) {
            continue;
        }
        size_t begin = i;
        while (begin > 0 && buf[begin - 1] >= 32 && buf[begin - 1] < 127 && i - begin < 60) {
            --begin;
        }
        size_t end = i + n;
        while (end < buf.size() && buf[end] >= 32 && buf[end] < 127 && end - begin < 140) {
            ++end;
        }
        const uint32_t str_rva = file_to_rva(begin);
        std::printf("  rva=0x%08x %.*s\n", str_rva, static_cast<int>(end - begin),
            reinterpret_cast<const char*>(buf.data() + begin));
        int xrefs = 0;
        for (int s = 0; s < nsections; ++s) {
            if (std::memcmp(sections[s].Name, ".text", 5) != 0) {
                continue;
            }
            const size_t start = sections[s].PointerToRawData;
            const size_t last = start + sections[s].SizeOfRawData;
            for (size_t off = start; off + 7 < last; ++off) {
                if (buf[off] != 0x48 || buf[off + 1] != 0x8d) {
                    continue;
                }
                if (buf[off + 2] != 0x0d && buf[off + 2] != 0x15 && buf[off + 2] != 0x05) {
                    continue;
                }
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                if (cur + 7 + rel != str_rva && cur + 7 + rel != file_to_rva(i)) {
                    continue;
                }
                std::printf("  xref 0x%08x\n", cur);
                hexdump(cur > 32 ? cur - 32 : cur, 80);
                ++xrefs;
                if (xrefs >= 4) {
                    break;
                }
            }
        }
        ++found;
        if (found >= 6) {
            return;
        }
    }
    if (found == 0) {
        std::printf("  missing\n");
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

    const char* needles[] = {
        "post AI command",
        "PostCommand",
        "AddCommand",
        "SendCommand",
        "ExecuteCommand",
        "QueueCommand",
        "CCommand",
        "Trying to post",
        "HasGameStarted",
        "command when",
    };
    for (const char* n : needles) {
        find_str(n);
    }

    const uint32_t cmd = rtti_vtable(".?AVCCommand@@");
    const uint32_t move = rtti_vtable(".?AVCMoveCommand@@");
    std::printf("\nVT CCommand=0x%08x CMove=0x%08x\n", cmd, move);
    if (cmd != 0) {
        std::printf("CCommand slots\n");
        for (int i = 0; i < 24; ++i) {
            std::printf("  [%d] 0x%08x\n", i, slot_rva(cmd, i));
        }
    }

    walk(0x01356600, 200, "Move[10]");
    hexdump(0x01356600, 160);
    walk(0x013596b0, 40, "Move[9]");
    walk(0x024bf390, 120, "Move10_callee");
    hexdump(0x024bf390, 96);
    walk(0x0029e7b0, 80, "maybe_post");
    hexdump(0x0029e7b0, 64);
    walk(0x013376c0, 80, "after_ui_move");
    hexdump(0x013376c0, 64);
    walk(0x02565780, 80, "Move21_callee");

    find_calls_to(0x01350350, "Move_ctor", 6);
    find_calls_to(0x01356600, "Move[10]", 8);
    find_calls_to(0x024bf390, "Move10_callee", 8);
    return 0;
}
