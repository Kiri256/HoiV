#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

static std::vector<unsigned char> buf;
static IMAGE_SECTION_HEADER* sections = nullptr;
static int nsections = 0;

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

static void dump_func(uint32_t rva, int nbytes) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        std::printf("bad 0x%x\n", rva);
        return;
    }
    std::printf("\n== func 0x%08x ==\n", rva);
    for (int i = 0; i < nbytes;) {
        const uint8_t* p = buf.data() + file + i;
        const uint32_t cur = rva + i;
        if (p[0] == 0xc3) {
            std::printf("  0x%08x C3 ret\n", cur);
            break;
        }
        if (p[0] == 0xe8) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
            std::printf("  0x%08x E8 call 0x%08x\n", cur, cur + 5 + rel);
            i += 5;
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0x8b && (p[2] & 0xc7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 3);
            std::printf("  0x%08x 488b mov [rip] -> 0x%08x\n", cur, cur + 7 + rel);
            i += 7;
            continue;
        }
        if (p[0] == 0x8b && (p[1] & 0xc7) == 0x01) {
            std::printf("  0x%08x 8bxx mov r32,[rcx+?] %02x %02x %02x %02x\n", cur, p[1], p[2], p[3], p[4]);
            i += (p[1] & 0xc0) == 0x80 ? 6 : ((p[1] & 0xc0) == 0x40 ? 3 : 2);
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0x8b && (p[2] & 0xc7) == 0x01) {
            std::printf("  0x%08x 488b mov r64,[rcx+?] %02x %02x %02x %02x %02x\n", cur, p[2], p[3], p[4], p[5], p[6]);
            i += (p[2] & 0xc0) == 0x80 ? 7 : ((p[2] & 0xc0) == 0x40 ? 4 : 3);
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 0x01) {
            std::printf("  0x%08x 488d lea r64,[rcx+?] %02x %02x %02x %02x\n", cur, p[2], p[3], p[4], p[5]);
            i += (p[2] & 0xc0) == 0x80 ? 7 : ((p[2] & 0xc0) == 0x40 ? 4 : 3);
            continue;
        }
        std::printf("  0x%08x", cur);
        for (int k = 0; k < 8 && i + k < nbytes; ++k) {
            std::printf(" %02x", p[k]);
        }
        std::printf("\n");
        i += 1;
    }
}

static void find_leas(const char* s) {
    const size_t n = std::strlen(s);
    size_t found = static_cast<size_t>(-1);
    for (size_t i = 0; i + n < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, s, n) == 0 && buf[i + n] == 0) {
            found = i;
            break;
        }
    }
    if (found == static_cast<size_t>(-1)) {
        std::printf("NOSTR %s\n", s);
        return;
    }
    const uint32_t target = file_to_rva(found);
    std::printf("STR %s rva=0x%08x\n", s, target);
    for (int i = 0; i < nsections; ++i) {
        if (std::memcmp(sections[i].Name, ".text", 5) != 0) {
            continue;
        }
        const size_t start = sections[i].PointerToRawData;
        const size_t end = start + sections[i].SizeOfRawData;
        for (size_t off = start; off + 7 < end; ++off) {
            if (buf[off] == 0x48 && buf[off + 1] == 0x8d && (buf[off + 2] & 0x07) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + off + 3);
                const uint32_t cur = file_to_rva(off);
                if (cur + 7 + rel == target) {
                    std::printf("  LEA 0x%08x\n", cur);
                }
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
    nsections = nt->FileHeader.NumberOfSections;
    sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);

    const uint32_t funcs[] = {
        0x001eac90, 0x001ed950, 0x001d5dc0, 0x001cc880, 0x001e0340, 0x001edda0, 0x001e9f60, 0x001e1f60, 0x001ea490,
    };
    for (uint32_t f : funcs) {
        dump_func(f, 48);
    }
    find_leas("pUnit->GetLocation() shouldn't be null");
    find_leas("pUnit && pUnit->GetLocation()");
    find_leas("GetCountry().GetCountry().GetArmies().Contains( this )");
    return 0;
}
