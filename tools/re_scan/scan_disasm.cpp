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

static void dump_rva(uint32_t rva, int before, int after) {
    const uint32_t start = rva - static_cast<uint32_t>(before);
    const size_t file = rva_to_file(start);
    if (file == static_cast<size_t>(-1)) {
        std::printf("bad rva 0x%x\n", rva);
        return;
    }
    const int total = before + after;
    std::printf("\n== dump rva=0x%08x ==\n", rva);
    for (int i = 0; i < total;) {
        const size_t off = file + i;
        const uint32_t cur = start + i;
        const uint8_t* p = buf.data() + off;
        if (p[0] == 0xe8 && i + 5 <= total) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
            const uint32_t dest = cur + 5 + rel;
            std::printf("  0x%08x E8 call 0x%08x\n", cur, dest);
            i += 5;
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0x8b && (p[2] & 0xc7) == 0x05 && i + 7 <= total) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 3);
            const uint32_t dest = cur + 7 + rel;
            std::printf("  0x%08x 488bxx mov r64,[rip+ -> 0x%08x] mod=%02x\n", cur, dest, p[2]);
            i += 7;
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0x8d && i + 7 <= total && (p[2] & 0xc7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 3);
            const uint32_t dest = cur + 7 + rel;
            std::printf("  0x%08x 488dxx lea r64,[rip+ -> 0x%08x] mod=%02x\n", cur, dest, p[2]);
            i += 7;
            continue;
        }
        if (p[0] == 0x4c && p[1] == 0x8b && (p[2] & 0xc7) == 0x05 && i + 7 <= total) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 3);
            const uint32_t dest = cur + 7 + rel;
            std::printf("  0x%08x 4c8bxx mov r64,[rip+ -> 0x%08x] mod=%02x\n", cur, dest, p[2]);
            i += 7;
            continue;
        }
        if (p[0] == 0x4c && p[1] == 0x8d && (p[2] & 0xc7) == 0x05 && i + 7 <= total) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(p + 3);
            const uint32_t dest = cur + 7 + rel;
            std::printf("  0x%08x 4c8dxx lea r64,[rip+ -> 0x%08x] mod=%02x\n", cur, dest, p[2]);
            i += 7;
            continue;
        }
        if (p[0] == 0xc3) {
            std::printf("  0x%08x C3 ret\n", cur);
            i += 1;
            continue;
        }
        if (p[0] == 0xcc) {
            std::printf("  0x%08x CC int3\n", cur);
            i += 1;
            continue;
        }
        std::printf("  0x%08x %02x\n", cur, p[0]);
        i += 1;
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

    const uint32_t sites[] = {
        0x0029e680,
        0x0029e7b0,
        0x0107b1ca,
        0x01a4a994,
        0x013ca298,
        0x013cceec,
        0x005356f0,
        0x0053779e,
        0x00bef935,
    };
    for (uint32_t rva : sites) {
        dump_rva(rva, 64, 320);
    }
    return 0;
}
