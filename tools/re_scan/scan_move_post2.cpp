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

static void walk(uint32_t rva, int nbytes, const char* label) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        return;
    }
    std::printf("\nWALK %s 0x%08x\n", label, rva);
    const uint8_t* q = buf.data() + file;
    for (int k = 0; k + 8 < nbytes; ++k) {
        if (q[k] == 0x48 && q[k + 1] == 0x8b && (q[k + 2] & 0xC7) == 0x05) {
            const int32_t rel = *reinterpret_cast<const int32_t*>(q + k + 3);
            std::printf("  +%d mov r64,[rip+ -> 0x%08x]\n", k, rva + k + 7 + rel);
        }
        if (q[k] == 0xff && q[k + 1] == 0x50) {
            std::printf("  +%d call [rax+0x%x] slot=%u\n", k, q[k + 2], q[k + 2] / 8);
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
        if (q[k] == 0xc3 && k > 20) {
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

    hexdump(0x01350350, 16);
    hexdump(0x013596b0, 16);
    hexdump(0x01356600, 16);
    hexdump(0x021aa4d0, 16);
    hexdump(0x01223a39, 16);

    walk(0x0029e680, 280, "post_ai_cmd");
    hexdump(0x0029e680, 256);
    walk(0x013596c0, 80, "Move9_body");
    hexdump(0x00d61fc0, 128);
    hexdump(0x01a2fac0, 80);
    hexdump(0x0029e766, 48);

    const size_t file = rva_to_file(0x01223a39);
    if (file != static_cast<size_t>(-1)) {
        const int32_t rel = *reinterpret_cast<const int32_t*>(buf.data() + file + 3);
        const uint32_t vt = 0x01223a40 + rel;
        std::printf("\nhelper_vt rva=0x%08x rel=0x%x\n", vt, rel);
        hexdump(vt, 96);
        const size_t vf = rva_to_file(vt);
        if (vf != static_cast<size_t>(-1)) {
            std::printf("helper slots\n");
            for (int i = 0; i < 16; ++i) {
                const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + vf + i * 8);
                const uint32_t rva = va >= image_base ? static_cast<uint32_t>(va - image_base) : 0;
                std::printf("  [%d] 0x%08x\n", i, rva);
            }
        }
    }
    return 0;
}
