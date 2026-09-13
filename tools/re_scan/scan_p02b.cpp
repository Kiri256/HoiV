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

static void dump_fn(uint32_t rva, int n) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1)) {
        std::printf("  bad 0x%x\n", rva);
        return;
    }
    std::printf("  0x%08x ", rva);
    for (int i = 0; i < n; ++i) {
        std::printf("%02x ", buf[file + i]);
    }
    std::printf("\n");
}

static void dump_vt_heads(const char* name, uint32_t vt_rva, int count) {
    const size_t file = rva_to_file(vt_rva);
    std::printf("\nVTABLE HEADS %s\n", name);
    for (int i = 0; i < count; ++i) {
        const uint64_t va = *reinterpret_cast<const uint64_t*>(buf.data() + file + i * 8);
        if (va < image_base || va > image_base + 0x04000000) {
            std::printf("  [%3d] noncode 0x%llx\n", i, (unsigned long long)va);
            continue;
        }
        const uint32_t rva = static_cast<uint32_t>(va - image_base);
        const size_t ff = rva_to_file(rva);
        std::printf("  [%3d] rva=0x%08x ", i, rva);
        for (int k = 0; k < 16; ++k) {
            std::printf("%02x ", buf[ff + k]);
        }
        std::printf("\n");
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

    dump_vt_heads("CCountry", 0x027c0e80, 40);
    dump_vt_heads("CArmy", 0x02933d20, 30);
    dump_vt_heads("CUnit", 0x0292cce8, 40);
    dump_vt_heads("CProvince", 0x0294ae78, 20);

    std::printf("\nGetArmies assert context\n");
    dump_fn(0x00c64080, 48);
    dump_fn(0x00c64100, 48);
    dump_fn(0x00c64180, 64);
    dump_fn(0x00c641a0, 48);

    std::printf("\nCUnit +0x258 getter\n");
    dump_fn(0x00bf3cb0, 16);

    std::printf("\norg named-stat caller\n");
    dump_fn(0x01697c40, 80);
    dump_fn(0x01697cb0, 80);

    std::printf("\nCUnit vtable slot 0x1B8/8=55\n");
    const size_t unit_vt = rva_to_file(0x0292cce8);
    const uint64_t slot55 = *reinterpret_cast<const uint64_t*>(buf.data() + unit_vt + 55 * 8);
    std::printf("  slot55 va=0x%llx rva=0x%llx\n", (unsigned long long)slot55,
                (unsigned long long)(slot55 - image_base));
    if (slot55 > image_base) {
        dump_fn(static_cast<uint32_t>(slot55 - image_base), 32);
    }
    return 0;
}
