#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    const uint32_t vt = static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 0));
    std::ifstream in(argv[1], std::ios::binary);
    std::vector<unsigned char> b((std::istreambuf_iterator<char>(in)), {});
    if (b.empty()) return 2;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(b.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(b.data() + dos->e_lfanew);
    const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        b.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader);
    const int nsec = nt->FileHeader.NumberOfSections;
    const uint64_t image_base = nt->OptionalHeader.ImageBase;
    auto to_off = [&](uint32_t rva) -> size_t {
        for (int i = 0; i < nsec; ++i) {
            const uint32_t size = sec[i].Misc.VirtualSize > sec[i].SizeOfRawData
                ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + size) {
                return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
            }
        }
        return static_cast<size_t>(-1);
    };
    auto to_rva = [&](size_t off) -> uint32_t {
        for (int i = 0; i < nsec; ++i) {
            if (off >= sec[i].PointerToRawData && off < sec[i].PointerToRawData + sec[i].SizeOfRawData) {
                return sec[i].VirtualAddress + static_cast<uint32_t>(off - sec[i].PointerToRawData);
            }
        }
        return 0;
    };
    const size_t vo = to_off(vt);
    if (vo == static_cast<size_t>(-1) || vo < 8) return 3;
    std::printf("preceding qwords:\n");
    for (int i = -32; i < 0; ++i) {
        const size_t at = vo + static_cast<ptrdiff_t>(i) * 8;
        if (at + 8 > b.size()) continue;
        uint64_t value = 0;
        std::memcpy(&value, b.data() + at, sizeof(value));
        std::printf("  [%d] 0x%016llx\n", i, static_cast<unsigned long long>(value));
    }
    uint64_t col_va = 0;
    std::memcpy(&col_va, b.data() + vo - 8, sizeof(col_va));
    const uint32_t col = col_va >= image_base ? static_cast<uint32_t>(col_va - image_base) : 0;
    const size_t co = to_off(col);
    std::printf("VT 0x%08x COL 0x%08x\n", vt, col);
    if (co == static_cast<size_t>(-1) || co + 16 > b.size()) return 4;
    uint32_t td = 0;
    std::memcpy(&td, b.data() + co + 12, sizeof(td));
    const size_t tdo = to_off(td);
    std::printf("TD 0x%08x\n", td);
    if (tdo != static_cast<size_t>(-1) && tdo + 16 < b.size()) {
        std::printf("name %s\n", reinterpret_cast<const char*>(b.data() + tdo + 16));
    }
    for (int i = -2; i < 40; ++i) {
        const size_t at = vo + static_cast<ptrdiff_t>(i) * 8;
        if (at + 8 > b.size()) continue;
        uint64_t value = 0;
        std::memcpy(&value, b.data() + at, sizeof(value));
        if (i < 0 || (value >= image_base && value < image_base + 0x4000000)) {
            std::printf("[%d] 0x%08x\n", i, value >= image_base ? static_cast<uint32_t>(value - image_base) : 0);
        }
    }
    std::printf("vtable file rva 0x%08x\n", to_rva(vo));
    return 0;
}
