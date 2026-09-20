#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    std::ifstream f(argv[1], std::ios::binary);
    std::vector<unsigned char> b((std::istreambuf_iterator<char>(f)), {});
    auto* d = reinterpret_cast<IMAGE_DOS_HEADER*>(b.data());
    auto* n = reinterpret_cast<IMAGE_NT_HEADERS64*>(b.data() + d->e_lfanew);
    auto* s = reinterpret_cast<IMAGE_SECTION_HEADER*>(b.data() + d->e_lfanew + 24 + n->FileHeader.SizeOfOptionalHeader);
    int ns = n->FileHeader.NumberOfSections;
    uint64_t ib = n->OptionalHeader.ImageBase;
    auto rva = [&](size_t o) -> uint32_t {
        for (int i = 0; i < ns; ++i)
            if (o >= s[i].PointerToRawData && o < s[i].PointerToRawData + s[i].SizeOfRawData)
                return s[i].VirtualAddress + static_cast<uint32_t>(o - s[i].PointerToRawData);
        return 0;
    };
    auto off = [&](uint32_t rv) -> size_t {
        for (int i = 0; i < ns; ++i) {
            uint32_t z = s[i].Misc.VirtualSize > s[i].SizeOfRawData ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
            if (rv >= s[i].VirtualAddress && rv < s[i].VirtualAddress + z)
                return s[i].PointerToRawData + rv - s[i].VirtualAddress;
        }
        return static_cast<size_t>(-1);
    };
    const uint32_t vts[] = {0x02710c90, 0x029613d0, 0x02962938, 0x0298ab90, 0x0298ac58};
    for (uint32_t vt : vts) {
        size_t vo = off(vt);
        std::printf("VT 0x%08x\n", vt);
        if (vo == static_cast<size_t>(-1) || vo < 8) continue;
        uint64_t col_va = 0; std::memcpy(&col_va, b.data() + vo - 8, 8);
        uint32_t col_rva = col_va >= ib ? static_cast<uint32_t>(col_va - ib) : 0;
        size_t co = off(col_rva);
        if (co == static_cast<size_t>(-1)) continue;
        uint32_t td_rva = 0;
        std::memcpy(&td_rva, b.data() + co + 12, 4);
        size_t to = off(td_rva);
        std::printf("  COL=0x%08x TD=0x%08x\n", col_rva, td_rva);
        if (to != static_cast<size_t>(-1)) std::printf("  name=%s\n", reinterpret_cast<const char*>(b.data() + to + 16));
        for (int i = 0; i < 32; ++i) {
            uint64_t va = 0; std::memcpy(&va, b.data() + vo + i * 8, 8);
            std::printf("  [%d] 0x%08x\n", i, va >= ib ? static_cast<uint32_t>(va - ib) : 0);
        }
    }
}
