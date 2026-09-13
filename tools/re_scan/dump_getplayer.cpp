#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <windows.h>

int main() {
    std::ifstream in(
        "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Hearts of Iron IV\\hoi4.exe",
        std::ios::binary);
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(in)), {});
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader);
    const uint32_t rva = 0x001dbb30;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            const size_t file = sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
            std::printf("GetPlayer:");
            for (int k = 0; k < 16; ++k) {
                std::printf(" %02x", buf[file + k]);
            }
            std::printf("\n");
        }
    }
    return 0;
}
