#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
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

static const char* rva_str(uint32_t rva) {
    const size_t file = rva_to_file(rva);
    if (file == static_cast<size_t>(-1) || file >= buf.size()) {
        return "";
    }
    return reinterpret_cast<const char*>(buf.data() + file);
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
        buf.data() + dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        nt->FileHeader.SizeOfOptionalHeader);

    const uint32_t import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const uint32_t import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    std::printf("import rva=0x%x size=0x%x\n", import_rva, import_size);
    size_t desc_file = rva_to_file(import_rva);
    if (desc_file == static_cast<size_t>(-1)) {
        return 1;
    }
    for (;;) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(buf.data() + desc_file);
        if (desc->Name == 0) {
            break;
        }
        const char* dll = rva_str(desc->Name);
        const bool interesting = std::strstr(dll, "USER32") || std::strstr(dll, "user32") ||
            std::strstr(dll, "SDL") || std::strstr(dll, "sdl");
        if (interesting) {
            std::printf("DLL %s thunk=0x%x orig=0x%x\n", dll, desc->FirstThunk, desc->OriginalFirstThunk);
        }
        uint32_t oft = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t ft = desc->FirstThunk;
        for (int i = 0; i < 400; ++i) {
            const size_t oft_file = rva_to_file(oft + i * 8);
            if (oft_file == static_cast<size_t>(-1)) {
                break;
            }
            const uint64_t hint = *reinterpret_cast<const uint64_t*>(buf.data() + oft_file);
            if (hint == 0) {
                break;
            }
            if (hint & 0x8000000000000000ull) {
                continue;
            }
            const char* name = rva_str(static_cast<uint32_t>(hint) + 2);
            if (interesting || std::strstr(name, "PeekMessage") || std::strstr(name, "GetMessage") ||
                std::strstr(name, "DispatchMessage") || std::strstr(name, "SwapBuffers") ||
                std::strstr(name, "wglSwap") || std::strstr(name, "Present")) {
                std::printf("  IAT %s!%s iat_rva=0x%x\n", dll, name, ft + i * 8);
            }
        }
        desc_file += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return 0;
}
