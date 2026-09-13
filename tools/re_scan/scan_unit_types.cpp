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

static uint32_t vtable_for_td(uint32_t td_rva) {
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
    return 0;
}

static void describe(uint32_t rva) {
    const size_t ff = rva_to_file(rva);
    if (ff == static_cast<size_t>(-1)) {
        std::printf(" bad");
        return;
    }
    const uint8_t* q = buf.data() + ff;
    if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x81 && q[8] == 0xc3) {
        std::printf(" movss [rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 4));
        return;
    }
    if (q[0] == 0xf3 && q[1] == 0x0f && q[2] == 0x10 && q[3] == 0x41 && q[5] == 0xc3) {
        std::printf(" movss [rcx+0x%x]", q[4]);
        return;
    }
    if (q[0] == 0x8b && q[1] == 0x81 && q[6] == 0xc3) {
        std::printf(" mov eax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 2));
        return;
    }
    if (q[0] == 0x48 && q[1] == 0x8b && q[2] == 0x81 && q[7] == 0xc3) {
        std::printf(" mov rax,[rcx+0x%x]", *reinterpret_cast<const uint32_t*>(q + 3));
        return;
    }
    std::printf(" %02x %02x %02x %02x %02x %02x %02x %02x", q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7]);
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

    const char prefix[] = ".?AVC";
    int shown = 0;
    for (size_t i = 0; i + 16 < buf.size(); ++i) {
        if (std::memcmp(buf.data() + i, prefix, 5) != 0) {
            continue;
        }
        size_t end = i + 5;
        while (end < buf.size() && buf[end] != 0 && end - i < 80) {
            ++end;
        }
        const char* name = reinterpret_cast<const char*>(buf.data() + i);
        if (std::strstr(name, "Unit") == nullptr && std::strstr(name, "Division") == nullptr) {
            continue;
        }
        const uint32_t td = file_to_rva(i) >= 16 ? file_to_rva(i) - 16 : 0;
        const uint32_t vt = vtable_for_td(td);
        std::printf("%s vt=0x%08x", name, vt);
        if (vt != 0) {
            const size_t ff = rva_to_file(vt);
            const uint64_t slot39 = *reinterpret_cast<const uint64_t*>(buf.data() + ff + 39 * 8);
            std::printf(" [39]=");
            if (slot39 > image_base) {
                describe(static_cast<uint32_t>(slot39 - image_base));
            }
        }
        std::printf("\n");
        ++shown;
        if (shown >= 40) {
            break;
        }
    }
    return 0;
}
