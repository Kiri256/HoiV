#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <cstring>

static std::vector<unsigned char> b;
static IMAGE_SECTION_HEADER* sec = nullptr;
static int nsec = 0;
static uint32_t to_rva(size_t off) {
    for (int i=0;i<nsec;i++) if (off >= sec[i].PointerToRawData && off < sec[i].PointerToRawData + sec[i].SizeOfRawData)
        return sec[i].VirtualAddress + static_cast<uint32_t>(off-sec[i].PointerToRawData);
    return 0;
}
static size_t to_off(uint32_t rva) {
    for (int i=0;i<nsec;i++) {
        uint32_t z = sec[i].Misc.VirtualSize > sec[i].SizeOfRawData ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + z)
            return sec[i].PointerToRawData + (rva-sec[i].VirtualAddress);
    }
    return static_cast<size_t>(-1);
}
static void dump(size_t off, int n) {
    for (int i=0;i<n && off+i<b.size();i++) {
        if ((i%16)==0) std::printf("\n    %08x ", to_rva(off+i));
        std::printf("%02x ", b[off+i]);
    }
    std::printf("\n");
}
int main(int argc,char**argv){
    if(argc<2)return 1; std::ifstream f(argv[1],std::ios::binary); b.assign(std::istreambuf_iterator<char>(f),{});
    auto* d=(IMAGE_DOS_HEADER*)b.data(); auto* n=(IMAGE_NT_HEADERS64*)(b.data()+d->e_lfanew);
    nsec=n->FileHeader.NumberOfSections; sec=(IMAGE_SECTION_HEADER*)(b.data()+d->e_lfanew+24+n->FileHeader.SizeOfOptionalHeader);
    const uint32_t targets[] = {
        0x01350350,0x01352c90,0x01354c40,
        0x0134fd70,0x01352ad0,0x01354b00,
        0x01350b40,0x01351f80,0x01352000,0x01352f80,0x01354d90,
        0x01351750,0x01353720,0x01355240,
        0x0029e670,0x0029e680,0x0029e7b0,
        0x0107afb0,0x01074470,0x0107d9c0,
        0x00d61910,0x00d62020,0x00d61f10,0x00d61cf0,
        0x01074470,0x010aba70,0x010bb0d0
    };
    for (uint32_t t: targets) {
        std::printf("\nTARGET 0x%08x\n",t); int hits=0;
        for(int si=0;si<nsec;si++) { if(std::memcmp(sec[si].Name,".text",5)!=0) continue;
            size_t st=sec[si].PointerToRawData,en=st+sec[si].SizeOfRawData;
            for(size_t o=st;o+5<=en;o++) if(b[o]==0xe8) {
                int32_t rel=*reinterpret_cast<int32_t*>(b.data()+o+1); uint32_t r=to_rva(o);
                if(r+5+rel==t){ std::printf("  CALL 0x%08x",r); dump(o>48?o-48:o,96); if(++hits>=100) break; }
            }
        }
        std::printf("  hits=%d\n",hits);
    }
}
