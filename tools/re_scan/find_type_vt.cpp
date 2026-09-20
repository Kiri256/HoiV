#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

int main(int argc,char**argv){
 if(argc<3)return 1; std::ifstream f(argv[1],std::ios::binary); std::vector<unsigned char>b((std::istreambuf_iterator<char>(f)),{}); const char* name=argv[2]; size_t nl=strlen(name);
 auto d=(IMAGE_DOS_HEADER*)b.data(); auto n=(IMAGE_NT_HEADERS64*)(b.data()+d->e_lfanew); auto s=(IMAGE_SECTION_HEADER*)(b.data()+d->e_lfanew+24+n->FileHeader.SizeOfOptionalHeader); int ns=n->FileHeader.NumberOfSections; uint64_t ib=n->OptionalHeader.ImageBase;
 auto rva=[&](size_t o)->uint32_t{for(int i=0;i<ns;i++)if(o>=s[i].PointerToRawData&&o<s[i].PointerToRawData+s[i].SizeOfRawData)return s[i].VirtualAddress+(uint32_t)(o-s[i].PointerToRawData);return 0;};
 auto roff=[&](uint32_t rv)->size_t{for(int i=0;i<ns;i++){uint32_t v=s[i].VirtualAddress, z=(s[i].Misc.VirtualSize>s[i].SizeOfRawData?s[i].Misc.VirtualSize:s[i].SizeOfRawData);if(rv>=v&&rv<v+z)return s[i].PointerToRawData+(rv-v);}return (size_t)-1;};
 std::vector<uint32_t> descs; for(size_t o=0;o+nl<b.size();o++)if(!memcmp(b.data()+o,name,nl)&&b[o+nl]==0){uint32_t sr=rva(o);printf("string file 0x%zx rva 0x%x\n",o,sr); if(sr>=16)descs.push_back(sr-16);} 
 for(uint32_t td:descs){ for(size_t o=0;o+4<=b.size();o++)if(!memcmp(b.data()+o,&td,4)){uint32_t col=rva(o); if(!col)continue; printf("TD ref rva 0x%x -> candidate COL 0x%x\n",col,col>=12?col-12:0); uint32_t c=col>=12?col-12:0; uint64_t q=ib+c; for(size_t p=0;p+8<=b.size();p++) if(!memcmp(b.data()+p,&q,8)){uint32_t vt=rva(p+8); if(!vt)continue; printf("  vtable ptr at rva 0x%x -> vt 0x%x\n",rva(p+8),vt); size_t vo=roff(vt); if(vo==(size_t)-1)continue; for(int i=0;i<20;i++){uint64_t va=0; memcpy(&va,b.data()+vo+i*8,8); if(va>=ib&&va<ib+0x4000000)printf("    [%d] 0x%x\n",i,(uint32_t)(va-ib));} }} }
}
