#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <cstring>
int main(int argc,char**argv){if(argc<2)return 1;std::ifstream f(argv[1],std::ios::binary);std::vector<unsigned char>b((std::istreambuf_iterator<char>(f)),{});auto d=(IMAGE_DOS_HEADER*)b.data();auto n=(IMAGE_NT_HEADERS64*)(b.data()+d->e_lfanew);auto s=(IMAGE_SECTION_HEADER*)(b.data()+d->e_lfanew+24+n->FileHeader.SizeOfOptionalHeader);int ns=n->FileHeader.NumberOfSections;auto rva=[&](size_t o)->uint32_t{for(int i=0;i<ns;i++)if(o>=s[i].PointerToRawData&&o<s[i].PointerToRawData+s[i].SizeOfRawData)return s[i].VirtualAddress+(uint32_t)(o-s[i].PointerToRawData);return 0u;};
 uint64_t base=n->OptionalHeader.ImageBase;
 const uint32_t vts[] = {0x02933d20u,0x02962938u,0x029613d0u,0x0298a3c0u,0x0298a618u,0x0298b680u,0x0298a488u,0x0298a7a8u};
 for(uint32_t vt:vts){uint64_t va=base+vt;printf("VT 0x%x VA %llx\n",vt,(unsigned long long)va); for(int i=0;i<ns;i++){size_t st=s[i].PointerToRawData,en=st+s[i].SizeOfRawData;for(size_t o=st;o+7<en;o++){if(memcmp(b.data()+o,&va,8)==0)printf(" qword ref section %.8s rva 0x%08x\n",s[i].Name,rva(o)); if(o+7<en&&b[o]==0x48&&b[o+1]==0x8d&&(b[o+2]&0x07)==5){int32_t rel=*reinterpret_cast<int32_t*>(b.data()+o+3);uint32_t x=rva(o);if((uint64_t)base+x+7+rel==va)printf(" lea ref section %.8s rva 0x%08x\n",s[i].Name,x);} }} }
}
