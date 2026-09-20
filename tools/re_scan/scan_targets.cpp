#include <windows.h>
#include <vector>
#include <fstream>
#include <cstdio>
#include <cstdint>
#include <cstring>

int main(int argc,char**argv){
 if(argc<2)return 1; std::ifstream f(argv[1],std::ios::binary);
 std::vector<unsigned char>b((std::istreambuf_iterator<char>(f)),{});
 auto d=(IMAGE_DOS_HEADER*)b.data(); auto n=(IMAGE_NT_HEADERS64*)(b.data()+d->e_lfanew);
 auto s=(IMAGE_SECTION_HEADER*)(b.data()+d->e_lfanew+24+n->FileHeader.SizeOfOptionalHeader);
 int ns=n->FileHeader.NumberOfSections;
 auto rva=[&](size_t o)->uint32_t{for(int i=0;i<ns;i++)if(o>=s[i].PointerToRawData&&o<s[i].PointerToRawData+s[i].SizeOfRawData)return s[i].VirtualAddress+(uint32_t)(o-s[i].PointerToRawData);return 0;};
 for(uint32_t t:{0x0029e7b0u,0x00c7e870u,0x00de7c40u,0x01350350u}){
  printf("TARGET 0x%08x\n",t); int h=0;
  for(int i=0;i<ns;i++){if(memcmp(s[i].Name,".text",5))continue; auto st=s[i].PointerToRawData,en=st+s[i].SizeOfRawData;
   for(size_t o=st;o+5<en;o++)if(b[o]==0xe8||b[o]==0xe9){int32_t rel=*reinterpret_cast<int32_t*>(b.data()+o+1);uint32_t x=rva(o);if(x&&x+5+rel==t){printf("  %s 0x%08x\n",b[o]==0xe8?"call":"jmp",x); for(int k=-20;k<36;k++){if((k%16)==0)printf("   ");printf("%02x ",b[o+k]);if((k%16)==15)printf("\n");} h++;}}
  }
  printf("hits=%d\n",h);
 }
}
