#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>

struct RuntimeFn { uint32_t begin, end; };

int main(int argc,char**argv){
 if(argc<2)return 1; std::ifstream f(argv[1],std::ios::binary);
 std::vector<unsigned char>b((std::istreambuf_iterator<char>(f)),{});
 auto d=(IMAGE_DOS_HEADER*)b.data(); auto n=(IMAGE_NT_HEADERS64*)(b.data()+d->e_lfanew);
 auto s=(IMAGE_SECTION_HEADER*)(b.data()+d->e_lfanew+24+n->FileHeader.SizeOfOptionalHeader);
 int ns=n->FileHeader.NumberOfSections;
 auto rva=[&](size_t o)->uint32_t{for(int i=0;i<ns;i++)if(o>=s[i].PointerToRawData&&o<s[i].PointerToRawData+s[i].SizeOfRawData)return s[i].VirtualAddress+(uint32_t)(o-s[i].PointerToRawData);return 0;};
 std::vector<RuntimeFn> funcs;
 auto &dd=n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
 if(dd.VirtualAddress && dd.Size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
  size_t po=0; for(int i=0;i<ns;i++){uint32_t v=s[i].VirtualAddress,z=(s[i].Misc.VirtualSize>s[i].SizeOfRawData?s[i].Misc.VirtualSize:s[i].SizeOfRawData);if(dd.VirtualAddress>=v&&dd.VirtualAddress<v+z){po=s[i].PointerToRawData+(dd.VirtualAddress-v);break;}}
  if(po){size_t count=dd.Size/sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); auto *rf=reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(b.data()+po); funcs.reserve(count); for(size_t i=0;i<count;i++) if(rf[i].BeginAddress<rf[i].EndAddress) funcs.push_back({rf[i].BeginAddress,rf[i].EndAddress}); std::sort(funcs.begin(),funcs.end(),[](auto&a,auto&b){return a.begin<b.begin;});}
 }
 auto fn_for=[&](uint32_t x)->RuntimeFn{auto it=std::upper_bound(funcs.begin(),funcs.end(),x,[](uint32_t v,const RuntimeFn&f){return v<f.begin;});if(it==funcs.begin())return {};--it;return (x>=it->begin&&x<it->end)?*it:RuntimeFn{};};
 for(unsigned slot: {0x70u,0x48u,0x68u,0x40u,0x78u,0x80u,0x88u,0x90u}){
  printf("SLOT 0x%x\n",slot); unsigned hits=0;
  for(int i=0;i<ns;i++){if(memcmp(s[i].Name,".text",5))continue; auto st=s[i].PointerToRawData,en=st+s[i].SizeOfRawData;
   for(size_t o=st+1;o+3<en;o++) {
    if(b[o]!=0xff) continue;
    unsigned char m=b[o+1];
    if(((m>>3)&7)!=2) continue; // FF /2 = indirect call
    unsigned mod=m>>6, rm=m&7; size_t n=2; int64_t disp=0;
    if(mod==1){disp=static_cast<int8_t>(b[o+n]); n+=1;}
    else if(mod==2){if(o+n+4>en)continue; int32_t d; memcpy(&d,b.data()+o+n,4); disp=d; n+=4;}
    else continue; // no displacement, or SIB-only form
    if(disp!=static_cast<int64_t>(slot)) continue;
    auto x=rva(o); if(!x)continue; auto fn=fn_for(x); printf("  call* 0x%08x mod=%u rm=%u fn=[0x%08x,0x%08x)\n",x,mod,rm,fn.begin,fn.end); size_t a=o>32?o-32:o; for(size_t q=a;q<o+n+12&&q<en;q++)printf("%02x ",b[q]); printf("\n"); hits++;
   }
  }
  printf("hits=%u\n",hits);
 }
}
