#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

namespace hoiv {

struct RemoteBridge {
    HANDLE process = nullptr;
    uint64_t module = 0;
    uint64_t initialize = 0;
    uint64_t disable = 0;
    uint64_t shutdown = 0;
};

bool load_bridge_into_process(HANDLE process, const std::wstring& dll_path, RemoteBridge* out, std::string* error);
bool call_remote(HANDLE process, uint64_t fn, DWORD timeout_ms, uint32_t* exit_code, std::string* error);
bool unload_bridge_from_process(const RemoteBridge& remote, DWORD timeout_ms, std::string* error);

}  // namespace hoiv
