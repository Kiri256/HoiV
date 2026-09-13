#include "remote_load.hpp"

#include "../win/utf8.hpp"

#include <windows.h>

namespace hoiv {
namespace {

constexpr DWORD kLoadTimeoutMs = 15000;

FARPROC local_export(const std::wstring& dll_path, const char* name, HMODULE* local_module) {
    *local_module = LoadLibraryW(dll_path.c_str());
    if (*local_module == nullptr) {
        return nullptr;
    }
    return GetProcAddress(*local_module, name);
}

}  // namespace

bool load_bridge_into_process(HANDLE process, const std::wstring& dll_path, RemoteBridge* out, std::string* error) {
    if (out == nullptr || process == nullptr || dll_path.empty()) {
        if (error != nullptr) {
            *error = "invalid load arguments";
        }
        return false;
    }
    *out = {};
    out->process = process;

    HMODULE local = nullptr;
    FARPROC init = local_export(dll_path, "Bridge_Initialize", &local);
    FARPROC disable = local != nullptr ? GetProcAddress(local, "Bridge_Disable") : nullptr;
    FARPROC shutdown = local != nullptr ? GetProcAddress(local, "Bridge_Shutdown") : nullptr;
    if (local == nullptr || init == nullptr || disable == nullptr || shutdown == nullptr) {
        if (error != nullptr) {
            *error = "bridge.dll exports are missing";
        }
        if (local != nullptr) {
            FreeLibrary(local);
        }
        return false;
    }

    const size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_path == nullptr) {
        if (error != nullptr) {
            *error = "VirtualAllocEx failed";
        }
        FreeLibrary(local);
        return false;
    }
    if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), bytes, nullptr)) {
        if (error != nullptr) {
            *error = "WriteProcessMemory failed";
        }
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        FreeLibrary(local);
        return false;
    }

    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel, "LoadLibraryW"));
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote_path, 0, nullptr);
    if (thread == nullptr) {
        if (error != nullptr) {
            *error = "CreateRemoteThread(LoadLibraryW) failed";
        }
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        FreeLibrary(local);
        return false;
    }

    const DWORD wait = WaitForSingleObject(thread, kLoadTimeoutMs);
    DWORD code = 0;
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    if (wait != WAIT_OBJECT_0 || code == 0) {
        if (error != nullptr) {
            *error = "LoadLibraryW did not return a module";
        }
        FreeLibrary(local);
        return false;
    }

    // x64 module handles may exceed 32 bits; the DLL publishes the full handle.
    const uintptr_t local_base = reinterpret_cast<uintptr_t>(local);
    out->initialize = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(init) - local_base);
    out->disable = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(disable) - local_base);
    out->shutdown = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(shutdown) - local_base);
    FreeLibrary(local);
    return true;
}

bool call_remote(HANDLE process, uint64_t fn, DWORD timeout_ms, uint32_t* exit_code, std::string* error) {
    if (process == nullptr || fn == 0) {
        if (error != nullptr) {
            *error = "invalid remote call";
        }
        return false;
    }
    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<uintptr_t>(fn)),
        nullptr,
        0,
        nullptr);
    if (thread == nullptr) {
        if (error != nullptr) {
            *error = "CreateRemoteThread failed";
        }
        return false;
    }
    const DWORD wait = WaitForSingleObject(thread, timeout_ms);
    DWORD code = 0;
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) {
        if (error != nullptr) {
            *error = "remote call timed out";
        }
        return false;
    }
    if (exit_code != nullptr) {
        *exit_code = static_cast<uint32_t>(code);
    }
    return true;
}

bool unload_bridge_from_process(const RemoteBridge& remote, DWORD timeout_ms, std::string* error) {
    if (remote.process == nullptr || remote.module == 0) {
        if (error != nullptr) {
            *error = "bridge module handle is missing";
        }
        return false;
    }
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    auto free_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel, "FreeLibrary"));
    HANDLE thread = CreateRemoteThread(
        remote.process,
        nullptr,
        0,
        free_library,
        reinterpret_cast<LPVOID>(static_cast<uintptr_t>(remote.module)),
        0,
        nullptr);
    if (thread == nullptr) {
        if (error != nullptr) {
            *error = "CreateRemoteThread(FreeLibrary) failed";
        }
        return false;
    }
    const DWORD wait = WaitForSingleObject(thread, timeout_ms);
    CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) {
        if (error != nullptr) {
            *error = "FreeLibrary timed out";
        }
        return false;
    }
    return true;
}

}  // namespace hoiv
