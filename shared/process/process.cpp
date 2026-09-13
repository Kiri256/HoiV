#include "process.hpp"

#include "../identity/identity.hpp"

#include <tlhelp32.h>

namespace hoiv {

std::wstring join_path(const std::wstring& dir, const std::wstring& name) {
    if (dir.empty()) {
        return name;
    }
    const wchar_t last = dir.back();
    if (last == L'\\' || last == L'/') {
        return dir + name;
    }
    return dir + L"\\" + name;
}

std::wstring sibling_path(const std::wstring& file_name) {
    wchar_t module_path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return file_name;
    }
    std::wstring path(module_path, module_path + n);
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return file_name;
    }
    return join_path(path.substr(0, slash), file_name);
}

std::wstring current_process_image() {
    wchar_t image[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, image, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return std::wstring(image, image + n);
}

bool create_owned_process(const std::wstring& exe_path, HANDLE* process, DWORD* pid, std::string* error) {
    if (process == nullptr || pid == nullptr) {
        return false;
    }
    STARTUPINFOW si {};
    PROCESS_INFORMATION pi {};
    si.cb = sizeof(si);
    std::wstring cmd = L"\"" + exe_path + L"\"";
    std::wstring writable = cmd;
    if (!CreateProcessW(exe_path.c_str(), writable.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        if (error != nullptr) {
            *error = "CreateProcessW failed";
        }
        return false;
    }
    CloseHandle(pi.hThread);
    *process = pi.hProcess;
    *pid = pi.dwProcessId;
    return true;
}

bool open_process_by_pid(DWORD pid, HANDLE* process, std::string* error) {
    if (process == nullptr) {
        return false;
    }
    *process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_DUP_HANDLE | SYNCHRONIZE,
        FALSE,
        pid);
    if (*process == nullptr) {
        if (error != nullptr) {
            *error = "OpenProcess failed";
        }
        return false;
    }
    return true;
}

bool find_pid_by_image(const std::string& image_lower, DWORD* pid) {
    if (pid == nullptr || image_lower.empty()) {
        return false;
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W entry {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    DWORD match = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            const std::string name = file_name_only(std::wstring(entry.szExeFile));
            if (name == image_lower) {
                if (found) {
                    CloseHandle(snap);
                    return false;
                }
                found = true;
                match = entry.th32ProcessID;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    if (!found) {
        return false;
    }
    *pid = match;
    return true;
}

}  // namespace hoiv
