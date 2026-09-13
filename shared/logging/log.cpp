#include "log.hpp"

#include <windows.h>

#include <cstdio>
#include <mutex>
#include <string>

namespace hoiv {
namespace {

std::mutex g_mutex;
HANDLE g_file = INVALID_HANDLE_VALUE;
std::string g_component;

void write_bytes(const char* data, DWORD size) {
    if (g_file == INVALID_HANDLE_VALUE || data == nullptr || size == 0) {
        return;
    }
    DWORD written = 0;
    WriteFile(g_file, data, size, &written, nullptr);
}

}  // namespace

void log_open(const std::wstring& path, const char* component) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    g_component = component != nullptr ? component : "unknown";
    if (path.empty()) {
        return;
    }

    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        const std::wstring dir = path.substr(0, slash);
        CreateDirectoryW(dir.c_str(), nullptr);
    }

    g_file = CreateFileW(
        path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

void log_line(const char* component, unsigned error_code, const char* message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    SYSTEMTIME st {};
    GetLocalTime(&st);

    char stamped[768];
    const int m = std::snprintf(
        stamped,
        sizeof(stamped),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03u tid=%lu component=%s error=%u %s\r\n",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds),
        static_cast<unsigned long>(GetCurrentThreadId()),
        component != nullptr ? component : g_component.c_str(),
        error_code,
        message != nullptr ? message : "");
    if (m > 0) {
        write_bytes(stamped, static_cast<DWORD>(m));
    }
}

void log_close() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
}

}  // namespace hoiv
