#pragma once

#include <string>
#include <windows.h>

namespace hoiv {

inline std::wstring widen(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int chars = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (chars <= 1) {
        return {};
    }
    std::wstring out(static_cast<size_t>(chars - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), chars);
    return out;
}

inline std::string narrow(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 1) {
        return {};
    }
    std::string out(static_cast<size_t>(bytes - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), bytes, nullptr, nullptr);
    return out;
}

inline void copy_narrow(char* dst, size_t dst_bytes, const std::string& src) {
    if (dst == nullptr || dst_bytes == 0) {
        return;
    }
    const size_t n = src.size() < dst_bytes - 1 ? src.size() : dst_bytes - 1;
    for (size_t i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
    dst[n] = '\0';
}

inline void copy_wide(wchar_t* dst, size_t dst_chars, const std::wstring& src) {
    if (dst == nullptr || dst_chars == 0) {
        return;
    }
    const size_t n = src.size() < dst_chars - 1 ? src.size() : dst_chars - 1;
    for (size_t i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
    dst[n] = L'\0';
}

}  // namespace hoiv
