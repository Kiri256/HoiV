#include "identity.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <fstream>
#include <vector>

namespace hoiv {
namespace {

constexpr size_t kSha256Bytes = 32;

std::string to_hex(const unsigned char* data, size_t size) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = kDigits[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kDigits[data[i] & 0x0f];
    }
    return out;
}

std::string trim(std::string text) {
    size_t begin = 0;
    while (begin < text.size() && (text[begin] == ' ' || text[begin] == '\t' || text[begin] == '"' ||
                                   text[begin] == '\r')) {
        ++begin;
    }
    size_t end = text.size();
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '"' ||
                           text[end - 1] == '\r' || text[end - 1] == '\n')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

}  // namespace

bool sha256_file(const std::wstring& path, std::string* hex) {
    if (hex == nullptr) {
        return false;
    }
    hex->clear();

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    unsigned char digest[kSha256Bytes];

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        unsigned char buffer[64 * 1024];
        DWORD read = 0;
        ok = true;
        for (;;) {
            if (!ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) {
                ok = false;
                break;
            }
            if (read == 0) {
                break;
            }
            if (BCryptHashData(hash, buffer, read, 0) != 0) {
                ok = false;
                break;
            }
        }
        if (ok && BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            *hex = to_hex(digest, sizeof(digest));
        } else {
            ok = false;
        }
    }

    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    CloseHandle(file);
    return ok && hex->size() == 64;
}

bool read_pe_timestamp(const std::wstring& path, uint32_t* timestamp) {
    if (timestamp == nullptr) {
        return false;
    }
    *timestamp = 0;

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    IMAGE_DOS_HEADER dos {};
    DWORD read = 0;
    bool ok = false;
    if (ReadFile(file, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
        if (SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
            IMAGE_NT_HEADERS64 nt {};
            if (ReadFile(file, &nt, sizeof(nt), &read, nullptr) && read >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) &&
                nt.Signature == IMAGE_NT_SIGNATURE) {
                *timestamp = nt.FileHeader.TimeDateStamp;
                ok = true;
            }
        }
    }
    CloseHandle(file);
    return ok;
}

bool read_product_version(const std::wstring& path, std::string* version) {
    if (version == nullptr) {
        return false;
    }
    version->clear();

    DWORD dummy = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (size == 0) {
        return false;
    }

    std::vector<unsigned char> buffer(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data())) {
        return false;
    }

    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixed_len = 0;
    if (VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<void**>(&fixed), &fixed_len) && fixed != nullptr &&
        fixed_len >= sizeof(VS_FIXEDFILEINFO)) {
        char text[64];
        std::snprintf(
            text,
            sizeof(text),
            "%u.%u.%u.%u",
            static_cast<unsigned>(HIWORD(fixed->dwProductVersionMS)),
            static_cast<unsigned>(LOWORD(fixed->dwProductVersionMS)),
            static_cast<unsigned>(HIWORD(fixed->dwProductVersionLS)),
            static_cast<unsigned>(LOWORD(fixed->dwProductVersionLS)));
        *version = text;
        return true;
    }
    return false;
}

std::string file_name_only(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    const std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    std::string out;
    out.resize(name.size());
    for (size_t i = 0; i < name.size(); ++i) {
        wchar_t c = name[i];
        if (c >= L'A' && c <= L'Z') {
            c = static_cast<wchar_t>(c - L'A' + L'a');
        }
        out[i] = c < 128 ? static_cast<char>(c) : '?';
    }
    return out;
}

bool read_file_identity(const std::wstring& path, FileIdentity* out, std::string* error) {
    if (out == nullptr) {
        return false;
    }
    *out = {};
    out->path = path;
    out->file_name = file_name_only(path);

    if (path.empty()) {
        if (error != nullptr) {
            *error = "exe path is empty";
        }
        return false;
    }
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (error != nullptr) {
            *error = "exe file not found";
        }
        return false;
    }
    if (!sha256_file(path, &out->sha256_hex)) {
        if (error != nullptr) {
            *error = "sha256 failed";
        }
        return false;
    }
    if (!read_pe_timestamp(path, &out->pe_timestamp)) {
        if (error != nullptr) {
            *error = "pe timestamp failed";
        }
        return false;
    }
    if (!read_product_version(path, &out->product_version)) {
        out->product_version.clear();
    }

    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        const std::wstring settings = path.substr(0, slash) + L"\\launcher-settings.json";
        HANDLE file = CreateFileW(
            settings.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size {};
            if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < 64 * 1024) {
                std::string text(static_cast<size_t>(size.QuadPart), '\0');
                DWORD read = 0;
                if (ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr)) {
                    const std::string key = "\"rawVersion\"";
                    const size_t pos = text.find(key);
                    if (pos != std::string::npos) {
                        const size_t colon = text.find(':', pos + key.size());
                        const size_t first = text.find('"', colon);
                        const size_t last = first == std::string::npos ? std::string::npos : text.find('"', first + 1);
                        if (first != std::string::npos && last != std::string::npos && last > first + 1) {
                            out->raw_version = text.substr(first + 1, last - first - 1);
                        }
                    }
                }
            }
            CloseHandle(file);
        }
    }
    return true;
}

bool read_blackice_version(const std::wstring& descriptor_path, BlackiceIdentity* out, std::string* error) {
    if (out == nullptr) {
        return false;
    }
    *out = {};
    out->descriptor_path = descriptor_path;
    if (descriptor_path.empty()) {
        if (error != nullptr) {
            *error = "blackice descriptor path is empty";
        }
        return false;
    }

    std::ifstream in(descriptor_path.c_str());
    if (!in) {
        if (error != nullptr) {
            *error = "blackice descriptor not found";
        }
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        const std::string trimmed = trim(line);
        if (trimmed.rfind("version=", 0) != 0) {
            continue;
        }
        out->version = trim(trimmed.substr(8));
        return !out->version.empty();
    }
    if (error != nullptr) {
        *error = "blackice version field missing";
    }
    return false;
}

bool version_prefix_match(const std::string& value, const std::string& prefix) {
    if (prefix.empty() || value.size() < prefix.size()) {
        return false;
    }
    return value.compare(0, prefix.size(), prefix) == 0;
}

std::string version_for_gate(const FileIdentity& exe) {
    return exe.raw_version.empty() ? exe.product_version : exe.raw_version;
}

bool find_blackice_descriptor(std::wstring* path) {
    if (path == nullptr) {
        return false;
    }
    wchar_t profile[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }
    const std::wstring root = std::wstring(profile) + L"\\Documents\\Paradox Interactive\\Hearts of Iron IV\\mod";
    const std::wstring pattern = root + L"\\*";
    WIN32_FIND_DATAW data {};
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool found = false;
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }
        if (data.cFileName[0] == L'.') {
            continue;
        }
        const std::wstring candidate = root + L"\\" + data.cFileName + L"\\descriptor.mod";
        BlackiceIdentity identity {};
        std::string error;
        if (!read_blackice_version(candidate, &identity, &error)) {
            continue;
        }
        std::ifstream in(candidate.c_str());
        if (!in) {
            continue;
        }
        std::string line;
        std::string name;
        while (std::getline(in, line)) {
            const std::string trimmed = trim(line);
            if (trimmed.rfind("name=", 0) == 0) {
                name = trim(trimmed.substr(5));
            }
        }
        if (name.find("BlackICE") == std::string::npos) {
            continue;
        }
        if (!version_prefix_match(identity.version, "12.1.")) {
            continue;
        }
        *path = candidate;
        found = true;
        break;
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return found;
}

}  // namespace hoiv
