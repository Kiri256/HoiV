#pragma once

#include <cstdint>
#include <string>

namespace hoiv {

struct FileIdentity {
    std::wstring path;
    std::string sha256_hex;
    uint32_t pe_timestamp = 0;
    std::string product_version;
    std::string raw_version;
    std::string file_name;
};

struct BlackiceIdentity {
    std::wstring descriptor_path;
    std::string version;
};

bool sha256_file(const std::wstring& path, std::string* hex);
bool read_pe_timestamp(const std::wstring& path, uint32_t* timestamp);
bool read_product_version(const std::wstring& path, std::string* version);
bool read_file_identity(const std::wstring& path, FileIdentity* out, std::string* error);
bool read_blackice_version(const std::wstring& descriptor_path, BlackiceIdentity* out, std::string* error);
bool find_blackice_descriptor(std::wstring* path);
std::string file_name_only(const std::wstring& path);
bool version_prefix_match(const std::string& value, const std::string& prefix);
std::string version_for_gate(const FileIdentity& exe);

}  // namespace hoiv
