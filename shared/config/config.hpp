#pragma once

#include <cstdint>
#include <string>

namespace hoiv {

struct RuntimeConfig {
    uint8_t enabled = 0;
    uint8_t read_only = 1;
    uint32_t max_orders_per_hour = 0;
    std::wstring exe_path;
    std::string expected_sha256_hex;
    uint32_t expected_pe_timestamp = 0;
    std::string expected_product_version;
    std::wstring blackice_descriptor;
    std::string expected_blackice_version;
    std::string adapter_id;
    std::wstring bridge_dll;
    std::wstring planner_exe;
    std::wstring log_dir;
    uint8_t allow_test_host = 0;
};

RuntimeConfig default_runtime_config();
bool load_runtime_config(const std::wstring& path, RuntimeConfig* out, std::string* error);
bool save_runtime_config_template(const std::wstring& path);

}  // namespace hoiv
