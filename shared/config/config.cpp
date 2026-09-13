#include "config.hpp"

#include "../win/utf8.hpp"

#include <fstream>

namespace hoiv {
namespace {

std::string trim(const std::string& text) {
    size_t begin = 0;
    while (begin < text.size() && (text[begin] == ' ' || text[begin] == '\t')) {
        ++begin;
    }
    size_t end = text.size();
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

uint32_t parse_u32(const std::string& text, uint32_t fallback) {
    if (text.empty()) {
        return fallback;
    }
    unsigned long value = 0;
    try {
        value = std::stoul(text, nullptr, 0);
    } catch (...) {
        return fallback;
    }
    return static_cast<uint32_t>(value);
}

uint8_t parse_flag(const std::string& text, uint8_t fallback) {
    const std::string v = trim(text);
    if (v == "1" || v == "true" || v == "yes") {
        return 1;
    }
    if (v == "0" || v == "false" || v == "no") {
        return 0;
    }
    return fallback;
}

}  // namespace

RuntimeConfig default_runtime_config() {
    RuntimeConfig cfg;
    cfg.enabled = 0;
    cfg.read_only = 1;
    cfg.max_orders_per_hour = 0;
    cfg.expected_product_version = "1.19.";
    cfg.expected_blackice_version = "12.1.";
    cfg.adapter_id = "hoi4_1_19_blackice_12_1";
    cfg.allow_test_host = 0;
    return cfg;
}

bool load_runtime_config(const std::wstring& path, RuntimeConfig* out, std::string* error) {
    if (out == nullptr) {
        return false;
    }
    *out = default_runtime_config();
    if (path.empty()) {
        if (error != nullptr) {
            *error = "config path is empty";
        }
        return false;
    }

    std::ifstream in(path.c_str());
    if (!in) {
        if (error != nullptr) {
            *error = "config.ini not found";
        }
        return false;
    }

    std::string section;
    std::string line;
    while (std::getline(in, line)) {
        std::string text = trim(line);
        if (text.empty() || text[0] == '#' || text[0] == ';') {
            continue;
        }
        if (text.front() == '[' && text.back() == ']') {
            section = text.substr(1, text.size() - 2);
            continue;
        }
        const size_t eq = text.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const std::string key = trim(text.substr(0, eq));
        const std::string value = trim(text.substr(eq + 1));

        if (section == "runtime") {
            if (key == "enabled") {
                out->enabled = parse_flag(value, 0);
            } else if (key == "read_only") {
                out->read_only = parse_flag(value, 1);
            } else if (key == "max_orders_per_hour") {
                out->max_orders_per_hour = parse_u32(value, 0);
            }
        } else if (section == "game") {
            if (key == "exe_path") {
                out->exe_path = widen(value);
            } else if (key == "expected_sha256") {
                out->expected_sha256_hex = value;
            } else if (key == "expected_pe_timestamp") {
                out->expected_pe_timestamp = parse_u32(value, 0);
            } else if (key == "expected_product_version") {
                out->expected_product_version = value;
            }
        } else if (section == "blackice") {
            if (key == "descriptor_path") {
                out->blackice_descriptor = widen(value);
            } else if (key == "expected_version") {
                out->expected_blackice_version = value;
            }
        } else if (section == "adapter") {
            if (key == "id") {
                out->adapter_id = value;
            }
        } else if (section == "paths") {
            if (key == "bridge_dll") {
                out->bridge_dll = widen(value);
            } else if (key == "planner_exe") {
                out->planner_exe = widen(value);
            } else if (key == "log_dir") {
                out->log_dir = widen(value);
            }
        } else if (section == "test") {
            if (key == "allow_test_host") {
                out->allow_test_host = parse_flag(value, 0);
            }
        }
    }
    return true;
}

bool save_runtime_config_template(const std::wstring& path) {
    std::ofstream out(path.c_str(), std::ios::trunc);
    if (!out) {
        return false;
    }
    out << "[runtime]\n"
        << "enabled=0\n"
        << "read_only=1\n"
        << "max_orders_per_hour=0\n"
        << "\n"
        << "[game]\n"
        << "exe_path=\n"
        << "expected_sha256=\n"
        << "expected_pe_timestamp=0\n"
        << "expected_product_version=1.19.\n"
        << "\n"
        << "[blackice]\n"
        << "descriptor_path=\n"
        << "expected_version=12.1.\n"
        << "\n"
        << "[adapter]\n"
        << "id=hoi4_1_19_blackice_12_1\n"
        << "\n"
        << "[paths]\n"
        << "bridge_dll=\n"
        << "planner_exe=\n"
        << "log_dir=\n"
        << "\n"
        << "[test]\n"
        << "allow_test_host=0\n";
    return true;
}

}  // namespace hoiv
