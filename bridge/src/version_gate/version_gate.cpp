#include "../../include/version_gate.hpp"

#include "../../../adapters/hoi4_1_19_blackice_12_1/adapter.hpp"

namespace hoiv {
namespace {

std::string or_default(const std::string& value, const char* fallback) {
    return value.empty() ? std::string(fallback) : value;
}

bool hex_equal(const std::string& a, const std::string& b) {
    if (a.size() != 64 || b.size() != 64) {
        return false;
    }
    for (size_t i = 0; i < 64; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'F') {
            ca = static_cast<char>(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'F') {
            cb = static_cast<char>(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

}  // namespace

GateResult evaluate_version_gate(const GateInput& input) {
    GateResult result;

    const std::string adapter_id = or_default(input.config.adapter_id, adapter::kId);
    if (adapter_id != adapter::kId) {
        result.code = ErrorCode::VersionMismatch;
        result.message = "adapter id is not hoi4_1_19_blackice_12_1";
        return result;
    }

    const bool test_host = input.config.allow_test_host != 0 && input.exe.file_name == adapter::kTestHostImageName;
    if (!test_host && input.exe.file_name != adapter::kGameImageName) {
        result.code = ErrorCode::WrongProcess;
        result.message = "process image is not hoi4.exe";
        return result;
    }

    if (input.config.expected_sha256_hex.size() != 64) {
        result.code = ErrorCode::VersionNotPinned;
        result.message = "expected_sha256 is not pinned";
        return result;
    }
    if (input.config.expected_pe_timestamp == 0) {
        result.code = ErrorCode::VersionNotPinned;
        result.message = "expected_pe_timestamp is not pinned";
        return result;
    }

    if (!hex_equal(input.exe.sha256_hex, input.config.expected_sha256_hex)) {
        result.code = ErrorCode::HashMismatch;
        result.message = "exe sha256 does not match pinned hash";
        return result;
    }
    if (input.exe.pe_timestamp != input.config.expected_pe_timestamp) {
        result.code = ErrorCode::PeTimestampMismatch;
        result.message = "pe timestamp does not match pinned value";
        return result;
    }

    const std::string version_prefix =
        or_default(input.config.expected_product_version, adapter::kHoi4VersionPrefix);
    if (!version_prefix_match(version_for_gate(input.exe), version_prefix)) {
        result.code = ErrorCode::VersionMismatch;
        result.message = "rawVersion/product version is not in the 1.19.x range";
        return result;
    }

    if (test_host) {
        result.code = ErrorCode::Ok;
        result.message = "test host identity accepted; writes stay disabled";
        result.version_ok = true;
        return result;
    }

    if (!input.have_blackice || input.blackice.version.empty()) {
        result.code = ErrorCode::BlackiceMismatch;
        result.message = "blackice 12.1.x descriptor was not identified";
        return result;
    }
    const std::string blackice_prefix =
        or_default(input.config.expected_blackice_version, adapter::kBlackIceVersionPrefix);
    if (!version_prefix_match(input.blackice.version, blackice_prefix)) {
        result.code = ErrorCode::BlackiceMismatch;
        result.message = "blackice version is not 12.1.x";
        return result;
    }

    result.code = ErrorCode::Ok;
    result.message = "build identity matches pinned adapter";
    result.version_ok = true;
    return result;
}

}  // namespace hoiv
