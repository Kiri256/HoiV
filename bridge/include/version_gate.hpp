#pragma once

#include "../../shared/config/config.hpp"
#include "../../shared/identity/identity.hpp"
#include "../../shared/schema/schema.hpp"

#include <string>

namespace hoiv {

struct GateInput {
    FileIdentity exe;
    BlackiceIdentity blackice;
    RuntimeConfig config;
    bool have_blackice = false;
};

struct GateResult {
    ErrorCode code = ErrorCode::IdentityReadFailed;
    std::string message;
    bool version_ok = false;
};

GateResult evaluate_version_gate(const GateInput& input);

}  // namespace hoiv
