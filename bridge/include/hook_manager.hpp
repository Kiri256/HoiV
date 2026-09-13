#pragma once

#include <cstdint>

namespace hoiv {

class HookManager {
public:
    enum class Result : uint32_t {
        Ok = 0,
        Rejected = 1,
        AlreadyInstalled = 2,
        NotInstalled = 3,
    };

    HookManager();
    ~HookManager();

    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    Result install_if_needed(
        bool version_ok,
        bool (*install)() = nullptr,
        void (*uninstall)() = nullptr);
    Result uninstall();
    bool is_installed() const;
    uint32_t install_calls() const;
    uint32_t actual_installs() const;

private:
    mutable void* section_;
    bool installed_;
    uint32_t install_calls_;
    uint32_t actual_installs_;
    void (*uninstall_fn_)();
};

}  // namespace hoiv
