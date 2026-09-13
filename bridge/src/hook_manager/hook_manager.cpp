#include "../../include/hook_manager.hpp"

#include <windows.h>

namespace hoiv {
namespace {

CRITICAL_SECTION* as_cs(void* section) {
    return static_cast<CRITICAL_SECTION*>(section);
}

}  // namespace

HookManager::HookManager()
    : section_(new CRITICAL_SECTION()),
      installed_(false),
      install_calls_(0),
      actual_installs_(0),
      uninstall_fn_(nullptr) {
    InitializeCriticalSection(as_cs(section_));
}

HookManager::~HookManager() {
    uninstall();
    DeleteCriticalSection(as_cs(section_));
    delete as_cs(section_);
    section_ = nullptr;
}

HookManager::Result HookManager::install_if_needed(
    bool version_ok,
    bool (*install)(),
    void (*uninstall)()) {
    EnterCriticalSection(as_cs(section_));
    ++install_calls_;
    if (!version_ok) {
        LeaveCriticalSection(as_cs(section_));
        return Result::Rejected;
    }
    if (installed_) {
        LeaveCriticalSection(as_cs(section_));
        return Result::AlreadyInstalled;
    }
    if (install != nullptr && !install()) {
        LeaveCriticalSection(as_cs(section_));
        return Result::Rejected;
    }
    installed_ = true;
    uninstall_fn_ = uninstall;
    ++actual_installs_;
    LeaveCriticalSection(as_cs(section_));
    return Result::Ok;
}

HookManager::Result HookManager::uninstall() {
    if (section_ == nullptr) {
        installed_ = false;
        uninstall_fn_ = nullptr;
        return Result::NotInstalled;
    }
    EnterCriticalSection(as_cs(section_));
    if (!installed_) {
        LeaveCriticalSection(as_cs(section_));
        return Result::NotInstalled;
    }
    void (*fn)() = uninstall_fn_;
    uninstall_fn_ = nullptr;
    installed_ = false;
    LeaveCriticalSection(as_cs(section_));
    if (fn != nullptr) {
        fn();
    }
    return Result::Ok;
}

bool HookManager::is_installed() const {
    EnterCriticalSection(as_cs(section_));
    const bool value = installed_;
    LeaveCriticalSection(as_cs(section_));
    return value;
}

uint32_t HookManager::install_calls() const {
    EnterCriticalSection(as_cs(section_));
    const uint32_t value = install_calls_;
    LeaveCriticalSection(as_cs(section_));
    return value;
}

uint32_t HookManager::actual_installs() const {
    EnterCriticalSection(as_cs(section_));
    const uint32_t value = actual_installs_;
    LeaveCriticalSection(as_cs(section_));
    return value;
}

}  // namespace hoiv
