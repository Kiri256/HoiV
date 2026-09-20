#include "../include/bridge_api.hpp"
#include "../include/game_reader.hpp"
#include "../include/hook_manager.hpp"
#include "../include/version_gate.hpp"

#include "../../adapters/hoi4_1_19_blackice_12_1/adapter.hpp"
#include "../../shared/identity/identity.hpp"
#include "../../shared/ipc/session.hpp"
#include "../../shared/logging/log.hpp"
#include "../../shared/process/process.hpp"
#include "../../shared/win/utf8.hpp"

#include <atomic>
#include <string>

namespace hoiv {

HMODULE g_module = nullptr;
IpcSession g_ipc {};
HookManager g_hooks;
HANDLE g_control_thread = nullptr;
std::atomic<bool> g_initialized {false};
std::atomic<bool> g_stop {false};

void set_error(SharedBlock* block, ErrorCode code, const std::string& message) {
    if (block == nullptr) {
        return;
    }
    block->error_code = static_cast<uint32_t>(code);
    copy_narrow(block->last_error, sizeof(block->last_error), message);
    log_line("bridge", static_cast<unsigned>(code), message.c_str());
}

void publish_identity(SharedBlock* block, const FileIdentity& exe, const BlackiceIdentity& blackice) {
    if (block == nullptr) {
        return;
    }
    block->pe_timestamp = exe.pe_timestamp;
    copy_narrow(block->product_version, sizeof(block->product_version), version_for_gate(exe));
    copy_narrow(block->blackice_version, sizeof(block->blackice_version), blackice.version);
    copy_narrow(block->sha256_hex, sizeof(block->sha256_hex), exe.sha256_hex);
}

void apply_disable(const char* reason) {
    g_hooks.uninstall();
    if (g_ipc.block != nullptr) {
        g_ipc.block->hooks_installed = g_hooks.is_installed() ? 1 : 0;
        g_ipc.block->write_enabled = 0;
        g_ipc.block->disabled = 1;
        g_ipc.block->request = static_cast<uint32_t>(Request::None);
        set_error(g_ipc.block, ErrorCode::Ok, reason);
        if (g_ipc.disabled != nullptr) {
            SetEvent(g_ipc.disabled);
        }
    }
}

DWORD WINAPI control_main(LPVOID) {
    HANDLE events[2] = {g_ipc.disable, g_ipc.shutdown};
    while (!g_stop.load()) {
        const DWORD wait = WaitForMultipleObjects(2, events, FALSE, 200);
        if (wait == WAIT_OBJECT_0) {
            if (g_ipc.disable != nullptr) {
                ResetEvent(g_ipc.disable);
            }
            if (g_ipc.block != nullptr && g_ipc.block->request == static_cast<uint32_t>(Request::Disable)) {
                apply_disable("bridge disabled; hooks uninstalled");
            }
        } else if (wait == WAIT_OBJECT_0 + 1) {
            if (g_ipc.block == nullptr || g_ipc.block->request == static_cast<uint32_t>(Request::Shutdown) ||
                g_stop.load()) {
                apply_disable("bridge shutdown; hooks uninstalled");
                break;
            }
            if (g_ipc.shutdown != nullptr) {
                ResetEvent(g_ipc.shutdown);
            }
        }
    }
    return 0;
}

bool start_control_thread() {
    if (g_control_thread != nullptr) {
        return true;
    }
    g_stop.store(false);
    g_control_thread = CreateThread(nullptr, 0, control_main, nullptr, 0, nullptr);
    return g_control_thread != nullptr;
}

void stop_control_thread() {
    g_stop.store(true);
    if (g_ipc.shutdown != nullptr) {
        SetEvent(g_ipc.shutdown);
    }
    if (g_control_thread != nullptr) {
        WaitForSingleObject(g_control_thread, 5000);
        CloseHandle(g_control_thread);
        g_control_thread = nullptr;
    }
}

RuntimeConfig config_from_block(const SharedBlock* block) {
    RuntimeConfig cfg = default_runtime_config();
    if (block == nullptr) {
        return cfg;
    }
    cfg.enabled = block->enabled;
    cfg.read_only = block->read_only;
    cfg.skip_theatre_ai = block->skip_theatre_ai;
    cfg.max_orders_per_hour = block->max_orders_per_hour;
    cfg.exe_path = block->exe_path;
    cfg.expected_sha256_hex = block->expected_sha256_hex;
    cfg.expected_pe_timestamp = block->expected_pe_timestamp;
    cfg.expected_product_version = block->expected_product_version;
    cfg.blackice_descriptor = block->blackice_descriptor;
    cfg.expected_blackice_version = block->expected_blackice_version;
    cfg.adapter_id = block->adapter_id;
    cfg.allow_test_host = block->allow_test_host;
    return cfg;
}

void arm_control_events() {
    if (g_ipc.block != nullptr) {
        g_ipc.block->request = static_cast<uint32_t>(Request::None);
    }
    if (g_ipc.disable != nullptr) {
        ResetEvent(g_ipc.disable);
    }
    if (g_ipc.shutdown != nullptr) {
        ResetEvent(g_ipc.shutdown);
    }
    if (g_ipc.disabled != nullptr) {
        ResetEvent(g_ipc.disabled);
    }
}

uint32_t initialize_once() {
    if (g_ipc.block == nullptr && !ipc_open(&g_ipc)) {
        return static_cast<uint32_t>(ErrorCode::IpcFailed);
    }
    SharedBlock* block = g_ipc.block;
    if (block == nullptr || block->magic != kSharedMagic || block->schema_version != kSchemaVersion ||
        block->struct_size != sizeof(SharedBlock)) {
        return static_cast<uint32_t>(ErrorCode::SchemaMismatch);
    }
    block->module_handle = reinterpret_cast<uint64_t>(g_module);
    block->write_enabled = 0;
    game_reader_bind(block);

    const std::wstring image = current_process_image();
    FileIdentity exe {};
    std::string identity_error;
    if (!read_file_identity(image, &exe, &identity_error)) {
        set_error(block, ErrorCode::IdentityReadFailed, identity_error);
        block->initialized = 1;
        ipc_publish_ready(&g_ipc);
        return static_cast<uint32_t>(ErrorCode::IdentityReadFailed);
    }

    BlackiceIdentity blackice {};
    bool have_blackice = false;
    if (block->blackice_descriptor[0] != L'\0') {
        std::string blackice_error;
        have_blackice = read_blackice_version(block->blackice_descriptor, &blackice, &blackice_error);
        if (!have_blackice) {
            set_error(block, ErrorCode::BlackiceMismatch, blackice_error);
        }
    }
    publish_identity(block, exe, blackice);

    GateInput input;
    input.exe = exe;
    input.blackice = blackice;
    input.config = config_from_block(block);
    input.have_blackice = have_blackice;
    const GateResult gate = evaluate_version_gate(input);
    block->version_ok = gate.version_ok ? 1 : 0;
    copy_narrow(block->adapter_id, sizeof(block->adapter_id), input.config.adapter_id);

    if (!gate.version_ok) {
        g_hooks.uninstall();
        block->hooks_installed = 0;
        block->hook_install_calls = g_hooks.install_calls();
        block->hook_actual_installs = g_hooks.actual_installs();
        block->initialized = 1;
        set_error(block, gate.code, gate.message);
        arm_control_events();
        start_control_thread();
        ipc_publish_ready(&g_ipc);
        return static_cast<uint32_t>(gate.code);
    }

    const bool test_host = block->allow_test_host != 0 && exe.file_name == adapter::kTestHostImageName;
    const HookManager::Result hook = test_host
        ? g_hooks.install_if_needed(true)
        : g_hooks.install_if_needed(true, &game_reader_install, &game_reader_uninstall);
    if (hook == HookManager::Result::Rejected) {
        const ErrorCode code = test_host ? ErrorCode::HookRejected : ErrorCode::SignatureFailed;
        set_error(
            block,
            code,
            test_host ? "hook install rejected" : "GetPlayer signature failed; live read disabled");
        block->initialized = 1;
        ipc_publish_ready(&g_ipc);
        return static_cast<uint32_t>(code);
    }

    block->hooks_installed = 1;
    block->hook_install_calls = g_hooks.install_calls();
    block->hook_actual_installs = g_hooks.actual_installs();
    block->write_enabled =
        (!test_host && block->enabled != 0 && block->read_only == 0 && block->max_orders_per_hour > 0)
            ? 1
            : 0;
    block->disabled = 0;
    block->initialized = 1;
    g_initialized.store(true);
    set_error(
        block,
        ErrorCode::Ok,
        test_host ? "version gate passed; writes remain disabled; live read skipped on test host"
                  : (block->write_enabled != 0
                        ? "version gate passed; sample armed"
                        : "version gate passed; writes remain disabled; sample armed"));
    arm_control_events();
    start_control_thread();
    ipc_publish_ready(&g_ipc);
    return static_cast<uint32_t>(ErrorCode::Ok);
}

void runtime_set_module(HMODULE module) {
    g_module = module;
    wchar_t dll_path[MAX_PATH];
    if (GetModuleFileNameW(module, dll_path, MAX_PATH) > 0) {
        std::wstring path(dll_path);
        const size_t slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            log_open(join_path(join_path(path.substr(0, slash), L"logs"), L"bridge.log"), "bridge");
        }
    }
    if (ipc_open(&g_ipc) && g_ipc.block != nullptr) {
        g_ipc.block->module_handle = reinterpret_cast<uint64_t>(module);
    }
}

uint32_t runtime_initialize() {
    return initialize_once();
}

uint32_t runtime_disable() {
    apply_disable("bridge disabled by export");
    return static_cast<uint32_t>(ErrorCode::Ok);
}

uint32_t runtime_shutdown() {
    apply_disable("bridge shutdown by export");
    stop_control_thread();
    g_initialized.store(false);
    return static_cast<uint32_t>(ErrorCode::Ok);
}

void runtime_detach(bool process_exiting) {
    try {
        g_stop.store(true);
        if (!process_exiting) {
            stop_control_thread();
        }
        g_hooks.uninstall();
        if (g_ipc.block != nullptr) {
            g_ipc.block->hooks_installed = 0;
            g_ipc.block->write_enabled = 0;
            g_ipc.block->disabled = 1;
        }
        ipc_close(&g_ipc);
        log_close();
        g_initialized.store(false);
    } catch (...) {
    }
}

}  // namespace hoiv

extern "C" uint32_t Bridge_Initialize() {
    try {
        return hoiv::runtime_initialize();
    } catch (...) {
        return static_cast<uint32_t>(hoiv::ErrorCode::InternalError);
    }
}

extern "C" uint32_t Bridge_Disable() {
    try {
        return hoiv::runtime_disable();
    } catch (...) {
        return static_cast<uint32_t>(hoiv::ErrorCode::InternalError);
    }
}

extern "C" uint32_t Bridge_Shutdown() {
    try {
        return hoiv::runtime_shutdown();
    } catch (...) {
        return static_cast<uint32_t>(hoiv::ErrorCode::InternalError);
    }
}
