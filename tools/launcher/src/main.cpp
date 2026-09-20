#include "../../../bridge/include/version_gate.hpp"
#include "../../../shared/config/config.hpp"
#include "../../../shared/identity/identity.hpp"
#include "../../../shared/ipc/session.hpp"
#include "../../../shared/loader/remote_load.hpp"
#include "../../../shared/logging/log.hpp"
#include "../../../shared/process/process.hpp"
#include "../../../shared/win/utf8.hpp"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
constexpr DWORD kInitTimeoutMs = 15000;

void print_utf8(const char* text) {
    if (text == nullptr) {
        return;
    }
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const DWORD n = static_cast<DWORD>(lstrlenA(text));
    DWORD written = 0;
    if (out == nullptr || out == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!WriteConsoleA(out, text, n, &written, nullptr)) {
        WriteFile(out, text, n, &written, nullptr);
    }
}

void println(const std::string& text) {
    print_utf8(text.c_str());
    print_utf8("\r\n");
}

bool file_exists(const std::wstring& path) {
    return !path.empty() && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::wstring normalize_path(const std::wstring& path) {
    wchar_t full[MAX_PATH];
    const DWORD n = GetFullPathNameW(path.c_str(), MAX_PATH, full, nullptr);
    if (n == 0 || n >= MAX_PATH) {
        return path;
    }
    return std::wstring(full, full + n);
}

std::wstring default_config_path() {
    const std::wstring repo = normalize_path(hoiv::sibling_path(L"..\\tools\\launcher\\config.ini"));
    if (file_exists(repo)) {
        return repo;
    }
    return hoiv::sibling_path(L"config.ini");
}

std::wstring config_path_from_args(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        if (lstrcmpW(argv[i], L"--config") == 0 && i + 1 < argc) {
            return argv[i + 1];
        }
    }
    return default_config_path();
}

std::wstring resolve_existing(const std::wstring& configured, const std::wstring& fallback_name) {
    if (!configured.empty() && GetFileAttributesW(configured.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return configured;
    }
    const std::wstring sibling = hoiv::sibling_path(fallback_name);
    if (GetFileAttributesW(sibling.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return sibling;
    }
    return configured;
}

std::wstring registry_steam_path() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return {};
    }
    wchar_t value[MAX_PATH];
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LSTATUS st = RegQueryValueExW(key, L"SteamPath", nullptr, &type, reinterpret_cast<LPBYTE>(value), &size);
    RegCloseKey(key);
    if (st != ERROR_SUCCESS || type != REG_SZ) {
        return {};
    }
    return value;
}

std::wstring guess_hoi4_path() {
    const std::wstring candidates[] = {
        L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Hearts of Iron IV\\hoi4.exe",
        L"C:\\Program Files\\Steam\\steamapps\\common\\Hearts of Iron IV\\hoi4.exe",
        hoiv::join_path(registry_steam_path(), L"steamapps\\common\\Hearts of Iron IV\\hoi4.exe"),
    };
    for (const std::wstring& path : candidates) {
        if (!path.empty() && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return path;
        }
    }
    return {};
}

void apply_config_to_block(hoiv::SharedBlock* block, const hoiv::RuntimeConfig& cfg) {
    hoiv::copy_wide(block->exe_path, 260, cfg.exe_path);
    hoiv::copy_wide(block->blackice_descriptor, 260, cfg.blackice_descriptor);
    hoiv::copy_narrow(block->expected_sha256_hex, sizeof(block->expected_sha256_hex), cfg.expected_sha256_hex);
    hoiv::copy_narrow(block->expected_product_version, sizeof(block->expected_product_version), cfg.expected_product_version);
    hoiv::copy_narrow(block->expected_blackice_version, sizeof(block->expected_blackice_version), cfg.expected_blackice_version);
    hoiv::copy_narrow(block->adapter_id, sizeof(block->adapter_id), cfg.adapter_id);
    block->expected_pe_timestamp = cfg.expected_pe_timestamp;
    block->enabled = cfg.enabled;
    block->read_only = cfg.read_only;
    block->allow_test_host = cfg.allow_test_host;
    block->max_orders_per_hour = cfg.max_orders_per_hour;
    block->skip_theatre_ai = cfg.skip_theatre_ai;
}

int identify(const hoiv::RuntimeConfig& cfg) {
    hoiv::FileIdentity exe {};
    std::string error;
    if (!hoiv::read_file_identity(cfg.exe_path, &exe, &error)) {
        println(std::string("识别失败: ") + error);
        return 2;
    }
    println("exe_path=" + hoiv::narrow(exe.path));
    println("file_name=" + exe.file_name);
    println("sha256=" + exe.sha256_hex);
    char ts[32];
    std::snprintf(ts, sizeof(ts), "pe_timestamp=%u", exe.pe_timestamp);
    println(ts);
    println("product_version=" + exe.product_version);
    println("raw_version=" + exe.raw_version);
    println("gate_version=" + hoiv::version_for_gate(exe));

    std::wstring blackice_path = cfg.blackice_descriptor;
    if (blackice_path.empty()) {
        hoiv::find_blackice_descriptor(&blackice_path);
    }
    if (!blackice_path.empty()) {
        hoiv::BlackiceIdentity blackice {};
        if (hoiv::read_blackice_version(blackice_path, &blackice, &error)) {
            println("blackice_descriptor=" + hoiv::narrow(blackice_path));
            println("blackice_version=" + blackice.version);
        } else {
            println(std::string("blackice识别失败: ") + error);
        }
    } else {
        println("blackice_version=(未找到 12.1.x descriptor)");
    }
    println("将 sha256 和 pe_timestamp 写入 tools\\launcher\\config.ini 后才能加载。未钉扎时拒绝注入。");
    return 0;
}

int run_load(hoiv::RuntimeConfig cfg) {
    cfg.bridge_dll = resolve_existing(cfg.bridge_dll, L"bridge.dll");
    cfg.planner_exe = resolve_existing(cfg.planner_exe, L"planner.exe");
    if (cfg.exe_path.empty()) {
        cfg.exe_path = guess_hoi4_path();
    }
    if (cfg.blackice_descriptor.empty()) {
        hoiv::find_blackice_descriptor(&cfg.blackice_descriptor);
    }
    if (cfg.bridge_dll.empty()) {
        println("找不到 bridge.dll");
        return 2;
    }

    hoiv::FileIdentity exe {};
    std::string error;
    if (!hoiv::read_file_identity(cfg.exe_path, &exe, &error)) {
        println(std::string("识别失败: ") + error);
        return 2;
    }

    hoiv::BlackiceIdentity blackice {};
    bool have_blackice = false;
    if (!cfg.blackice_descriptor.empty()) {
        have_blackice = hoiv::read_blackice_version(cfg.blackice_descriptor, &blackice, &error);
    }

    hoiv::GateInput input;
    input.exe = exe;
    input.blackice = blackice;
    input.config = cfg;
    input.have_blackice = have_blackice;
    const hoiv::GateResult gate = hoiv::evaluate_version_gate(input);
    println(gate.message);
    if (!gate.version_ok) {
        hoiv::log_line("launcher", static_cast<unsigned>(gate.code), gate.message.c_str());
        return 3;
    }

    hoiv::IpcSession session {};
    if (!hoiv::ipc_create(&session)) {
        println("无法创建 IPC，可能已有启动器实例");
        return 4;
    }
    apply_config_to_block(session.block, cfg);

    DWORD pid = 0;
    HANDLE process = nullptr;
    bool owned = false;
    if (hoiv::find_pid_by_image(exe.file_name, &pid)) {
        if (!hoiv::open_process_by_pid(pid, &process, &error)) {
            println(error);
            hoiv::ipc_close(&session);
            return 5;
        }
    } else if (hoiv::create_owned_process(cfg.exe_path, &process, &pid, &error)) {
        owned = true;
        Sleep(200);
    } else {
        println(error);
        hoiv::ipc_close(&session);
        return 5;
    }

    hoiv::RemoteBridge remote {};
    if (!hoiv::load_bridge_into_process(process, cfg.bridge_dll, &remote, &error)) {
        println(error);
        if (owned) {
            TerminateProcess(process, 1);
        }
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return 6;
    }

    const DWORD wait_module = WaitForSingleObject(session.ready, 50);
    (void)wait_module;
    for (int i = 0; i < 100 && session.block->module_handle == 0; ++i) {
        Sleep(50);
    }
    if (session.block->module_handle == 0) {
        println("bridge.dll 未发布模块句柄");
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return 6;
    }
    remote.module = session.block->module_handle;
    remote.initialize += remote.module;
    remote.disable += remote.module;
    remote.shutdown += remote.module;

    uint32_t init_code = 0;
    if (!hoiv::call_remote(process, remote.initialize, kInitTimeoutMs, &init_code, &error)) {
        println(error);
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return 7;
    }
    if (WaitForSingleObject(session.ready, kInitTimeoutMs) != WAIT_OBJECT_0) {
        println("等待 bridge 就绪超时");
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return 7;
    }
    if (init_code != 0 || session.block->version_ok == 0) {
        println(std::string("版本门控拒绝: ") + session.block->last_error);
        hoiv::call_remote(process, remote.shutdown, 5000, nullptr, nullptr);
        hoiv::unload_bridge_from_process(remote, 5000, nullptr);
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return 3;
    }

    println("bridge.dll 已加载，版本识别通过。另开终端运行 --status 查看实时读取。");
    if (!cfg.planner_exe.empty() && GetFileAttributesW(cfg.planner_exe.c_str()) != INVALID_FILE_ATTRIBUTES) {
        HANDLE planner = nullptr;
        DWORD planner_pid = 0;
        if (hoiv::create_owned_process(cfg.planner_exe, &planner, &planner_pid, &error)) {
            println("planner.exe 已启动（P0.2 不执行规划）。");
            CloseHandle(planner);
        } else {
            println(std::string("planner 启动失败: ") + error);
        }
    }

    println("按 Ctrl+C 或关闭目标进程以停用。");
    WaitForSingleObject(process, INFINITE);
    hoiv::ipc_signal_shutdown(&session);
    hoiv::call_remote(process, remote.shutdown, 5000, nullptr, nullptr);
    hoiv::unload_bridge_from_process(remote, 5000, nullptr);
    CloseHandle(process);
    hoiv::ipc_close(&session);
    println("已停用并卸载，目标进程若仍在运行则保持其原生行为。");
    return 0;
}

int run_move(int argc, wchar_t** argv) {
    if (argc < 3) {
        println("用法: launcher --move <邻省ID>");
        println("邻省必须与 --status 里 army province 相邻，且不是同一格。");
        return 2;
    }
    wchar_t* end = nullptr;
    const long parsed = wcstol(argv[2], &end, 10);
    if (end == argv[2] || *end != L'\0' || parsed <= 0 || parsed >= 20000) {
        println("邻省ID无效");
        return 2;
    }
    const int32_t to = static_cast<int32_t>(parsed);

    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session) || session.block == nullptr) {
        println("没有活动的 bridge 会话");
        return 8;
    }
    if (session.block->schema_version != hoiv::kSchemaVersion) {
        println("schema 与启动器不一致，新旧启动器不能混用");
        hoiv::ipc_close(&session);
        return 1;
    }
    if (session.block->write_enabled == 0) {
        println("写入仍关。要实测必须 enabled=1、read_only=0、max_orders_per_hour>0 后重载 DLL");
        hoiv::ipc_close(&session);
        return 1;
    }
    if (session.block->player_tag != 1 || session.block->division_ok == 0) {
        println("先 --status，确认 sample tag=1 且 army 有 id/province，再 --move");
        hoiv::ipc_close(&session);
        return 1;
    }

    session.block->pending_move_province = to;
    session.block->order_attempts = 0;
    session.block->order_accepted = 0;
    session.block->last_order_result = 0;
    session.block->request = static_cast<uint32_t>(hoiv::Request::TestMove);
    for (int i = 0; i < 50 &&
         session.block->request == static_cast<uint32_t>(hoiv::Request::TestMove);
         ++i) {
        Sleep(100);
    }

    char line[240];
    std::snprintf(
        line,
        sizeof(line),
        "move    id=%d gen=%u from=%d to=%d attempts=%u accepted=%u result=%u writes=%u",
        session.block->division_id,
        session.block->division_generation,
        session.block->division_province,
        to,
        session.block->order_attempts,
        session.block->order_accepted,
        session.block->last_order_result,
        session.block->write_enabled);
    println(line);
    if (session.block->last_error[0] != '\0') {
        println(std::string("error   ") + session.block->last_error);
    }
    if (session.block->last_order_result != static_cast<uint32_t>(hoiv::OrderResult::Submitted)) {
        println("未提交。result 1=Gated 2=SignatureFailed 3=CanExecuteFalse 6=BadTarget 7=NoArmy。不要手控移动。");
    } else {
        println("已提交。看该师黄色箭头；再 --status 看 province 是否朝目标变。不要重下单。");
    }
    hoiv::ipc_close(&session);
    return 0;
}

int run_org(hoiv::Request request, const char* label) {
    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session) || session.block == nullptr) {
        println("没有活动的 bridge 会话");
        return 8;
    }
    if (session.block->schema_version != hoiv::kSchemaVersion) {
        println("schema 与启动器不一致，新旧启动器不能混用");
        hoiv::ipc_close(&session);
        return 1;
    }
    if (session.block->write_enabled == 0) {
        println("写入仍关。要实测必须 enabled=1、read_only=0、max_orders_per_hour>0 后重载 DLL");
        hoiv::ipc_close(&session);
        return 1;
    }
    if (session.block->player_tag != 1 || session.block->division_ok == 0) {
        println("先 --status，确认 sample tag=1 且 army 有 id/province");
        hoiv::ipc_close(&session);
        return 1;
    }

    session.block->order_attempts = 0;
    session.block->order_accepted = 0;
    session.block->last_order_result = 0;
    session.block->request = static_cast<uint32_t>(request);
    for (int i = 0; i < 50 && session.block->request == static_cast<uint32_t>(request); ++i) {
        Sleep(100);
    }

    char line[240];
    std::snprintf(
        line,
        sizeof(line),
        "%s id=%d gen=%u attempts=%u accepted=%u result=%u writes=%u",
        label,
        session.block->division_id,
        session.block->division_generation,
        session.block->order_attempts,
        session.block->order_accepted,
        session.block->last_order_result,
        session.block->write_enabled);
    println(line);
    if (session.block->last_error[0] != '\0') {
        println(std::string("error   ") + session.block->last_error);
    }
    if (session.block->last_order_result != static_cast<uint32_t>(hoiv::OrderResult::Submitted)) {
        println("未提交。result 1=Gated 2=SignatureFailed 3=CanExecuteFalse 6=BadTarget 7=NoArmy。");
        if (session.block->last_order_result == static_cast<uint32_t>(hoiv::OrderResult::Gated)) {
            println("Gated：写入关了，或上一单还占着 accepted。启动器现在会清掉测试计数。");
        }
    } else {
        println("已提交。看地图编制栏是否出现新对象。不要重下单。");
    }
    hoiv::ipc_close(&session);
    return 0;
}

int run_no_land_ai() {
    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session) || session.block == nullptr) {
        println("没有活动的 bridge 会话");
        return 8;
    }
    session.block->request = static_cast<uint32_t>(hoiv::Request::SuppressLandAi);
    for (int i = 0; i < 30 &&
         session.block->request == static_cast<uint32_t>(hoiv::Request::SuppressLandAi);
         ++i) {
        Sleep(100);
    }
    const char* path = "none";
    if (session.block->land_ai_path == hoiv::kLandAiPathOrgCreate) {
        path = "org-create";
    } else if (session.block->land_ai_path == hoiv::kLandAiPathGeneral) {
        path = "general";
    } else if (session.block->land_ai_path == hoiv::kLandAiPathOrderLock) {
        path = "orders";
    } else if (session.block->land_ai_path == hoiv::kLandAiPathMoveGate) {
        path = "move-gate";
    }
    char line[200];
    std::snprintf(
        line,
        sizeof(line),
        "抑制结果 result=%u off=%u path=%s ai_global=%u writes=%u read_only=%u",
        session.block->last_order_result,
        session.block->land_ai_off_count,
        path,
        session.block->land_ai_global,
        session.block->write_enabled,
        session.block->read_only);
    println(line);
    if (session.block->land_ai_path == hoiv::kLandAiPathOrgCreate) {
        println("已拦主要国家战线/集团军创建。不锁计划组，不动全局 ai。已有对象不拆。");
    } else if (session.block->land_ai_path == hoiv::kLandAiPathGeneral) {
        println("旧的 general-gate。重载 DLL 后再 --no-land-ai。");
    } else if (session.block->land_ai_path == hoiv::kLandAiPathMoveGate ||
        session.block->land_ai_path == hoiv::kLandAiPathOrderLock) {
        println("旧路径不应再出现。重载 DLL 后再 --no-land-ai。");
    }
    if (session.block->write_enabled == 0) {
        println("写入仍关。要实测必须 enabled=1、read_only=0 后重载 DLL");
    }
    hoiv::ipc_close(&session);
    return 0;
}

int run_cancel() {
    println("瑞士取消已验收，不再发测试单。当前只采德国、只看 probe。");
    return 0;
}

int run_signal(const wchar_t* action) {
    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session)) {
        println("没有活动的 bridge 会话");
        return 8;
    }
    if (lstrcmpW(action, L"--disable") == 0) {
        hoiv::ipc_signal_disable(&session);
        println("已请求停用");
    } else {
        hoiv::ipc_signal_shutdown(&session);
        println("已请求关闭");
    }
    hoiv::ipc_close(&session);
    return 0;
}

int run_status() {
    hoiv::IpcSession session {};
    if (!hoiv::ipc_open(&session) || session.block == nullptr) {
        println("没有活动的 bridge 会话");
        return 8;
    }
    const hoiv::SharedBlock* b = session.block;
    char line[640];
    std::snprintf(
        line,
        sizeof(line),
        "gate    schema=%u version_ok=%u hooks=%u installs=%u disabled=%u error=%u writes=%u",
        b->schema_version,
        b->version_ok,
        b->hooks_installed,
        b->hook_actual_installs,
        b->disabled,
        b->error_code,
        b->write_enabled);
    println(line);
    std::snprintf(
        line,
        sizeof(line),
        "ident   %s  %s",
        b->product_version,
        b->sha256_hex);
    println(line);
    std::snprintf(
        line,
        sizeof(line),
        "sample  tag=%d idx=%d countries=%d started=%u read=%u division=%u org_valid=%u seq=%llu",
        b->player_tag,
        b->country_index,
        b->country_count,
        b->game_started,
        b->read_ok,
        b->division_ok,
        b->org_valid,
        static_cast<unsigned long long>(b->snapshot_sequence));
    println(line);
    std::snprintf(
        line,
        sizeof(line),
        "army    id=%d gen=%u province=%d org=%.3f hp=%.1f armies=%d located=%d",
        b->division_id,
        b->division_generation,
        b->division_province,
        static_cast<double>(b->division_organization),
        static_cast<double>(b->division_hp),
        b->diag_armies,
        b->diag_units);
    println(line);
    std::snprintf(
        line,
        sizeof(line),
        "order   attempts=%u accepted=%u result=%u pending=%d",
        b->order_attempts,
        b->order_accepted,
        b->last_order_result,
        b->pending_move_province);
    println(line);
    std::snprintf(
        line,
        sizeof(line),
        "probe   move=%u vt=%x tag=%d skip=%u mass=%u vt=%x tag=%d skip=%u vol=%u vt=%x tag=%d skip=%u org=%u vt=%x tag=%d skip=%u exec=%u skip=%u exec_vt=%x/%x/%x ag=%u vt=%x tag=%d skip=%u cfg_th=%u",
        b->land_actor_move_enters,
        b->land_actor_move_vt,
        b->land_actor_move_tag,
        b->land_actor_move_skips,
        b->land_actor_mass_enters,
        b->land_actor_mass_vt,
        b->land_actor_mass_tag,
        b->land_actor_mass_skips,
        b->land_actor_vol_enters,
        b->land_actor_vol_vt,
        b->land_actor_vol_tag,
        b->land_actor_vol_skips,
        b->land_actor_org_enters,
        b->land_actor_org_vt,
        b->land_actor_org_tag,
        b->land_actor_org_skips,
        b->land_actor_exec_enters,
        b->land_actor_exec_skips,
        b->land_actor_exec_vt0,
        b->land_actor_exec_vt1,
        b->land_actor_exec_vt2,
        b->land_actor_ag_enters,
        b->land_actor_ag_vt,
        b->land_actor_ag_tag,
        b->land_actor_ag_skips,
        b->skip_theatre_ai);
    println(line);
    if (b->last_error[0] != '\0') {
        println(std::string("error   ") + b->last_error);
    }
    hoiv::ipc_close(&session);
    return 0;
}

void usage() {
    println("launcher --identify [--config path]");
    println("launcher --load [--config path]");
    println("launcher --disable");
    println("launcher --shutdown");
    println("launcher --status");
    println("launcher --move <邻省ID>");
    println("launcher --army");
    println("launcher --ag");
    println("只测德国采样师。瑞士 --cancel 已撤。战区/集团军群必须至少挂一个集团军。");
    println("先 --army。不要对唯一的集团军发 --ag。");
    println("只改 tools\\launcher\\config.ini。build\\config.ini 不读。");
    println("默认: enabled=0, read_only=1, max_orders_per_hour=0");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    const std::wstring config_path = config_path_from_args(argc, argv);
    hoiv::RuntimeConfig cfg = hoiv::default_runtime_config();
    std::string error;
    const bool have_config = hoiv::load_runtime_config(config_path, &cfg, &error);
    println(std::string("config ") + hoiv::narrow(config_path));
    const std::wstring log_dir = cfg.log_dir.empty() ? hoiv::sibling_path(L"logs") : cfg.log_dir;
    hoiv::log_open(hoiv::join_path(log_dir, L"launcher.log"), "launcher");

    if (argc < 2) {
        usage();
        if (have_config && cfg.exe_path.empty()) {
            cfg.exe_path = guess_hoi4_path();
        }
        if (have_config && !cfg.exe_path.empty()) {
            return identify(cfg);
        }
        hoiv::log_close();
        return 1;
    }

    const std::wstring action = argv[1];
    int code = 1;
    if (action == L"--identify") {
        if (!have_config) {
            println(error);
            code = 2;
        } else {
            if (cfg.exe_path.empty()) {
                cfg.exe_path = guess_hoi4_path();
            }
            code = identify(cfg);
        }
    } else if (action == L"--load") {
        if (!have_config) {
            println(error);
            code = 2;
        } else {
            code = run_load(cfg);
        }
    } else if (action == L"--disable" || action == L"--shutdown") {
        code = run_signal(action.c_str());
    } else if (action == L"--status") {
        code = run_status();
    } else if (action == L"--move") {
        code = run_move(argc, argv);
    } else if (action == L"--army") {
        code = run_org(hoiv::Request::TestArmy, "army   ");
    } else if (action == L"--ag") {
        code = run_org(hoiv::Request::TestArmyGroup, "ag     ");
    } else if (action == L"--cancel") {
        code = run_cancel();
    } else if (action == L"--no-land-ai") {
        code = run_no_land_ai();
    } else {
        usage();
    }

    hoiv::log_close();
    return code;
}
