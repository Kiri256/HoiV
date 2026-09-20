#pragma once

#include <cstdint>

namespace hoiv {

inline constexpr uint32_t kSchemaVersion = 10;
inline constexpr uint32_t kSharedMagic = 0x56494F48u;  // 'HOIV'
inline constexpr uint32_t kSharedBlockBytes = 4096;

enum class ErrorCode : uint32_t {
    Ok = 0,
    SchemaMismatch = 1,
    VersionNotPinned = 2,
    HashMismatch = 3,
    VersionMismatch = 4,
    PeTimestampMismatch = 5,
    BlackiceMismatch = 6,
    IdentityReadFailed = 7,
    WrongProcess = 8,
    AlreadyInitialized = 9,
    NotInitialized = 10,
    ConfigDisabled = 11,
    WriteDisabled = 12,
    IpcFailed = 13,
    HookRejected = 14,
    UnloadFailed = 15,
    InternalError = 16,
    SignatureFailed = 17,
    ReadUnreliable = 18,
};

enum class Request : uint32_t {
    None = 0,
    Disable = 1,
    Shutdown = 2,
    TestMove = 3,
    TestCancel = 4,
    SuppressLandAi = 5,
    TestArmy = 6,
    TestArmyGroup = 7,
};

enum class OrderResult : uint32_t {
    None = 0,
    Gated = 1,
    SignatureFailed = 2,
    CanExecuteFalse = 3,
    Submitted = 4,
    Fault = 5,
    BadTarget = 6,
    NoArmy = 7,
    Cancelled = 8,
    LandAiOff = 9,
};

#pragma pack(push, 1)
struct SharedBlock {
    uint32_t magic;
    uint32_t schema_version;
    uint32_t struct_size;
    uint32_t reserved0;

    wchar_t exe_path[260];
    wchar_t blackice_descriptor[260];
    char expected_sha256_hex[65];
    char expected_product_version[32];
    char expected_blackice_version[32];
    char adapter_id[32];
    uint32_t expected_pe_timestamp;
    uint8_t enabled;
    uint8_t read_only;
    uint8_t allow_test_host;
    uint8_t reserved1;
    uint32_t max_orders_per_hour;

    volatile uint32_t initialized;
    volatile uint32_t version_ok;
    volatile uint32_t hooks_installed;
    volatile uint32_t hook_install_calls;
    volatile uint32_t hook_actual_installs;
    volatile uint32_t write_enabled;
    volatile uint32_t disabled;
    volatile uint32_t planner_connected;
    volatile uint32_t error_code;
    volatile uint32_t request;

    uint64_t module_handle;
    uint32_t pe_timestamp;
    uint32_t reserved2;
    char product_version[32];
    char blackice_version[32];
    char sha256_hex[65];
    char last_error[192];

    volatile uint32_t read_ok;
    volatile uint32_t division_ok;
    volatile uint32_t org_valid;
    volatile uint32_t game_started;
    int32_t player_tag;
    int32_t country_count;
    int32_t country_index;
    int32_t division_id;
    uint32_t division_generation;
    int32_t division_province;
    float division_organization;
    uint32_t snapshot_tick_ms;
    uint64_t snapshot_sequence;
    volatile uint32_t hook_enter_count;
    uint32_t diag_vt_ok;
    uint32_t diag_tag_nz;
    int32_t diag_vote_idx;
    uint32_t diag_vote_n;
    uint32_t diag_actor_rva;
    int32_t diag_armies;
    int32_t diag_units;
    int64_t diag_org_current;
    int64_t diag_org_max;
    int64_t diag_hp_current;
    int64_t diag_hp_max;
    float division_hp;
    char player_tag_text[8];
    int32_t pending_move_province;
    uint32_t order_attempts;
    uint32_t order_accepted;
    uint32_t last_order_result;
    uint32_t land_ai_off_count;
    uint8_t land_ai_global;
    uint8_t land_ai_path;
    uint8_t skip_theatre_ai;
    uint8_t reserved3;
    uint32_t land_actor_move_enters;
    uint32_t land_actor_mass_enters;
    uint32_t land_actor_exec_enters;
    int32_t land_actor_exec_tag;
    uint32_t land_actor_exec_vt0;
    uint32_t land_actor_exec_vt1;
    uint32_t land_actor_exec_vt2;
    uint32_t land_actor_mass_vt;
    int32_t land_actor_mass_tag;
    uint32_t land_actor_move_vt;
    int32_t land_actor_move_tag;
    uint32_t land_actor_mass_skips;
    uint32_t land_actor_move_skips;
    uint32_t land_actor_vol_enters;
    uint32_t land_actor_vol_vt;
    int32_t land_actor_vol_tag;
    uint32_t land_actor_vol_skips;
    uint32_t land_actor_org_enters;
    uint32_t land_actor_org_vt;
    int32_t land_actor_org_tag;
    uint32_t land_actor_org_skips;
    uint32_t land_actor_exec_skips;
    uint32_t land_actor_ag_enters;
    uint32_t land_actor_ag_vt;
    int32_t land_actor_ag_tag;
    uint32_t land_actor_ag_skips;
};

inline constexpr uint8_t kLandAiPathNone = 0;
inline constexpr uint8_t kLandAiPathOrderLock = 1;
inline constexpr uint8_t kLandAiPathMoveGate = 2;
inline constexpr uint8_t kLandAiPathGeneral = 3;
inline constexpr uint8_t kLandAiPathOrgCreate = 4;
#pragma pack(pop)

static_assert(sizeof(SharedBlock) <= kSharedBlockBytes, "SharedBlock exceeds mapping size");

inline constexpr const char* kIpcMutexName = "Local\\HoiV.Bridge.Mutex";
inline constexpr const char* kIpcMappingName = "Local\\HoiV.Bridge.Session";
inline constexpr const char* kIpcReadyEventName = "Local\\HoiV.Bridge.Ready";
inline constexpr const char* kIpcDisableEventName = "Local\\HoiV.Bridge.Disable";
inline constexpr const char* kIpcShutdownEventName = "Local\\HoiV.Bridge.Shutdown";
inline constexpr const char* kIpcDisabledEventName = "Local\\HoiV.Bridge.Disabled";

}  // namespace hoiv
