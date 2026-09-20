#include "../../include/game_reader.hpp"

#include "../../../adapters/hoi4_1_19_blackice_12_1/read_model.hpp"
#include "../../../shared/schema/schema.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(__GNUC__)
#define HOIV_MSABI __attribute__((ms_abi))
#else
#define HOIV_MSABI
#endif

namespace hoiv {
namespace {

using adapter::is_canonical_user_pointer;
using adapter::is_known_gamestate_vtable;
using adapter::pdx_array_bounds_ok;
using adapter::tag_matches;

SharedBlock* g_block = nullptr;
uint8_t* g_module_base = nullptr;
uint32_t g_module_size = 0;
uint8_t g_saved_get_player[adapter::kGetPlayerHookBytes] {};
uint8_t g_saved_move_can[adapter::kMoveCanExecuteHookBytes] {};
uint8_t g_saved_move_do[adapter::kMoveExecuteHookBytes] {};
uint8_t g_saved_general_tick[adapter::kCAIGeneralTickHookBytes] {};
uint8_t g_saved_front_factory[adapter::kFrontFactoryHookBytes] {};
uint8_t g_saved_front_tick[adapter::kFrontTickHookBytes] {};
uint8_t g_saved_ag_factory[adapter::kArmyGroupFactoryHookBytes] {};
uint8_t g_saved_mil_create[adapter::kMilitaryMinisterCreateHookBytes] {};
uint8_t g_saved_probe_move[adapter::kLandActorMoveHookBytes] {};
uint8_t g_saved_probe_mass[adapter::kLandActorMassHookBytes] {};
uint8_t g_saved_mass_move_can[adapter::kCMassMoveCommandCanHookBytes] {};
uint8_t g_saved_probe_exec[adapter::kLandActorExecHookBytes] {};
uint8_t g_saved_probe_vol[adapter::kCAIVolunteerGeneralTickHookBytes] {};
uint8_t g_saved_probe_org[adapter::kLandOrgHelperHookBytes] {};
uint8_t g_saved_general_org[adapter::kCAIGeneralOrgHookBytes] {};
uint8_t g_saved_theatre_can[adapter::kCSetTheatreCommandCanHookBytes] {};
uint8_t g_saved_ag_can[adapter::kCArmyGroupCommandCanHookBytes] {};
uint8_t g_saved_assign_ag_can[adapter::kCAssignToArmyGroupCommandCanHookBytes] {};
uint8_t g_saved_front_can[adapter::kCOrderNewFrontCommandCanHookBytes] {};
uint8_t g_saved_theatre_ai[adapter::kTheatreAiCreateHookBytes] {};
uint8_t g_saved_theatre_gate[adapter::kTheatreCreateGateHookBytes] {};
uint8_t g_saved_theatre_ctor[adapter::kCTheatreCtorHookBytes] {};
uint8_t g_saved_area_def_ai[adapter::kAreaDefenseAiHookBytes] {};
uint8_t g_saved_ag_ai[adapter::kArmyGroupAiHookBytes] {};
uint8_t g_saved_army_ai[adapter::kArmyAiHookBytes] {};
uint8_t g_saved_army_ai2[adapter::kArmyAi2HookBytes] {};
uint8_t g_saved_order_group_can[adapter::kCOrderGroupCommandCanHookBytes] {};
std::atomic<bool> g_armed {false};
std::atomic<bool> g_patched {false};
std::atomic<bool> g_iat_patched {false};
std::atomic<bool> g_move_patched {false};
std::atomic<bool> g_general_patched {false};
std::atomic<bool> g_org_patched {false};
std::atomic<bool> g_probe_patched {false};
using PeekMessageWFn = BOOL (WINAPI*)(LPMSG, HWND, UINT, UINT, UINT);
PeekMessageWFn g_orig_peek_message = nullptr;
uint64_t* g_peek_iat = nullptr;
std::atomic<uint32_t> g_last_capture_ms {0};
int32_t g_track_id = 0;
int32_t g_track_gen = 0;
std::atomic<bool> g_hold_land_ai {false};
std::atomic<bool> g_land_ai_general {false};
std::atomic<bool> g_land_ai_org_create {false};
struct LandLockDiag {
    uint8_t ai = 0;
    uint8_t mil = 0;
    int32_t gen = -1;
    int32_t fronts = -1;
};
LandLockDiag g_land_diag {};
using GeneralTickFn = void(HOIV_MSABI*)(void*);
GeneralTickFn g_orig_general_tick = nullptr;
uint8_t* g_general_tick_tramp = nullptr;
using FrontFactoryFn = void(HOIV_MSABI*)(void*, void*, uint32_t);
FrontFactoryFn g_orig_front_factory = nullptr;
uint8_t* g_front_factory_tramp = nullptr;
using FrontTickFn = void(HOIV_MSABI*)(void*, void*);
FrontTickFn g_orig_front_tick = nullptr;
uint8_t* g_front_tick_tramp = nullptr;
using ArmyGroupFactoryFn = uint64_t(HOIV_MSABI*)(void*, void*, void*, void*);
ArmyGroupFactoryFn g_orig_ag_factory = nullptr;
uint8_t* g_ag_factory_tramp = nullptr;
using MinisterCreateFn = void(HOIV_MSABI*)(void*);
MinisterCreateFn g_orig_mil_create = nullptr;
uint8_t* g_mil_create_tramp = nullptr;
using LandActorProbeFn = uint64_t(HOIV_MSABI*)(void*, void*, void*, void*);
LandActorProbeFn g_orig_probe_move = nullptr;
LandActorProbeFn g_orig_probe_mass = nullptr;
LandActorProbeFn g_orig_probe_exec = nullptr;
LandActorProbeFn g_orig_probe_org = nullptr;
LandActorProbeFn g_orig_general_org = nullptr;
GeneralTickFn g_orig_probe_vol = nullptr;
using MassMoveCanFn = uint8_t(HOIV_MSABI*)(void*);
MassMoveCanFn g_orig_mass_move_can = nullptr;
using OrgCommandCanFn = uint8_t(HOIV_MSABI*)(void*);
OrgCommandCanFn g_orig_theatre_can = nullptr;
OrgCommandCanFn g_orig_ag_can = nullptr;
OrgCommandCanFn g_orig_assign_ag_can = nullptr;
OrgCommandCanFn g_orig_front_can = nullptr;
OrgCommandCanFn g_orig_order_group_can = nullptr;
LandActorProbeFn g_orig_theatre_ai = nullptr;
LandActorProbeFn g_orig_theatre_gate = nullptr;
LandActorProbeFn g_orig_theatre_ctor = nullptr;
LandActorProbeFn g_orig_area_def_ai = nullptr;
LandActorProbeFn g_orig_ag_ai = nullptr;
LandActorProbeFn g_orig_army_ai = nullptr;
LandActorProbeFn g_orig_army_ai2 = nullptr;
uint8_t* g_probe_move_tramp = nullptr;
uint8_t* g_probe_mass_tramp = nullptr;
uint8_t* g_probe_exec_tramp = nullptr;
uint8_t* g_probe_vol_tramp = nullptr;
uint8_t* g_probe_org_tramp = nullptr;
uint8_t* g_general_org_tramp = nullptr;
uint8_t* g_mass_move_can_tramp = nullptr;
uint8_t* g_theatre_can_tramp = nullptr;
uint8_t* g_ag_can_tramp = nullptr;
uint8_t* g_assign_ag_can_tramp = nullptr;
uint8_t* g_front_can_tramp = nullptr;
uint8_t* g_theatre_ai_tramp = nullptr;
uint8_t* g_theatre_gate_tramp = nullptr;
uint8_t* g_theatre_ctor_tramp = nullptr;
uint8_t* g_area_def_ai_tramp = nullptr;
uint8_t* g_ag_ai_tramp = nullptr;
uint8_t* g_army_ai_tramp = nullptr;
uint8_t* g_army_ai2_tramp = nullptr;
uint8_t* g_order_group_can_tramp = nullptr;
std::atomic<uint32_t> g_probe_move_enters {0};
std::atomic<uint32_t> g_probe_mass_enters {0};
std::atomic<uint32_t> g_probe_exec_enters {0};
std::atomic<uint32_t> g_probe_vol_enters {0};
std::atomic<int32_t> g_probe_exec_tag {0};
std::atomic<uint32_t> g_probe_exec_vt0 {0};
std::atomic<uint32_t> g_probe_exec_vt1 {0};
std::atomic<uint32_t> g_probe_exec_vt2 {0};
std::atomic<uint32_t> g_probe_mass_vt {0};
std::atomic<int32_t> g_probe_mass_tag {0};
std::atomic<uint32_t> g_probe_move_vt {0};
std::atomic<int32_t> g_probe_move_tag {0};
std::atomic<uint32_t> g_probe_mass_skips {0};
std::atomic<uint32_t> g_probe_move_skips {0};
std::atomic<uint32_t> g_probe_vol_vt {0};
std::atomic<int32_t> g_probe_vol_tag {0};
std::atomic<uint32_t> g_probe_vol_skips {0};
std::atomic<uint32_t> g_probe_org_enters {0};
std::atomic<uint32_t> g_probe_org_vt {0};
std::atomic<int32_t> g_probe_org_tag {0};
std::atomic<uint32_t> g_probe_org_skips {0};
std::atomic<uint32_t> g_probe_exec_skips {0};
std::atomic<uint32_t> g_probe_ag_enters {0};
std::atomic<uint32_t> g_probe_ag_vt {0};
std::atomic<int32_t> g_probe_ag_tag {0};
std::atomic<uint32_t> g_probe_ag_skips {0};
std::atomic<bool> g_restored_global_ai {false};
thread_local bool g_allow_our_move = false;
thread_local bool g_allow_our_org = false;
thread_local bool g_skip_german_mass_move = false;
thread_local bool g_skip_german_org_create = false;
thread_local int32_t g_org_create_tag = 0;
uint64_t g_major_handle_hash[2][adapter::kMajorHandleHashSlots] {};
std::atomic<uint32_t> g_major_handle_sel {0};
uint32_t g_last_handle_snapshot_ms = 0;

void try_submit_test_move(uint64_t army, int32_t from_province, int32_t handle_id, int32_t handle_gen);
void try_submit_test_army(uint64_t country, uint64_t army);
void try_submit_test_army_group(uint64_t country);
void try_submit_swiss_cancel(uint64_t army, int32_t handle_id, int32_t handle_gen);
uint64_t country_by_tag(const uint64_t* countries, int32_t country_size, int32_t tag);
void try_suppress_major_land_ai(uint64_t gamestate);
void hold_land_ai_if_armed(uint64_t gamestate);
void sample_land_ai_global();
void restore_global_ai_if_needed();
bool land_ai_signatures_match();
uint32_t count_major_generals(uint64_t gamestate);
bool patch_general_tick();
void restore_general_tick();
bool patch_org_create();
void restore_org_create();
bool patch_move_gate();
void restore_move_gate();
bool patch_land_actor_probes();
void restore_land_actor_probes();
void reset_land_actor_probes();

uint64_t module_va(uint32_t rva) {
    return reinterpret_cast<uint64_t>(g_module_base) + rva;
}

bool in_module(uint64_t address, uint32_t bytes) {
    const uint64_t begin = reinterpret_cast<uint64_t>(g_module_base);
    return address >= begin && address + bytes <= begin + g_module_size;
}

bool page_readable(uint64_t address, size_t bytes) {
    if (bytes == 0 || address + bytes < address) {
        return false;
    }
    MEMORY_BASIC_INFORMATION info {};
    uint64_t cursor = address;
    const uint64_t end = address + bytes;
    while (cursor < end) {
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0) {
            return false;
        }
        if (info.State != MEM_COMMIT) {
            return false;
        }
        const DWORD protect = info.Protect & 0xFF;
        if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) {
            return false;
        }
        const uint64_t region_end =
            reinterpret_cast<uint64_t>(info.BaseAddress) + info.RegionSize;
        if (region_end <= cursor) {
            return false;
        }
        cursor = region_end;
    }
    return true;
}

bool user_object(uint64_t address) {
    return is_canonical_user_pointer(address) && page_readable(address, 8);
}

bool vtable_in_image(uint64_t object) {
    if (!user_object(object) || !page_readable(object, 16) || g_module_base == nullptr) {
        return false;
    }
    const uint64_t vtable = *reinterpret_cast<const uint64_t*>(object);
    return in_module(vtable, 8);
}

bool rtti_is(uint64_t object, const char* name) {
    if (name == nullptr || !vtable_in_image(object)) {
        return false;
    }
    const uint64_t vtable = *reinterpret_cast<const uint64_t*>(object);
    if (vtable < reinterpret_cast<uint64_t>(g_module_base) + 8 || !page_readable(vtable - 8, 8)) {
        return false;
    }
    const uint64_t col = *reinterpret_cast<const uint64_t*>(vtable - 8);
    if (!in_module(col, 24) || !page_readable(col, 24)) {
        return false;
    }
    if (*reinterpret_cast<const uint32_t*>(col) != 1) {
        return false;
    }
    const uint32_t td_rva = *reinterpret_cast<const uint32_t*>(col + 12);
    const uint64_t name_addr = reinterpret_cast<uint64_t>(g_module_base) + td_rva + 16;
    const size_t n = std::strlen(name);
    return in_module(name_addr, n + 1) && page_readable(name_addr, n + 1) &&
        std::memcmp(reinterpret_cast<const void*>(name_addr), name, n + 1) == 0;
}

int32_t index_of_country(uint64_t pointer, const uint64_t* countries, int32_t country_size) {
    if (pointer == 0 || countries == nullptr) {
        return -1;
    }
    for (int32_t i = 0; i < country_size; ++i) {
        if (countries[i] == pointer) {
            return i;
        }
    }
    return -1;
}

bool copy_letter_tag(uint64_t object, uint32_t offset, char* out, size_t out_n) {
    if (out == nullptr || out_n < 4 || !page_readable(object + offset, 4)) {
        return false;
    }
    char tmp[4] {};
    std::memcpy(tmp, reinterpret_cast<const void*>(object + offset), 4);
    if (!adapter::is_three_letter_tag(tmp)) {
        return false;
    }
    std::memset(out, 0, out_n);
    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    return true;
}

int32_t country_index_for_tag(
    int32_t tag,
    const uint64_t* countries,
    int32_t country_size) {
    if (!adapter::country_tag_usable(tag) || countries == nullptr) {
        return -1;
    }
    int32_t found = -1;
    for (int32_t i = 0; i < country_size; ++i) {
        if (!page_readable(countries[i] + adapter::kCountryTagOffset, 4)) {
            continue;
        }
        const int32_t country_tag =
            *reinterpret_cast<const int32_t*>(countries[i] + adapter::kCountryTagOffset);
        if (country_tag != tag) {
            continue;
        }
        if (found >= 0) {
            return -1;
        }
        found = i;
    }
    return found;
}

int32_t resolve_player_pointer(
    uint64_t pointer,
    const uint64_t* countries,
    int32_t country_size) {
    const int32_t direct = index_of_country(pointer, countries, country_size);
    if (direct > 0) {
        return direct;
    }
    if (!vtable_in_image(pointer)) {
        if (page_readable(pointer, 4)) {
            return country_index_for_tag(
                *reinterpret_cast<const int32_t*>(pointer), countries, country_size);
        }
        return -1;
    }
    if (rtti_is(pointer, adapter::kRttiCountry)) {
        return -1;
    }
    for (uint32_t off = 0x08; off + 8 <= 0x0400; off += 8) {
        if (!page_readable(pointer + off, 8)) {
            break;
        }
        const int32_t idx = index_of_country(
            *reinterpret_cast<const uint64_t*>(pointer + off), countries, country_size);
        if (idx > 0) {
            return idx;
        }
    }
    if (page_readable(pointer + adapter::kCountryTagOffset, 4) &&
        rtti_is(pointer, adapter::kRttiHuman)) {
        return country_index_for_tag(
            *reinterpret_cast<const int32_t*>(pointer + adapter::kCountryTagOffset),
            countries,
            country_size);
    }
    return -1;
}

int32_t scan_object_for_country(
    uint64_t object,
    uint32_t begin,
    uint32_t end,
    const uint64_t* countries,
    int32_t country_size,
    uint32_t* match_off) {
    if (!user_object(object) || countries == nullptr) {
        return -1;
    }
    int32_t found = -1;
    uint32_t found_off = 0;
    for (uint32_t off = begin; off + 8 <= end; off += 8) {
        if (!page_readable(object + off, 8)) {
            break;
        }
        const int32_t idx = resolve_player_pointer(
            *reinterpret_cast<const uint64_t*>(object + off), countries, country_size);
        if (idx <= 0) {
            continue;
        }
        if (found >= 0 && found != idx) {
            return -1;
        }
        found = idx;
        found_off = off;
    }
    if (found > 0 && match_off != nullptr) {
        *match_off = found_off;
    }
    return found;
}

int32_t scan_object_for_tag(
    uint64_t object,
    uint32_t begin,
    uint32_t end,
    const uint64_t* countries,
    int32_t country_size,
    uint32_t* match_off) {
    if (!user_object(object) || countries == nullptr) {
        return -1;
    }
    int32_t votes[adapter::kMaxCountries] {};
    uint32_t first_off[adapter::kMaxCountries] {};
    for (uint32_t off = begin; off + 4 <= end; off += 4) {
        if (!page_readable(object + off, 4)) {
            break;
        }
        const int32_t idx = country_index_for_tag(
            *reinterpret_cast<const int32_t*>(object + off), countries, country_size);
        if (idx <= 0 || idx >= adapter::kMaxCountries) {
            continue;
        }
        if (votes[idx] == 0) {
            first_off[idx] = off;
        }
        ++votes[idx];
    }
    int32_t best = -1;
    int32_t best_n = 0;
    for (int32_t i = 1; i < country_size && i < adapter::kMaxCountries; ++i) {
        if (votes[i] > best_n) {
            best_n = votes[i];
            best = i;
        }
    }
    if (best_n < 2) {
        return -1;
    }
    int32_t runners = 0;
    for (int32_t i = 1; i < country_size && i < adapter::kMaxCountries; ++i) {
        if (votes[i] == best_n) {
            ++runners;
        }
    }
    if (runners != 1) {
        return -1;
    }
    if (match_off != nullptr) {
        *match_off = first_off[best];
    }
    return best;
}

bool read_pdx_array(uint64_t object, uint32_t offset, int32_t max_size, uint64_t* data_out, int32_t* size_out) {
    if (data_out == nullptr || size_out == nullptr) {
        return false;
    }
    *data_out = 0;
    *size_out = 0;
    if (!user_object(object) || !page_readable(object + offset, adapter::kPdxArrayBytes)) {
        return false;
    }
    const uint8_t* base = reinterpret_cast<const uint8_t*>(object);
    const uint64_t data = *reinterpret_cast<const uint64_t*>(base + offset + adapter::kPdxArrayData);
    const int32_t capacity = *reinterpret_cast<const int32_t*>(base + offset + adapter::kPdxArrayCapacity);
    const int32_t size = *reinterpret_cast<const int32_t*>(base + offset + adapter::kPdxArraySize);
    if (!pdx_array_bounds_ok(size, capacity, max_size)) {
        return false;
    }
    if (size > 0 &&
        (!user_object(data) || !page_readable(data, static_cast<size_t>(size) * sizeof(uint64_t)))) {
        return false;
    }
    *data_out = data;
    *size_out = size;
    return true;
}

bool array_elements_match(uint64_t data, int32_t size, const char* rtti_name) {
    if (size <= 0 || rtti_name == nullptr) {
        return false;
    }
    const uint64_t* items = reinterpret_cast<const uint64_t*>(data);
    for (int32_t i = 0; i < size; ++i) {
        if (!rtti_is(items[i], rtti_name)) {
            return false;
        }
    }
    return true;
}

bool array_elements_in_image(uint64_t data, int32_t size) {
    if (size <= 0) {
        return false;
    }
    const uint64_t* items = reinterpret_cast<const uint64_t*>(data);
    for (int32_t i = 0; i < size; ++i) {
        if (!vtable_in_image(items[i])) {
            return false;
        }
    }
    return true;
}

bool find_pointer_array(
    uint64_t object,
    uint32_t begin,
    uint32_t end,
    const char* rtti_name,
    int32_t max_size,
    uint64_t* data_out,
    int32_t* size_out) {
    uint64_t best_data = 0;
    int32_t best_size = 0;
    for (uint32_t off = begin; off + adapter::kPdxArrayBytes <= end; off += 8) {
        uint64_t data = 0;
        int32_t size = 0;
        if (!read_pdx_array(object, off, max_size, &data, &size)) {
            continue;
        }
        if (!array_elements_match(data, size, rtti_name)) {
            continue;
        }
        if (size > best_size) {
            best_data = data;
            best_size = size;
        }
    }
    if (best_size <= 0) {
        return false;
    }
    *data_out = best_data;
    *size_out = best_size;
    return true;
}

bool read_army_stat_pair(uint64_t army, uint32_t current_off, uint32_t max_off, int64_t* current, int64_t* maximum) {
    if (current == nullptr || maximum == nullptr) {
        return false;
    }
    *current = 0;
    *maximum = 0;
    if (!vtable_in_image(army) ||
        !page_readable(army + current_off, 8) ||
        !page_readable(army + adapter::kArmyStatsPointerOffset, 8)) {
        return false;
    }
    const uint64_t stats =
        *reinterpret_cast<const uint64_t*>(army + adapter::kArmyStatsPointerOffset);
    if (!is_canonical_user_pointer(stats) || !page_readable(stats + max_off, 8)) {
        return false;
    }
    *current = *reinterpret_cast<const int64_t*>(army + current_off);
    *maximum = *reinterpret_cast<const int64_t*>(stats + max_off);
    return *current >= 0 && *maximum >= 0;
}

bool read_army_handle(uint64_t army, int32_t* id, int32_t* gen) {
    if (id == nullptr || gen == nullptr ||
        !page_readable(army + adapter::kArmyHandleOffset, 8)) {
        return false;
    }
    *id = *reinterpret_cast<const int32_t*>(army + adapter::kArmyHandleOffset);
    *gen = *reinterpret_cast<const int32_t*>(army + adapter::kArmyHandleOffset + 4);
    return adapter::army_handle_usable(*id, *gen);
}

int32_t read_province(uint64_t unit) {
    if (!vtable_in_image(unit) || !page_readable(unit, adapter::kUnitLocationOffset + 8)) {
        return 0;
    }
    const uint64_t location =
        *reinterpret_cast<const uint64_t*>(unit + adapter::kUnitLocationOffset);
    if (!vtable_in_image(location) ||
        !page_readable(location, adapter::kProvinceIdOffset + 4)) {
        return 0;
    }
    const int32_t province =
        *reinterpret_cast<const int32_t*>(location + adapter::kProvinceIdOffset);
    return province > 0 && province < 20000 ? province : 0;
}

bool pick_units_from_array(
    uint64_t data,
    int32_t size,
    int32_t* division_id,
    int32_t* province,
    int32_t* located) {
    if (data == 0 || size <= 0) {
        return false;
    }
    const uint64_t* units = reinterpret_cast<const uint64_t*>(data);
    int32_t with_province = 0;
    for (int32_t i = 0; i < size; ++i) {
        const int32_t prov = read_province(units[i]);
        if (prov == 0) {
            continue;
        }
        ++with_province;
        if (*division_id == 0) {
            *division_id = i + 1;
            *province = prov;
        }
    }
    if (located != nullptr) {
        *located += with_province;
    }
    return *division_id != 0;
}

bool find_any_pointer_array(
    uint64_t object,
    uint32_t begin,
    uint32_t end,
    int32_t max_size,
    uint64_t* data_out,
    int32_t* size_out) {
    uint64_t best_data = 0;
    int32_t best_size = 0;
    int32_t best_located = 0;
    for (uint32_t off = begin; off + adapter::kPdxArrayBytes <= end; off += 8) {
        uint64_t data = 0;
        int32_t size = 0;
        if (!read_pdx_array(object, off, max_size, &data, &size) ||
            !array_elements_in_image(data, size)) {
            continue;
        }
        int32_t dummy_id = 0;
        int32_t dummy_prov = 0;
        int32_t located = 0;
        pick_units_from_array(data, size, &dummy_id, &dummy_prov, &located);
        if (located > best_located || (located == best_located && size > best_size && located > 0)) {
            best_data = data;
            best_size = size;
            best_located = located;
        }
    }
    if (best_located <= 0) {
        return false;
    }
    *data_out = best_data;
    *size_out = best_size;
    return true;
}

bool load_armies(uint64_t country, uint64_t* data_out, int32_t* size_out) {
    uint64_t data = 0;
    int32_t size = 0;
    if (!read_pdx_array(country, adapter::kCountryArmiesOffset, adapter::kMaxArmies, &data, &size) ||
        size <= 0) {
        return false;
    }
    *data_out = data;
    *size_out = size;
    return true;
}

bool pick_located_army(
    uint64_t data,
    int32_t size,
    int32_t want_id,
    int32_t want_gen,
    int32_t* division_id,
    int32_t* province,
    int32_t* located,
    uint64_t* unit_out) {
    if (data == 0 || size <= 0 || division_id == nullptr || province == nullptr) {
        return false;
    }
    const uint64_t* units = reinterpret_cast<const uint64_t*>(data);
    uint64_t chosen = 0;
    int32_t chosen_id = 0;
    int32_t chosen_prov = 0;
    uint64_t tracked = 0;
    int32_t tracked_id = 0;
    int32_t tracked_prov = 0;
    uint64_t first = 0;
    int32_t first_id = 0;
    int32_t first_prov = 0;
    for (int32_t u = 0; u < size; ++u) {
        const int32_t prov = read_province(units[u]);
        if (prov == 0) {
            continue;
        }
        if (located != nullptr) {
            ++*located;
        }
        int32_t handle_id = 0;
        int32_t handle_gen = 0;
        const bool have_handle = read_army_handle(units[u], &handle_id, &handle_gen);
        if (have_handle && adapter::army_handle_match(handle_id, handle_gen, want_id, want_gen)) {
            tracked = units[u];
            tracked_id = handle_id;
            tracked_prov = prov;
        }
        if (first == 0 && have_handle && adapter::army_handle_usable(handle_id, handle_gen)) {
            first = units[u];
            first_id = handle_id;
            first_prov = prov;
        }
    }
    if (tracked != 0) {
        chosen = tracked;
        chosen_id = tracked_id;
        chosen_prov = tracked_prov;
    } else {
        chosen = first;
        chosen_id = first_id;
        chosen_prov = first_prov;
    }
    *division_id = chosen_id;
    *province = chosen_prov;
    if (unit_out != nullptr) {
        *unit_out = chosen;
    }
    return chosen != 0;
}

bool capture_from_gamestate(uint64_t gamestate, adapter::LiveRead* out) {
    *out = {};
    SharedBlock* retired = g_block;
    if (retired != nullptr && retired->request == static_cast<uint32_t>(Request::TestCancel)) {
        retired->last_order_result = static_cast<uint32_t>(OrderResult::Gated);
        retired->request = static_cast<uint32_t>(Request::None);
    }
    if (!user_object(gamestate) ||
        !page_readable(gamestate, adapter::kPlayerTagOffset + 16)) {
        return false;
    }
    const uint64_t vtable = *reinterpret_cast<const uint64_t*>(gamestate);
    if (!is_known_gamestate_vtable(vtable, reinterpret_cast<uint64_t>(g_module_base))) {
        return false;
    }

    const uint8_t started = *reinterpret_cast<const uint8_t*>(gamestate + adapter::kGameReadyOffset);
    out->game_started = started != 0 ? 1 : 0;
    out->player_tag = *reinterpret_cast<const int32_t*>(gamestate + adapter::kPlayerTagOffset);
    adapter::format_country_tag(static_cast<uint32_t>(out->player_tag), out->tag_text, sizeof(out->tag_text));

    const uint64_t country_data =
        *reinterpret_cast<const uint64_t*>(gamestate + adapter::kCountryArrayDataOffset);
    const int32_t country_cap =
        *reinterpret_cast<const int32_t*>(gamestate + adapter::kCountryArrayCapacityOffset);
    const int32_t country_size =
        *reinterpret_cast<const int32_t*>(gamestate + adapter::kCountryArraySizeOffset);
    if (!pdx_array_bounds_ok(country_size, country_cap, adapter::kMaxCountries) ||
        (country_size > 0 && !user_object(country_data))) {
        return false;
    }
    out->country_count = country_size;
    if (country_size <= 0) {
        return true;
    }

    const uint64_t* countries = reinterpret_cast<const uint64_t*>(country_data);

    const uint64_t idler_slot = module_va(adapter::kCGameIdlerSingletonRva);
    if (page_readable(idler_slot, 8)) {
        const uint64_t idler = *reinterpret_cast<const uint64_t*>(idler_slot);
        if (user_object(idler) && page_readable(idler, 8)) {
            const uint64_t idler_vt = *reinterpret_cast<const uint64_t*>(idler);
            if (in_module(idler_vt, 8)) {
                out->diag_actor_rva =
                    static_cast<uint32_t>(idler_vt - reinterpret_cast<uint64_t>(g_module_base));
            }
        }
    }

    out->diag_vote_idx = -1;
    out->diag_vote_n = 0;

    int32_t found = -1;
    uint64_t country = 0;
    int32_t army_id = 0;
    int32_t army_prov = 0;
    int32_t army_units = 0;
    int32_t army_count = 0;
    uint64_t unit = 0;
    int32_t handle_gen = 0;
    const int32_t sample_tag = adapter::kLiveSampleCountryTag;
    const uint64_t sample = country_by_tag(countries, country_size, sample_tag);
    if (sample != 0) {
        found = sample_tag;
        country = sample;
        uint64_t army_data = 0;
        int32_t army_size = 0;
        if (load_armies(country, &army_data, &army_size)) {
            army_count = army_size;
            pick_located_army(
                army_data,
                army_size,
                g_track_id,
                g_track_gen,
                &army_id,
                &army_prov,
                &army_units,
                &unit);
            if (unit != 0 && page_readable(unit, 8)) {
                const uint64_t unit_vt = *reinterpret_cast<const uint64_t*>(unit);
                if (in_module(unit_vt, 8)) {
                    out->diag_vote_n =
                        static_cast<uint32_t>(unit_vt - reinterpret_cast<uint64_t>(g_module_base));
                }
                int64_t org_cur = 0;
                int64_t org_max = 0;
                int64_t hp_cur = 0;
                int64_t hp_max = 0;
                if (read_army_stat_pair(
                        unit,
                        adapter::kArmyOrgCurrentOffset,
                        adapter::kArmyStatsMaxOrgOffset,
                        &org_cur,
                        &org_max) &&
                    adapter::army_stat_ratio(org_cur, org_max, &out->organization)) {
                    out->org_current = org_cur;
                    out->org_max = org_max;
                    out->org_valid = 1;
                }
                if (read_army_stat_pair(
                        unit,
                        adapter::kArmyHpCurrentOffset,
                        adapter::kArmyStatsMaxHpOffset,
                        &hp_cur,
                        &hp_max)) {
                    out->hp_current = hp_cur;
                    out->hp_max = hp_max;
                    out->hp = static_cast<float>(adapter::fixed_point_to_display(hp_cur));
                }
                int32_t handle_id = 0;
                int32_t read_gen = 0;
                if (read_army_handle(unit, &handle_id, &read_gen)) {
                    army_id = handle_id;
                    handle_gen = read_gen;
                    out->division_generation = read_gen;
                    if (g_track_id == 0) {
                        g_track_id = handle_id;
                        g_track_gen = read_gen;
                    }
                }
            }
        }
    }
    out->diag_armies = army_count;
    out->diag_units = army_units;

    if (found != sample_tag || country == 0) {
        try_submit_test_move(0, 0, 0, 0);
        try_submit_test_army(0, 0);
        try_submit_test_army_group(0);
        return true;
    }
    out->country_ok = 1;
    out->country_index = found;
    if (page_readable(country, adapter::kCountryTagOffset + 4)) {
        const int32_t tag =
            *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
        if (adapter::country_tag_usable(tag)) {
            out->player_tag = tag;
        }
        adapter::format_country_tag(
            static_cast<uint32_t>(out->player_tag), out->tag_text, sizeof(out->tag_text));
    }
    if (army_prov != 0) {
        out->division_ok = 1;
        out->division_id = army_id;
        out->division_province = army_prov;
    }
    try_submit_test_move(unit, army_prov, army_id, handle_gen);
    try_submit_test_army(country, unit);
    try_submit_test_army_group(country);
    return true;
}

void publish(const adapter::LiveRead& read) {
    SharedBlock* block = g_block;
    if (block == nullptr) {
        return;
    }
    block->game_started = read.game_started;
    block->read_ok = read.country_ok;
    block->division_ok = read.division_ok;
    block->org_valid = read.org_valid;
    block->player_tag = read.player_tag;
    block->country_count = read.country_count;
    block->country_index = read.country_index;
    block->division_id = read.division_id;
    block->division_generation = static_cast<uint32_t>(read.division_generation);
    block->division_province = read.division_province;
    block->division_organization = read.organization;
    block->diag_org_current = read.org_current;
    block->diag_org_max = read.org_max;
    block->diag_hp_current = read.hp_current;
    block->diag_hp_max = read.hp_max;
    block->division_hp = read.hp;
    std::memcpy(block->player_tag_text, read.tag_text, sizeof(block->player_tag_text));
    block->diag_vt_ok = read.diag_vt_ok;
    block->diag_tag_nz = read.diag_tag_nz;
    block->diag_vote_idx = read.diag_vote_idx;
    block->diag_vote_n = read.diag_vote_n;
    block->diag_actor_rva = read.diag_actor_rva;
    block->diag_armies = read.diag_armies;
    block->diag_units = read.diag_units;
    block->land_actor_move_enters = g_probe_move_enters.load(std::memory_order_relaxed);
    block->land_actor_mass_enters = g_probe_mass_enters.load(std::memory_order_relaxed);
    block->land_actor_exec_enters = g_probe_exec_enters.load(std::memory_order_relaxed);
    block->land_actor_exec_tag = g_probe_exec_tag.load(std::memory_order_relaxed);
    block->land_actor_exec_vt0 = g_probe_exec_vt0.load(std::memory_order_relaxed);
    block->land_actor_exec_vt1 = g_probe_exec_vt1.load(std::memory_order_relaxed);
    block->land_actor_exec_vt2 = g_probe_exec_vt2.load(std::memory_order_relaxed);
    block->land_actor_mass_vt = g_probe_mass_vt.load(std::memory_order_relaxed);
    block->land_actor_mass_tag = g_probe_mass_tag.load(std::memory_order_relaxed);
    block->land_actor_move_vt = g_probe_move_vt.load(std::memory_order_relaxed);
    block->land_actor_move_tag = g_probe_move_tag.load(std::memory_order_relaxed);
    block->land_actor_mass_skips = g_probe_mass_skips.load(std::memory_order_relaxed);
    block->land_actor_move_skips = g_probe_move_skips.load(std::memory_order_relaxed);
    block->land_actor_vol_enters = g_probe_vol_enters.load(std::memory_order_relaxed);
    block->land_actor_vol_vt = g_probe_vol_vt.load(std::memory_order_relaxed);
    block->land_actor_vol_tag = g_probe_vol_tag.load(std::memory_order_relaxed);
    block->land_actor_vol_skips = g_probe_vol_skips.load(std::memory_order_relaxed);
    block->land_actor_org_enters = g_probe_org_enters.load(std::memory_order_relaxed);
    block->land_actor_org_vt = g_probe_org_vt.load(std::memory_order_relaxed);
    block->land_actor_org_tag = g_probe_org_tag.load(std::memory_order_relaxed);
    block->land_actor_org_skips = g_probe_org_skips.load(std::memory_order_relaxed);
    block->land_actor_exec_skips = g_probe_exec_skips.load(std::memory_order_relaxed);
    block->land_actor_ag_enters = g_probe_ag_enters.load(std::memory_order_relaxed);
    block->land_actor_ag_vt = g_probe_ag_vt.load(std::memory_order_relaxed);
    block->land_actor_ag_tag = g_probe_ag_tag.load(std::memory_order_relaxed);
    block->land_actor_ag_skips = g_probe_ag_skips.load(std::memory_order_relaxed);
    ++block->snapshot_sequence;
    block->snapshot_tick_ms = GetTickCount();
}

void clear_snapshot() {
    SharedBlock* block = g_block;
    if (block == nullptr) {
        return;
    }
    block->read_ok = 0;
    block->division_ok = 0;
    block->org_valid = 0;
    block->game_started = 0;
    block->player_tag = 0;
    block->country_count = 0;
    block->country_index = -1;
    block->division_id = 0;
    block->division_generation = 0;
    block->division_province = 0;
    block->division_organization = 0.0f;
    block->diag_org_current = 0;
    block->diag_org_max = 0;
    block->diag_hp_current = 0;
    block->diag_hp_max = 0;
    block->division_hp = 0.0f;
    block->hook_enter_count = 0;
    block->diag_vt_ok = 0;
    block->diag_tag_nz = 0;
    block->diag_vote_idx = -1;
    block->diag_vote_n = 0;
    block->diag_actor_rva = 0;
    block->diag_armies = 0;
    block->diag_units = 0;
    std::memset(block->player_tag_text, 0, sizeof(block->player_tag_text));
    block->pending_move_province = 0;
    block->order_attempts = 0;
    block->order_accepted = 0;
    block->last_order_result = 0;
    block->land_ai_off_count = 0;
    block->land_ai_global = 1;
    block->land_ai_path = kLandAiPathNone;
}

bool name_ends_with_ci(const char* value, const char* suffix) {
    if (value == nullptr || suffix == nullptr) {
        return false;
    }
    const size_t n = std::strlen(value);
    const size_t m = std::strlen(suffix);
    if (n < m) {
        return false;
    }
    for (size_t i = 0; i < m; ++i) {
        char a = value[n - m + i];
        char b = suffix[i];
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

uint64_t* find_iat_slot(const char* dll_suffix, const char* function_name) {
    if (g_module_base == nullptr) {
        return nullptr;
    }
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_module_base);
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_module_base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.VirtualAddress >= g_module_size) {
        return nullptr;
    }
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(g_module_base + dir.VirtualAddress);
    for (; desc->Name != 0; ++desc) {
        const char* dll = reinterpret_cast<const char*>(g_module_base + desc->Name);
        if (!name_ends_with_ci(dll, dll_suffix)) {
            continue;
        }
        const uint32_t oft_rva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;
        auto* oft = reinterpret_cast<const uint64_t*>(g_module_base + oft_rva);
        auto* iat = reinterpret_cast<uint64_t*>(g_module_base + desc->FirstThunk);
        for (int i = 0; oft[i] != 0; ++i) {
            if (oft[i] & IMAGE_ORDINAL_FLAG64) {
                continue;
            }
            auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(g_module_base + static_cast<uint32_t>(oft[i]));
            if (std::strcmp(ibn->Name, function_name) == 0) {
                return &iat[i];
            }
        }
    }
    return nullptr;
}

uint64_t load_singleton_gamestate() {
    const uint64_t slot = module_va(adapter::kCurrentGameStateRva);
    if (!page_readable(slot, 8)) {
        return 0;
    }
    return *reinterpret_cast<const uint64_t*>(slot);
}

void capture_throttled(uint64_t gamestate) {
    if (!g_armed.load(std::memory_order_acquire) || g_module_base == nullptr) {
        return;
    }
    const uint32_t now = GetTickCount();
    uint32_t last = g_last_capture_ms.load(std::memory_order_relaxed);
    const bool flush_write = g_block != nullptr &&
        (g_block->request == static_cast<uint32_t>(Request::TestMove) ||
         g_block->request == static_cast<uint32_t>(Request::TestArmy) ||
         g_block->request == static_cast<uint32_t>(Request::TestArmyGroup));
    if (!flush_write) {
        if (last != 0 && now - last < adapter::kCaptureMinIntervalMs) {
            return;
        }
        if (!g_last_capture_ms.compare_exchange_strong(last, now, std::memory_order_relaxed)) {
            return;
        }
    } else {
        g_last_capture_ms.store(now, std::memory_order_relaxed);
    }
    if (g_block != nullptr) {
        ++g_block->hook_enter_count;
    }
    if (gamestate == 0) {
        gamestate = load_singleton_gamestate();
    }
    adapter::LiveRead read {};
    if (gamestate != 0 && capture_from_gamestate(gamestate, &read)) {
        publish(read);
    } else if (g_block != nullptr) {
        g_block->read_ok = 0;
        g_block->division_ok = 0;
        ++g_block->snapshot_sequence;
    }
    restore_global_ai_if_needed();
    if (gamestate != 0) {
        try_suppress_major_land_ai(gamestate);
        hold_land_ai_if_armed(gamestate);
    }
    sample_land_ai_global();
}

extern "C" uint32_t hoiv_hook_get_player(void* gamestate) {
    capture_throttled(reinterpret_cast<uint64_t>(gamestate));
    if (gamestate != nullptr) {
        return *reinterpret_cast<const uint32_t*>(
            static_cast<const uint8_t*>(gamestate) + adapter::kPlayerTagOffset);
    }
    return 0;
}

BOOL WINAPI hoiv_hook_peek_message(
    LPMSG message,
    HWND window,
    UINT filter_min,
    UINT filter_max,
    UINT remove) {
    const BOOL result = g_orig_peek_message != nullptr
        ? g_orig_peek_message(message, window, filter_min, filter_max, remove)
        : FALSE;
    capture_throttled(0);
    return result;
}

bool resolve_module() {
    HMODULE module = GetModuleHandleW(nullptr);
    if (module == nullptr) {
        return false;
    }
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    g_module_base = reinterpret_cast<uint8_t*>(module);
    g_module_size = nt->OptionalHeader.SizeOfImage;
    return g_module_size > adapter::kGetPlayerRva + adapter::kGetPlayerHookBytes;
}

bool signatures_match() {
    if (!in_module(module_va(adapter::kGetPlayerRva), adapter::kGetPlayerHookBytes) ||
        !in_module(module_va(adapter::kGetArmiesRva), adapter::kGetArmiesByteCount) ||
        !in_module(module_va(adapter::kCurrentGameStateRva), 8) ||
        !in_module(module_va(adapter::kCGameIdlerSingletonRva), 8)) {
        return false;
    }
    const uint8_t* bytes = g_module_base + adapter::kGetPlayerRva;
    const uint8_t* armies = g_module_base + adapter::kGetArmiesRva;
    return adapter::get_player_bytes_match(bytes) && adapter::get_player_padding_safe(bytes) &&
        adapter::get_armies_bytes_match(armies);
}

bool land_ai_signatures_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kCountryAiPointerStoreRva), adapter::kCountryAiPointerStoreByteCount) ||
        !in_module(module_va(adapter::kGetAiRva), adapter::kGetAiByteCount) ||
        !in_module(module_va(adapter::kFrontFactoryRva), adapter::kFrontFactoryByteCount) ||
        !in_module(module_va(adapter::kFrontTickRva), adapter::kFrontTickByteCount) ||
        !in_module(module_va(adapter::kArmyGroupFactoryRva), adapter::kArmyGroupFactoryByteCount) ||
        !in_module(module_va(adapter::kMilitaryMinisterCreateRva), adapter::kMilitaryMinisterCreateByteCount)) {
        return false;
    }
    return adapter::country_ai_pointer_store_bytes_match(
               g_module_base + adapter::kCountryAiPointerStoreRva) &&
        adapter::get_ai_bytes_match(g_module_base + adapter::kGetAiRva) &&
        adapter::front_factory_bytes_match(g_module_base + adapter::kFrontFactoryRva) &&
        adapter::front_tick_bytes_match(g_module_base + adapter::kFrontTickRva) &&
        adapter::army_group_factory_bytes_match(g_module_base + adapter::kArmyGroupFactoryRva) &&
        adapter::military_minister_create_bytes_match(
            g_module_base + adapter::kMilitaryMinisterCreateRva);
}

bool move_signatures_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kMoveCommandRva), adapter::kMoveCommandByteCount) ||
        !in_module(module_va(adapter::kMoveCanExecuteRva), adapter::kMoveCanExecuteByteCount) ||
        !in_module(module_va(adapter::kMoveExecuteRva), adapter::kMoveExecuteByteCount)) {
        return false;
    }
    return adapter::move_ctor_bytes_match(g_module_base + adapter::kMoveCommandRva) &&
        adapter::move_can_bytes_match(g_module_base + adapter::kMoveCanExecuteRva) &&
        adapter::move_do_bytes_match(g_module_base + adapter::kMoveExecuteRva);
}

void finish_order(SharedBlock* block, OrderResult result) {
    if (block == nullptr) {
        return;
    }
    block->last_order_result = static_cast<uint32_t>(result);
    block->request = static_cast<uint32_t>(Request::None);
}

void try_submit_test_move(uint64_t army, int32_t from_province, int32_t handle_id, int32_t handle_gen) {
    SharedBlock* block = g_block;
    if (block == nullptr || block->request != static_cast<uint32_t>(Request::TestMove)) {
        return;
    }
    if (!adapter::writes_allowed(block->enabled, block->read_only, block->max_orders_per_hour) ||
        block->write_enabled == 0 || block->order_accepted != 0 ||
        block->order_attempts >= block->max_orders_per_hour) {
        finish_order(block, OrderResult::Gated);
        return;
    }
    const int32_t to = block->pending_move_province;
    if (army == 0 || !vtable_in_image(army)) {
        finish_order(block, OrderResult::NoArmy);
        return;
    }
    if (!adapter::army_handle_usable(handle_id, handle_gen) ||
        !adapter::move_target_ok(from_province, to)) {
        finish_order(block, OrderResult::BadTarget);
        return;
    }
    if (!move_signatures_match()) {
        finish_order(block, OrderResult::SignatureFailed);
        return;
    }

    using MoveCtor = void(HOIV_MSABI*)(
        void*, void*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    using CanFn = uint8_t(HOIV_MSABI*)(void*, uint32_t);
    using DoFn = void(HOIV_MSABI*)(void*);

    ++block->order_attempts;
    block->request = static_cast<uint32_t>(Request::None);

    struct OurMoveGuard {
        OurMoveGuard() {
            g_allow_our_move = true;
        }
        ~OurMoveGuard() {
            g_allow_our_move = false;
        }
    } allow_ours;

    alignas(16) uint8_t cmd[adapter::kMoveCommandBytesSize] {};
    auto ctor = reinterpret_cast<MoveCtor>(g_module_base + adapter::kMoveCommandRva);
    ctor(
        cmd,
        reinterpret_cast<void*>(army),
        static_cast<uint32_t>(to),
        adapter::kMoveCtorShiftFlag,
        adapter::kMoveCtorMode,
        0,
        0,
        0,
        0,
        0,
        0);

    void** vt = *reinterpret_cast<void***>(cmd);
    if (vt == nullptr || !in_module(reinterpret_cast<uint64_t>(vt), 88)) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    auto can = reinterpret_cast<CanFn>(vt[adapter::kMoveCommandVtableSlotCan]);
    if (can == nullptr || can(cmd, 0) == 0) {
        finish_order(block, OrderResult::CanExecuteFalse);
        return;
    }
    auto exec = reinterpret_cast<DoFn>(vt[adapter::kMoveCommandVtableSlotDo]);
    if (exec == nullptr) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    exec(cmd);
    block->order_accepted = 1;
    block->last_order_result = static_cast<uint32_t>(OrderResult::Submitted);
}

bool army_command_signatures_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kCOrderGroupCommandCtorBRva), adapter::kCOrderGroupCommandCtorBByteCount) ||
        !in_module(module_va(adapter::kCOrderGroupCommandCanRva), adapter::kCOrderGroupCommandCanByteCount)) {
        return false;
    }
    return adapter::order_group_ctor_b_bytes_match(g_module_base + adapter::kCOrderGroupCommandCtorBRva);
}

bool army_group_command_signatures_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kCArmyGroupCommandCtorBRva), adapter::kCArmyGroupCommandCtorBByteCount) ||
        !in_module(module_va(adapter::kCArmyGroupCommandCanRva), adapter::kCArmyGroupCommandCanByteCount)) {
        return false;
    }
    return adapter::army_group_ctor_b_bytes_match(g_module_base + adapter::kCArmyGroupCommandCtorBRva);
}

uint64_t object_parent(uint64_t object) {
    if (!user_object(object) ||
        !page_readable(object + adapter::kUnitParentOffset, 8)) {
        return 0;
    }
    const uint64_t parent = *reinterpret_cast<const uint64_t*>(object + adapter::kUnitParentOffset);
    if (!vtable_in_image(parent)) {
        return 0;
    }
    return parent;
}

uint64_t first_group_with_vtable(uint64_t country, uint32_t vtable_rva) {
    uint64_t data = 0;
    int32_t size = 0;
    if (!read_pdx_array(
            country, adapter::kCountryCommandGroupsOffset, adapter::kMaxArmies, &data, &size) ||
        size <= 0) {
        return 0;
    }
    const uint64_t want = module_va(vtable_rva);
    const uint64_t* items = reinterpret_cast<const uint64_t*>(data);
    for (int32_t i = 0; i < size; ++i) {
        const uint64_t item = items[i];
        if (!vtable_in_image(item)) {
            continue;
        }
        if (*reinterpret_cast<const uint64_t*>(item) == want) {
            return item;
        }
    }
    return 0;
}

uint64_t parent_for_org(uint64_t member, uint64_t country) {
    const uint64_t from_member = object_parent(member);
    if (from_member != 0) {
        return from_member;
    }
    if (country == 0) {
        return 0;
    }
    return first_group_with_vtable(country, adapter::kCTheatreVtableRva);
}

struct PdxPtrList {
    uint64_t* data;
    uint32_t cap;
    uint32_t size;
};

void try_submit_test_army(uint64_t country, uint64_t army) {
    SharedBlock* block = g_block;
    if (block == nullptr || block->request != static_cast<uint32_t>(Request::TestArmy)) {
        return;
    }
    if (!adapter::writes_allowed(block->enabled, block->read_only, block->max_orders_per_hour) ||
        block->write_enabled == 0 || block->order_accepted != 0 ||
        block->order_attempts >= block->max_orders_per_hour) {
        finish_order(block, OrderResult::Gated);
        return;
    }
    if (army == 0 || !vtable_in_image(army) ||
        *reinterpret_cast<const uint64_t*>(army) != module_va(adapter::kCArmyVtableRva)) {
        finish_order(block, OrderResult::NoArmy);
        return;
    }
    const uint64_t parent = parent_for_org(army, country);
    if (parent == 0) {
        finish_order(block, OrderResult::BadTarget);
        return;
    }
    if (!army_command_signatures_match()) {
        finish_order(block, OrderResult::SignatureFailed);
        return;
    }

    using CtorB = void*(HOIV_MSABI*)(void*, void*, void*, void*);
    using CanFn = uint8_t(HOIV_MSABI*)(void*, uint32_t);
    using DoFn = void(HOIV_MSABI*)(void*);

    ++block->order_attempts;
    block->request = static_cast<uint32_t>(Request::None);

    struct OurOrgGuard {
        OurOrgGuard() {
            g_allow_our_org = true;
        }
        ~OurOrgGuard() {
            g_allow_our_org = false;
        }
    } allow_ours;

    uint64_t item = army;
    PdxPtrList arr {&item, 1, 1};

    alignas(16) uint8_t cmd[adapter::kCOrderGroupCommandBytesSize] {};
    auto ctor = reinterpret_cast<CtorB>(g_module_base + adapter::kCOrderGroupCommandCtorBRva);
    ctor(cmd, &arr, reinterpret_cast<void*>(parent), nullptr);

    void** vt = *reinterpret_cast<void***>(cmd);
    if (vt == nullptr || !in_module(reinterpret_cast<uint64_t>(vt), 88)) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    auto can = reinterpret_cast<CanFn>(vt[adapter::kCOrderGroupCommandVtableSlotCan]);
    if (can == nullptr || can(cmd, 0) == 0) {
        finish_order(block, OrderResult::CanExecuteFalse);
        return;
    }
    auto exec = reinterpret_cast<DoFn>(vt[adapter::kCOrderGroupCommandVtableSlotDo]);
    if (exec == nullptr) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    exec(cmd);
    block->order_accepted = 1;
    block->last_order_result = static_cast<uint32_t>(OrderResult::Submitted);
}

void try_submit_test_army_group(uint64_t country) {
    SharedBlock* block = g_block;
    if (block == nullptr || block->request != static_cast<uint32_t>(Request::TestArmyGroup)) {
        return;
    }
    if (!adapter::writes_allowed(block->enabled, block->read_only, block->max_orders_per_hour) ||
        block->write_enabled == 0 || block->order_accepted != 0 ||
        block->order_attempts >= block->max_orders_per_hour) {
        finish_order(block, OrderResult::Gated);
        return;
    }
    if (country == 0 || !vtable_in_image(country)) {
        finish_order(block, OrderResult::NoArmy);
        return;
    }
    const uint64_t group = first_group_with_vtable(country, adapter::kCOrdersGroupVtableRva);
    if (group == 0) {
        finish_order(block, OrderResult::NoArmy);
        return;
    }
    // Army group must keep at least one army. Taking the only army empties the source.
    const uint64_t parent = parent_for_org(group, country);
    if (parent == 0) {
        finish_order(block, OrderResult::BadTarget);
        return;
    }
    if (!army_group_command_signatures_match()) {
        finish_order(block, OrderResult::SignatureFailed);
        return;
    }

    using CtorB = void*(HOIV_MSABI*)(void*, void*, void*);
    using CanFn = uint8_t(HOIV_MSABI*)(void*, uint32_t);
    using DoFn = void(HOIV_MSABI*)(void*);

    ++block->order_attempts;
    block->request = static_cast<uint32_t>(Request::None);

    struct OurOrgGuard {
        OurOrgGuard() {
            g_allow_our_org = true;
        }
        ~OurOrgGuard() {
            g_allow_our_org = false;
        }
    } allow_ours;

    uint64_t item = group;
    PdxPtrList arr {&item, 1, 1};

    alignas(16) uint8_t cmd[adapter::kCArmyGroupCommandBytesSize] {};
    auto ctor = reinterpret_cast<CtorB>(g_module_base + adapter::kCArmyGroupCommandCtorBRva);
    ctor(cmd, &arr, reinterpret_cast<void*>(parent));

    void** vt = *reinterpret_cast<void***>(cmd);
    if (vt == nullptr || !in_module(reinterpret_cast<uint64_t>(vt), 88)) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    auto can = reinterpret_cast<CanFn>(vt[adapter::kCArmyGroupCommandVtableSlotCan]);
    if (can == nullptr || can(cmd, 0) == 0) {
        finish_order(block, OrderResult::CanExecuteFalse);
        return;
    }
    auto exec = reinterpret_cast<DoFn>(vt[adapter::kCArmyGroupCommandVtableSlotDo]);
    if (exec == nullptr) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    exec(cmd);
    block->order_accepted = 1;
    block->last_order_result = static_cast<uint32_t>(OrderResult::Submitted);
}

bool cancel_signatures_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kCancelCommandRva), adapter::kCancelCommandByteCount) ||
        !in_module(module_va(adapter::kCancelCanExecuteRva), adapter::kCancelCanExecuteByteCount) ||
        !in_module(module_va(adapter::kCancelExecuteRva), adapter::kCancelExecuteByteCount)) {
        return false;
    }
    return adapter::cancel_ctor_bytes_match(g_module_base + adapter::kCancelCommandRva) &&
        adapter::cancel_can_bytes_match(g_module_base + adapter::kCancelCanExecuteRva) &&
        adapter::cancel_do_bytes_match(g_module_base + adapter::kCancelExecuteRva);
}

void try_submit_swiss_cancel(uint64_t army, int32_t handle_id, int32_t handle_gen) {
    SharedBlock* block = g_block;
    if (block == nullptr || block->request != static_cast<uint32_t>(Request::TestCancel)) {
        return;
    }
    if (!adapter::writes_allowed(block->enabled, block->read_only, block->max_orders_per_hour) ||
        block->write_enabled == 0 || block->order_attempts >= block->max_orders_per_hour) {
        finish_order(block, OrderResult::Gated);
        return;
    }
    if (army == 0 || !vtable_in_image(army) || !adapter::army_handle_usable(handle_id, handle_gen)) {
        finish_order(block, OrderResult::NoArmy);
        return;
    }
    if (!cancel_signatures_match()) {
        finish_order(block, OrderResult::SignatureFailed);
        return;
    }

    using CancelCtor = void(HOIV_MSABI*)(void*, void*, uint8_t);
    using CanFn = uint8_t(HOIV_MSABI*)(void*, uint32_t);
    using DoFn = void(HOIV_MSABI*)(void*);

    ++block->order_attempts;
    block->request = static_cast<uint32_t>(Request::None);

    alignas(16) uint8_t cmd[adapter::kCancelCommandBytesSize] {};
    auto ctor = reinterpret_cast<CancelCtor>(g_module_base + adapter::kCancelCommandRva);
    ctor(cmd, reinterpret_cast<void*>(army), adapter::kCancelCtorFlag);

    void** vt = *reinterpret_cast<void***>(cmd);
    if (vt == nullptr || !in_module(reinterpret_cast<uint64_t>(vt), 88)) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    auto can = reinterpret_cast<CanFn>(vt[adapter::kCancelCommandVtableSlotCan]);
    if (can == nullptr || can(cmd, 0) == 0) {
        finish_order(block, OrderResult::CanExecuteFalse);
        return;
    }
    auto exec = reinterpret_cast<DoFn>(vt[adapter::kCancelCommandVtableSlotDo]);
    if (exec == nullptr) {
        finish_order(block, OrderResult::Fault);
        return;
    }
    exec(cmd);
    block->last_order_result = static_cast<uint32_t>(OrderResult::Cancelled);
}

bool global_ai_toggle_match() {
    if (g_module_base == nullptr ||
        !in_module(module_va(adapter::kGlobalAiToggleRva), adapter::kGlobalAiToggleByteCount) ||
        !in_module(module_va(adapter::kGlobalAiEnabledRva), 1)) {
        return false;
    }
    return adapter::global_ai_toggle_bytes_match(g_module_base + adapter::kGlobalAiToggleRva);
}

uint8_t* global_ai_flag() {
    return g_module_base + adapter::kGlobalAiEnabledRva;
}

void sample_land_ai_global() {
    SharedBlock* block = g_block;
    if (block == nullptr || g_module_base == nullptr ||
        !page_readable(module_va(adapter::kGlobalAiEnabledRva), 1)) {
        return;
    }
    block->land_ai_global = *global_ai_flag();
}

void restore_global_ai_if_needed() {
    if (g_restored_global_ai.load() || !global_ai_toggle_match() ||
        !page_readable(module_va(adapter::kGlobalAiEnabledRva), 1)) {
        return;
    }
    *global_ai_flag() = adapter::kGlobalAiOnValue;
    g_restored_global_ai.store(true);
}

bool load_countries(
    uint64_t gamestate,
    const uint64_t** countries_out,
    int32_t* size_out) {
    if (countries_out == nullptr || size_out == nullptr || !user_object(gamestate) ||
        !page_readable(gamestate, adapter::kCountryArraySizeOffset + 4)) {
        return false;
    }
    const uint64_t country_data =
        *reinterpret_cast<const uint64_t*>(gamestate + adapter::kCountryArrayDataOffset);
    const int32_t country_cap =
        *reinterpret_cast<const int32_t*>(gamestate + adapter::kCountryArrayCapacityOffset);
    const int32_t country_size =
        *reinterpret_cast<const int32_t*>(gamestate + adapter::kCountryArraySizeOffset);
    if (!pdx_array_bounds_ok(country_size, country_cap, adapter::kMaxCountries) ||
        (country_size > 0 && !user_object(country_data))) {
        return false;
    }
    *countries_out = reinterpret_cast<const uint64_t*>(country_data);
    *size_out = country_size;
    return true;
}

uint64_t country_by_tag(const uint64_t* countries, int32_t country_size, int32_t tag) {
    if (countries == nullptr || tag < 0 || tag >= country_size) {
        return 0;
    }
    const uint64_t country = countries[tag];
    if (!is_canonical_user_pointer(country) ||
        *reinterpret_cast<const uint64_t*>(country) != module_va(adapter::kCCountryVtableRva) ||
        *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset) != tag) {
        return 0;
    }
    return country;
}

bool should_block_major_move(void* cmd) {
    if (!g_hold_land_ai.load(std::memory_order_relaxed) || g_allow_our_move || cmd == nullptr) {
        return false;
    }
    const uint64_t packed = *reinterpret_cast<const uint64_t*>(
        static_cast<const uint8_t*>(cmd) + adapter::kMoveCommandHandleOffset);
    if (packed == 0) {
        return false;
    }
    const uint32_t sel = g_major_handle_sel.load(std::memory_order_acquire);
    return adapter::major_handle_hash_has(
        g_major_handle_hash[sel], adapter::kMajorHandleHashSlots, packed);
}

uint32_t snapshot_major_handles(uint64_t gamestate) {
    const uint64_t* countries = nullptr;
    int32_t country_size = 0;
    if (!load_countries(gamestate, &countries, &country_size)) {
        return 0;
    }
    const uint32_t sel = g_major_handle_sel.load(std::memory_order_relaxed);
    const uint32_t dest = 1u - sel;
    std::memset(g_major_handle_hash[dest], 0, sizeof(g_major_handle_hash[dest]));
    uint32_t n = 0;
    uint32_t majors = 0;
    const uint64_t army_vt = module_va(adapter::kCArmyVtableRva);
    for (int32_t tag = adapter::kMajorCountryTagBegin; tag <= adapter::kMajorCountryTagEnd; ++tag) {
        const uint64_t country = country_by_tag(countries, country_size, tag);
        if (country == 0) {
            continue;
        }
        uint64_t army_data = 0;
        int32_t army_size = 0;
        if (!load_armies(country, &army_data, &army_size) || army_data == 0) {
            continue;
        }
        ++majors;
        const uint64_t* armies = reinterpret_cast<const uint64_t*>(army_data);
        for (int32_t i = 0; i < army_size && n < adapter::kMaxMajorArmyHandles; ++i) {
            const uint64_t army = armies[i];
            if (!is_canonical_user_pointer(army) ||
                *reinterpret_cast<const uint64_t*>(army) != army_vt) {
                continue;
            }
            const uint64_t packed =
                *reinterpret_cast<const uint64_t*>(army + adapter::kArmyHandleOffset);
            if (!adapter::army_handle_usable(
                    static_cast<int32_t>(packed),
                    static_cast<int32_t>(packed >> 32))) {
                continue;
            }
            if (adapter::major_handle_hash_insert(
                    g_major_handle_hash[dest], adapter::kMajorHandleHashSlots, packed)) {
                ++n;
            }
        }
    }
    g_major_handle_sel.store(dest, std::memory_order_release);
    g_last_handle_snapshot_ms = GetTickCount();
    return majors;
}

uint64_t country_ai_of(uint64_t country) {
    if (!user_object(country) ||
        !page_readable(country + adapter::kCountryAiPointerOffset, 8)) {
        return 0;
    }
    const uint64_t ai =
        *reinterpret_cast<const uint64_t*>(country + adapter::kCountryAiPointerOffset);
    if (!user_object(ai) ||
        !adapter::is_country_ai_vtable(*reinterpret_cast<const uint64_t*>(ai), module_va(0))) {
        return 0;
    }
    return ai;
}

int32_t peek_array_size(uint64_t object, uint32_t offset) {
    uint64_t data = 0;
    int32_t size = 0;
    if (!read_pdx_array(object, offset, adapter::kMaxArmyGroupOrders, &data, &size)) {
        return -1;
    }
    return size;
}

uint64_t country_from_owner(uint64_t owner) {
    if (!is_canonical_user_pointer(owner)) {
        return 0;
    }
    const uint64_t ovt = *reinterpret_cast<const uint64_t*>(owner);
    uint64_t country = 0;
    if (adapter::is_country_ai_vtable(ovt, module_va(0))) {
        country = *reinterpret_cast<const uint64_t*>(owner + adapter::kCountryAiCountryOffset);
    } else if (ovt == module_va(adapter::kCCountryVtableRva)) {
        country = owner;
    }
    if (!is_canonical_user_pointer(country) ||
        *reinterpret_cast<const uint64_t*>(country) != module_va(adapter::kCCountryVtableRva)) {
        return 0;
    }
    return country;
}

bool owner_is_major_country(uint64_t owner) {
    const uint64_t country = country_from_owner(owner);
    if (country == 0) {
        return false;
    }
    const int32_t tag = *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
    return adapter::is_major_country_tag(tag);
}

uint64_t country_from_general(void* general) {
    if (general == nullptr || !is_canonical_user_pointer(reinterpret_cast<uint64_t>(general))) {
        return 0;
    }
    const uint64_t vt = *reinterpret_cast<const uint64_t*>(general);
    if (!adapter::is_land_general_vtable(vt, module_va(0))) {
        return 0;
    }
    const uint32_t owner_off = vt == module_va(adapter::kCAIVolunteerGeneralVtableRva)
        ? adapter::kCAIVolunteerGeneralOwnerOffset
        : adapter::kCAIGeneralOwnerOffset;
    return country_from_owner(
        *reinterpret_cast<const uint64_t*>(static_cast<const uint8_t*>(general) + owner_off));
}

bool should_skip_major_general(void* general) {
    if (!g_land_ai_general.load(std::memory_order_relaxed) || g_module_base == nullptr) {
        return false;
    }
    const uint64_t country = country_from_general(general);
    if (country == 0) {
        return false;
    }
    const int32_t tag = *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
    return adapter::is_major_country_tag(tag);
}

bool should_skip_major_org(uint64_t owner) {
    if (g_allow_our_org || !g_land_ai_org_create.load(std::memory_order_relaxed) ||
        g_module_base == nullptr) {
        return false;
    }
    return owner_is_major_country(owner);
}

bool should_skip_major_front(void* front) {
    if (front == nullptr || !is_canonical_user_pointer(reinterpret_cast<uint64_t>(front))) {
        return false;
    }
    if (*reinterpret_cast<const uint64_t*>(front) != module_va(adapter::kCFrontVtableRva)) {
        return false;
    }
    const uint64_t owner = *reinterpret_cast<const uint64_t*>(
        static_cast<const uint8_t*>(front) + adapter::kFrontOwnerOffset);
    return should_skip_major_org(owner);
}

void HOIV_MSABI hoiv_hook_general_tick(void* general) {
    if (should_skip_major_general(general)) {
        return;
    }
    if (g_orig_general_tick != nullptr) {
        g_orig_general_tick(general);
    }
}

void HOIV_MSABI hoiv_hook_front_factory(void* owner, void* msg, uint32_t type) {
    if (should_skip_major_org(reinterpret_cast<uint64_t>(owner))) {
        return;
    }
    if (g_orig_front_factory != nullptr) {
        g_orig_front_factory(owner, msg, type);
    }
}

void HOIV_MSABI hoiv_hook_front_tick(void* front, void* other) {
    if (should_skip_major_front(front)) {
        return;
    }
    if (g_orig_front_tick != nullptr) {
        g_orig_front_tick(front, other);
    }
}

uint64_t HOIV_MSABI hoiv_hook_ag_factory(void* front, void* a, void* b, void* c) {
    if (should_skip_major_front(front)) {
        return 0;
    }
    if (g_orig_ag_factory == nullptr) {
        return 0;
    }
    return g_orig_ag_factory(front, a, b, c);
}

uint64_t probe_object_vtable(uint64_t object) {
    if (!user_object(object) || !page_readable(object, 8)) {
        return 0;
    }
    return *reinterpret_cast<const uint64_t*>(object);
}

uint32_t probe_vt_rva(uint64_t object) {
    const uint64_t vt = probe_object_vtable(object);
    if (vt == 0 || g_module_base == nullptr) {
        return 0;
    }
    const uint64_t begin = module_va(0);
    if (vt < begin || vt >= begin + g_module_size) {
        return 0;
    }
    return static_cast<uint32_t>(vt - begin);
}

void note_probe_vt(std::atomic<uint32_t>* slot, uint64_t object) {
    if (slot == nullptr || slot->load(std::memory_order_relaxed) != 0) {
        return;
    }
    const uint32_t rva = probe_vt_rva(object);
    if (rva != 0) {
        slot->store(rva, std::memory_order_relaxed);
    }
}

int32_t probe_tag_from_country(uint64_t country) {
    if (!user_object(country) ||
        !page_readable(country + adapter::kCountryTagOffset, 4) ||
        *reinterpret_cast<const uint64_t*>(country) != module_va(adapter::kCCountryVtableRva)) {
        return 0;
    }
    return *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
}

int32_t probe_tag_from_object(uint64_t object) {
    const uint64_t vt = probe_object_vtable(object);
    if (vt == 0) {
        return 0;
    }
    if (vt == module_va(adapter::kCCountryVtableRva)) {
        return probe_tag_from_country(object);
    }
    if (adapter::is_country_ai_vtable(vt, module_va(0))) {
        if (!page_readable(object + adapter::kCountryAiCountryOffset, 8)) {
            return 0;
        }
        return probe_tag_from_country(
            *reinterpret_cast<const uint64_t*>(object + adapter::kCountryAiCountryOffset));
    }
    if (adapter::is_military_minister_vtable(vt, module_va(0))) {
        if (!page_readable(object + adapter::kCAIMilitaryMinisterOwnerOffset, 8)) {
            return 0;
        }
        return probe_tag_from_object(
            *reinterpret_cast<const uint64_t*>(
                object + adapter::kCAIMilitaryMinisterOwnerOffset));
    }
    if (adapter::is_land_general_vtable(vt, module_va(0))) {
        const uint32_t owner_off = vt == module_va(adapter::kCAIVolunteerGeneralVtableRva)
            ? adapter::kCAIVolunteerGeneralOwnerOffset
            : adapter::kCAIGeneralOwnerOffset;
        if (!page_readable(object + owner_off, 8)) {
            return 0;
        }
        return probe_tag_from_object(*reinterpret_cast<const uint64_t*>(object + owner_off));
    }
    if (vt == module_va(adapter::kCFrontVtableRva)) {
        if (!page_readable(object + adapter::kFrontOwnerOffset, 8)) {
            return 0;
        }
        return probe_tag_from_object(
            *reinterpret_cast<const uint64_t*>(object + adapter::kFrontOwnerOffset));
    }
    return 0;
}

void note_probe_tag(std::atomic<int32_t>* slot, int32_t tag) {
    if (slot == nullptr || tag == 0) {
        return;
    }
    const int32_t current = slot->load(std::memory_order_relaxed);
    if (current == 0 || tag == adapter::kGermanyTestCountryTag) {
        slot->store(tag, std::memory_order_relaxed);
    }
}

int32_t probe_tag_from_move_list(uint64_t list) {
    if (!user_object(list) || !page_readable(list + adapter::kLandActorMoveOwnerOffset, 8)) {
        return 0;
    }
    const uint64_t owner = *reinterpret_cast<const uint64_t*>(list + adapter::kLandActorMoveOwnerOffset);
    note_probe_vt(&g_probe_move_vt, owner);
    return probe_tag_from_object(owner);
}

uint64_t HOIV_MSABI hoiv_hook_probe_move(void* a, void* b, void* c, void* d) {
    g_probe_move_enters.fetch_add(1, std::memory_order_relaxed);
    const uint64_t list = reinterpret_cast<uint64_t>(a);
    const int32_t tag = probe_tag_from_move_list(list);
    note_probe_tag(&g_probe_move_tag, tag);
    if (tag == adapter::kGermanyTestCountryTag) {
        g_probe_move_skips.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    if (g_orig_probe_move == nullptr) {
        return 0;
    }
    return g_orig_probe_move(a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_probe_mass(void* a, void* b, void* c, void* d) {
    g_probe_mass_enters.fetch_add(1, std::memory_order_relaxed);
    const uint64_t self = reinterpret_cast<uint64_t>(a);
    note_probe_vt(&g_probe_mass_vt, self);
    const int32_t tag = probe_tag_from_object(self);
    note_probe_tag(&g_probe_mass_tag, tag);
    const bool german_ai =
        tag == adapter::kGermanyTestCountryTag &&
        adapter::is_country_ai_vtable(probe_object_vtable(self), reinterpret_cast<uint64_t>(g_module_base));
    if (german_ai) {
        g_skip_german_mass_move = true;
    }
    uint64_t result = 0;
    if (g_orig_probe_mass != nullptr) {
        result = g_orig_probe_mass(a, b, c, d);
    }
    if (german_ai) {
        g_skip_german_mass_move = false;
    }
    return result;
}

uint64_t HOIV_MSABI hoiv_hook_probe_exec(void* a, void* b, void* c, void* d) {
    g_probe_exec_enters.fetch_add(1, std::memory_order_relaxed);
    note_probe_tag(&g_probe_exec_tag, probe_tag_from_object(reinterpret_cast<uint64_t>(a)));
    note_probe_tag(&g_probe_exec_tag, probe_tag_from_object(reinterpret_cast<uint64_t>(b)));
    note_probe_tag(&g_probe_exec_tag, probe_tag_from_object(reinterpret_cast<uint64_t>(c)));
    note_probe_vt(&g_probe_exec_vt0, reinterpret_cast<uint64_t>(a));
    note_probe_vt(&g_probe_exec_vt1, reinterpret_cast<uint64_t>(b));
    note_probe_vt(&g_probe_exec_vt2, reinterpret_cast<uint64_t>(c));
    (void)d;
    if (g_orig_probe_exec == nullptr) {
        return 0;
    }
    return g_orig_probe_exec(a, b, c, d);
}

void HOIV_MSABI hoiv_hook_volunteer_tick(void* general) {
    g_probe_vol_enters.fetch_add(1, std::memory_order_relaxed);
    note_probe_vt(&g_probe_vol_vt, reinterpret_cast<uint64_t>(general));
    const uint64_t country = country_from_general(general);
    int32_t tag = 0;
    if (country != 0 && page_readable(country + adapter::kCountryTagOffset, 4)) {
        tag = *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
    }
    note_probe_tag(&g_probe_vol_tag, tag);
    const uint64_t vt = probe_object_vtable(reinterpret_cast<uint64_t>(general));
    if (tag == adapter::kGermanyTestCountryTag &&
        vt == module_va(adapter::kCAIVolunteerGeneralVtableRva)) {
        g_probe_vol_skips.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (g_orig_probe_vol != nullptr) {
        g_orig_probe_vol(general);
    }
}

uint64_t HOIV_MSABI hoiv_hook_org_helper(void* a, void* b, void* c, void* d) {
    if (g_orig_probe_org == nullptr) {
        return 0;
    }
    return g_orig_probe_org(a, b, c, d);
}

int32_t probe_tag_from_args(void* a, void* b, void* c) {
    int32_t tag = probe_tag_from_object(reinterpret_cast<uint64_t>(a));
    if (tag == 0) {
        tag = probe_tag_from_object(reinterpret_cast<uint64_t>(b));
    }
    if (tag == 0 && c != nullptr) {
        tag = probe_tag_from_object(reinterpret_cast<uint64_t>(c));
    }
    if (tag == 0) {
        const uint64_t country = country_from_general(a);
        if (country != 0 && page_readable(country + adapter::kCountryTagOffset, 4)) {
            tag = *reinterpret_cast<const int32_t*>(country + adapter::kCountryTagOffset);
        }
    }
    return tag;
}

uint64_t HOIV_MSABI hoiv_hook_general_org(void* a, void* b, void* c, void* d) {
    const int32_t tag = probe_tag_from_args(a, b, c);
    const bool prev_skip = g_skip_german_org_create;
    const int32_t prev_tag = g_org_create_tag;
    if (tag != 0) {
        g_org_create_tag = tag;
    }
    if (!g_allow_our_org && tag == adapter::kGermanyTestCountryTag) {
        g_skip_german_org_create = true;
    }
    uint64_t result = 0;
    if (g_orig_general_org != nullptr) {
        result = g_orig_general_org(a, b, c, d);
    }
    g_skip_german_org_create = prev_skip;
    g_org_create_tag = prev_tag;
    return result;
}

uint64_t HOIV_MSABI hoiv_hook_area_defense_ai(void* a, void* b, void* c, void* d) {
    note_probe_vt(&g_probe_exec_vt0, reinterpret_cast<uint64_t>(a));
    const int32_t tag = probe_tag_from_args(a, b, c);
    note_probe_tag(&g_probe_exec_tag, tag);
    if (!g_allow_our_org && tag == adapter::kGermanyTestCountryTag) {
        g_probe_exec_skips.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    if (g_orig_area_def_ai == nullptr) {
        return 0;
    }
    return g_orig_area_def_ai(a, b, c, d);
}

bool skip_german_ag_or_army_poster(void* a, void* b, void* c) {
    g_probe_ag_enters.fetch_add(1, std::memory_order_relaxed);
    note_probe_vt(&g_probe_ag_vt, reinterpret_cast<uint64_t>(a));
    int32_t tag = probe_tag_from_args(a, b, c);
    if (tag == 0) {
        tag = g_org_create_tag;
    }
    note_probe_tag(&g_probe_ag_tag, tag);
    if (!g_allow_our_org &&
        (g_skip_german_org_create || tag == adapter::kGermanyTestCountryTag)) {
        g_probe_ag_skips.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

uint64_t HOIV_MSABI call_org_poster(LandActorProbeFn original, void* a, void* b, void* c, void* d) {
    if (skip_german_ag_or_army_poster(a, b, c)) {
        return 0;
    }
    if (original == nullptr) {
        return 0;
    }
    return original(a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_army_group_ai(void* a, void* b, void* c, void* d) {
    return call_org_poster(g_orig_ag_ai, a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_army_ai(void* a, void* b, void* c, void* d) {
    return call_org_poster(g_orig_army_ai, a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_army_ai2(void* a, void* b, void* c, void* d) {
    return call_org_poster(g_orig_army_ai2, a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_theatre_ai_create(void* a, void* b, void* c, void* d) {
    g_probe_org_enters.fetch_add(1, std::memory_order_relaxed);
    note_probe_vt(&g_probe_org_vt, reinterpret_cast<uint64_t>(a));
    int32_t tag = probe_tag_from_object(reinterpret_cast<uint64_t>(a));
    if (tag == 0) {
        tag = probe_tag_from_object(reinterpret_cast<uint64_t>(b));
    }
    if (tag == 0 && user_object(reinterpret_cast<uint64_t>(a)) &&
        page_readable(reinterpret_cast<uint64_t>(a) + adapter::kCountryTagOffset, 8)) {
        tag = probe_tag_from_object(
            *reinterpret_cast<const uint64_t*>(
                reinterpret_cast<uint64_t>(a) + adapter::kCountryAiCountryOffset));
    }
    note_probe_tag(&g_probe_org_tag, tag);
    const int32_t prev_tag = g_org_create_tag;
    if (tag != 0) {
        g_org_create_tag = tag;
    }
    uint64_t result = 0;
    if (g_orig_theatre_ai != nullptr) {
        result = g_orig_theatre_ai(a, b, c, d);
    }
    g_org_create_tag = prev_tag;
    return result;
}

uint64_t HOIV_MSABI hoiv_hook_theatre_create_gate(void* a, void* b, void* c, void* d) {
    if (g_orig_theatre_gate == nullptr) {
        return 0;
    }
    return g_orig_theatre_gate(a, b, c, d);
}

uint64_t HOIV_MSABI hoiv_hook_theatre_ctor(void* self, void* b, void* c, void* d) {
    if (g_orig_theatre_ctor == nullptr) {
        return 0;
    }
    return g_orig_theatre_ctor(self, b, c, d);
}

uint8_t HOIV_MSABI hoiv_hook_org_command_can(OrgCommandCanFn original, void* cmd) {
    if (g_skip_german_org_create && !g_allow_our_org) {
        g_probe_org_skips.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    if (original == nullptr) {
        return 0;
    }
    return original(cmd);
}

uint8_t HOIV_MSABI hoiv_hook_theatre_can(void* cmd) {
    return hoiv_hook_org_command_can(g_orig_theatre_can, cmd);
}

uint8_t HOIV_MSABI hoiv_hook_ag_can(void* cmd) {
    return hoiv_hook_org_command_can(g_orig_ag_can, cmd);
}

uint8_t HOIV_MSABI hoiv_hook_assign_ag_can(void* cmd) {
    return hoiv_hook_org_command_can(g_orig_assign_ag_can, cmd);
}

uint8_t HOIV_MSABI hoiv_hook_front_can(void* cmd) {
    return hoiv_hook_org_command_can(g_orig_front_can, cmd);
}

uint8_t HOIV_MSABI hoiv_hook_order_group_can(void* cmd) {
    return hoiv_hook_org_command_can(g_orig_order_group_can, cmd);
}

uint8_t HOIV_MSABI hoiv_hook_mass_move_can(void* cmd) {
    if (g_skip_german_mass_move) {
        g_probe_mass_skips.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    if (g_orig_mass_move_can == nullptr) {
        return 0;
    }
    return g_orig_mass_move_can(cmd);
}

void HOIV_MSABI hoiv_hook_mil_create(void* mil) {
    if (mil != nullptr && is_canonical_user_pointer(reinterpret_cast<uint64_t>(mil)) &&
        *reinterpret_cast<const uint64_t*>(mil) == module_va(adapter::kCAIMilitaryMinisterVtableRva)) {
        const uint64_t owner = *reinterpret_cast<const uint64_t*>(
            static_cast<const uint8_t*>(mil) + adapter::kCAIGeneralOwnerOffset);
        if (should_skip_major_org(owner)) {
            return;
        }
    }
    if (g_orig_mil_create != nullptr) {
        g_orig_mil_create(mil);
    }
}

uint32_t count_major_generals(uint64_t gamestate) {
    const uint64_t* countries = nullptr;
    int32_t country_size = 0;
    if (!load_countries(gamestate, &countries, &country_size)) {
        return 0;
    }
    uint32_t n = 0;
    const uint64_t general_vt = module_va(adapter::kCAIGeneralVtableRva);
    const uint64_t mil_vt = module_va(adapter::kCAIMilitaryMinisterVtableRva);
    g_land_diag = {};
    for (int32_t tag = adapter::kMajorCountryTagBegin; tag <= adapter::kMajorCountryTagEnd; ++tag) {
        const uint64_t country = country_by_tag(countries, country_size, tag);
        if (country == 0) {
            continue;
        }
        const uint64_t ai = country_ai_of(country);
        if (tag == adapter::kGermanyTestCountryTag) {
            g_land_diag.ai = ai != 0 ? 1 : 0;
            g_land_diag.fronts = peek_array_size(country, adapter::kCountryCommandGroupsOffset);
        }
        if (ai == 0 || !page_readable(ai + adapter::kCountryAiMilitaryMinisterOffset, 8)) {
            continue;
        }
        const uint64_t mil =
            *reinterpret_cast<const uint64_t*>(ai + adapter::kCountryAiMilitaryMinisterOffset);
        if (!user_object(mil) || *reinterpret_cast<const uint64_t*>(mil) != mil_vt) {
            continue;
        }
        if (tag == adapter::kGermanyTestCountryTag) {
            g_land_diag.mil = 1;
            g_land_diag.gen = peek_array_size(mil, adapter::kMilitaryMinisterGeneralsOffset);
        }
        uint64_t data = 0;
        int32_t size = 0;
        if (!read_pdx_array(
                mil, adapter::kMilitaryMinisterGeneralsOffset, adapter::kMaxArmyGroupOrders, &data,
                &size) ||
            data == 0) {
            continue;
        }
        const uint64_t* gens = reinterpret_cast<const uint64_t*>(data);
        for (int32_t i = 0; i < size; ++i) {
            if (is_canonical_user_pointer(gens[i]) &&
                *reinterpret_cast<const uint64_t*>(gens[i]) == general_vt) {
                ++n;
            }
        }
    }
    g_last_handle_snapshot_ms = GetTickCount();
    return n;
}

void try_suppress_major_land_ai(uint64_t gamestate) {
    SharedBlock* block = g_block;
    if (block == nullptr || block->request != static_cast<uint32_t>(Request::SuppressLandAi)) {
        return;
    }
    if (!adapter::ai_writes_allowed(block->enabled, block->read_only) || block->write_enabled == 0) {
        block->land_ai_path = kLandAiPathNone;
        finish_order(block, OrderResult::Gated);
        return;
    }
    restore_global_ai_if_needed();
    if (page_readable(module_va(adapter::kGlobalAiEnabledRva), 1)) {
        block->land_ai_global = *global_ai_flag();
    }
    if (!land_ai_signatures_match() || !patch_org_create()) {
        block->land_ai_path = kLandAiPathNone;
        std::snprintf(
            block->last_error, sizeof(block->last_error), "org-create signature or patch failed");
        finish_order(block, OrderResult::SignatureFailed);
        return;
    }
    patch_general_tick();
    const uint32_t gens = count_major_generals(gamestate);
    block->land_ai_off_count = gens;
    block->land_ai_path = kLandAiPathOrgCreate;
    g_land_ai_org_create.store(true, std::memory_order_release);
    g_land_ai_general.store(true, std::memory_order_release);
    g_hold_land_ai.store(true, std::memory_order_release);
    std::snprintf(
        block->last_error,
        sizeof(block->last_error),
        "org-create gens=%u ger ai=%u mil=%u gen=%d fronts=%d",
        gens,
        g_land_diag.ai,
        g_land_diag.mil,
        g_land_diag.gen,
        g_land_diag.fronts);
    finish_order(block, OrderResult::LandAiOff);
}

void hold_land_ai_if_armed(uint64_t gamestate) {
    SharedBlock* block = g_block;
    if (block == nullptr || !g_hold_land_ai.load(std::memory_order_relaxed) ||
        !adapter::ai_writes_allowed(block->enabled, block->read_only) || block->write_enabled == 0) {
        return;
    }
    const uint32_t now = GetTickCount();
    if (g_last_handle_snapshot_ms != 0 &&
        now - g_last_handle_snapshot_ms < adapter::kLandAiHandleRefreshMs) {
        return;
    }
    if (g_land_ai_general.load(std::memory_order_relaxed)) {
        block->land_ai_off_count = count_major_generals(gamestate);
    }
}

uint8_t HOIV_MSABI hoiv_hook_move_can_execute(void* cmd, uint32_t mode) {
    if (should_block_major_move(cmd)) {
        return 0;
    }
    if (cmd == nullptr) {
        return 0;
    }
    void** inner_vt = *reinterpret_cast<void***>(
        static_cast<uint8_t*>(cmd) + adapter::kMoveCommandInnerOffset);
    auto fn = reinterpret_cast<uint8_t(HOIV_MSABI*)(void*, uint32_t)>(
        inner_vt[adapter::kMoveCanInnerVtableSlot]);
    return fn(static_cast<uint8_t*>(cmd) + adapter::kMoveCommandInnerOffset, mode);
}

void HOIV_MSABI hoiv_hook_move_execute(void* cmd) {
    if (should_block_major_move(cmd) || cmd == nullptr) {
        return;
    }
    void** inner_vt = *reinterpret_cast<void***>(
        static_cast<uint8_t*>(cmd) + adapter::kMoveCommandInnerOffset);
    auto fn = reinterpret_cast<void(HOIV_MSABI*)(void*)>(inner_vt[adapter::kMoveDoInnerVtableSlot]);
    fn(static_cast<uint8_t*>(cmd) + adapter::kMoveCommandInnerOffset);
}

bool patch_get_player() {
    uint8_t* target = g_module_base + adapter::kGetPlayerRva;
    DWORD old_protect = 0;
    if (!VirtualProtect(target, adapter::kGetPlayerHookBytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }
    std::memcpy(g_saved_get_player, target, adapter::kGetPlayerHookBytes);
    uint8_t hook[adapter::kGetPlayerHookBytes] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t dest = reinterpret_cast<uint64_t>(&hoiv_hook_get_player);
    std::memcpy(hook + 6, &dest, sizeof(dest));
    std::memcpy(target, hook, adapter::kGetPlayerHookBytes);
    FlushInstructionCache(GetCurrentProcess(), target, adapter::kGetPlayerHookBytes);
    DWORD ignored = 0;
    VirtualProtect(target, adapter::kGetPlayerHookBytes, old_protect, &ignored);
    g_patched.store(true);
    return true;
}

void restore_get_player() {
    if (!g_patched.load() || g_module_base == nullptr) {
        g_patched.store(false);
        return;
    }
    uint8_t* target = g_module_base + adapter::kGetPlayerRva;
    DWORD old_protect = 0;
    if (VirtualProtect(target, adapter::kGetPlayerHookBytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::memcpy(target, g_saved_get_player, adapter::kGetPlayerHookBytes);
        FlushInstructionCache(GetCurrentProcess(), target, adapter::kGetPlayerHookBytes);
        DWORD ignored = 0;
        VirtualProtect(target, adapter::kGetPlayerHookBytes, old_protect, &ignored);
    }
    g_patched.store(false);
}

bool patch_peek_message() {
    g_peek_iat = find_iat_slot("user32.dll", "PeekMessageW");
    if (g_peek_iat == nullptr) {
        return false;
    }
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) {
        return false;
    }
    auto* expected = reinterpret_cast<PeekMessageWFn>(GetProcAddress(user32, "PeekMessageW"));
    if (expected == nullptr || *g_peek_iat != reinterpret_cast<uint64_t>(expected)) {
        return false;
    }
    DWORD old_protect = 0;
    if (!VirtualProtect(g_peek_iat, sizeof(uint64_t), PAGE_READWRITE, &old_protect)) {
        return false;
    }
    g_orig_peek_message = expected;
    *g_peek_iat = reinterpret_cast<uint64_t>(&hoiv_hook_peek_message);
    DWORD ignored = 0;
    VirtualProtect(g_peek_iat, sizeof(uint64_t), old_protect, &ignored);
    g_iat_patched.store(true);
    return true;
}

void restore_peek_message() {
    if (!g_iat_patched.load() || g_peek_iat == nullptr || g_orig_peek_message == nullptr) {
        g_iat_patched.store(false);
        return;
    }
    DWORD old_protect = 0;
    if (VirtualProtect(g_peek_iat, sizeof(uint64_t), PAGE_READWRITE, &old_protect)) {
        *g_peek_iat = reinterpret_cast<uint64_t>(g_orig_peek_message);
        DWORD ignored = 0;
        VirtualProtect(g_peek_iat, sizeof(uint64_t), old_protect, &ignored);
    }
    g_orig_peek_message = nullptr;
    g_peek_iat = nullptr;
    g_iat_patched.store(false);
}

bool patch_abs_jmp(uint8_t* target, uint32_t bytes, void* dest, uint8_t* saved) {
    if (target == nullptr || dest == nullptr || saved == nullptr || bytes < 14) {
        return false;
    }
    DWORD old_protect = 0;
    if (!VirtualProtect(target, bytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }
    std::memcpy(saved, target, bytes);
    uint8_t hook[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint64_t addr = reinterpret_cast<uint64_t>(dest);
    std::memcpy(hook + 6, &addr, sizeof(addr));
    std::memcpy(target, hook, bytes);
    FlushInstructionCache(GetCurrentProcess(), target, bytes);
    DWORD ignored = 0;
    VirtualProtect(target, bytes, old_protect, &ignored);
    return true;
}

void restore_abs_jmp(uint8_t* target, uint32_t bytes, const uint8_t* saved) {
    if (target == nullptr || saved == nullptr || g_module_base == nullptr) {
        return;
    }
    DWORD old_protect = 0;
    if (!VirtualProtect(target, bytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return;
    }
    std::memcpy(target, saved, bytes);
    FlushInstructionCache(GetCurrentProcess(), target, bytes);
    DWORD ignored = 0;
    VirtualProtect(target, bytes, old_protect, &ignored);
}

bool write_abs_jmp(uint8_t* dest, uint64_t target) {
    uint8_t hook[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    std::memcpy(hook + 6, &target, sizeof(target));
    std::memcpy(dest, hook, 14);
    return true;
}

bool patch_general_tick() {
    if (g_general_patched.load()) {
        return true;
    }
    if (!adapter::general_tick_bytes_match(g_module_base + adapter::kCAIGeneralTickRva)) {
        return false;
    }
    uint8_t* target = g_module_base + adapter::kCAIGeneralTickRva;
    g_general_tick_tramp = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (g_general_tick_tramp == nullptr) {
        return false;
    }
    std::memcpy(g_saved_general_tick, target, adapter::kCAIGeneralTickHookBytes);
    std::memcpy(g_general_tick_tramp, target, adapter::kCAIGeneralTickHookBytes);
    write_abs_jmp(
        g_general_tick_tramp + adapter::kCAIGeneralTickHookBytes,
        reinterpret_cast<uint64_t>(target + adapter::kCAIGeneralTickHookBytes));
    DWORD old_protect = 0;
    if (!VirtualProtect(target, adapter::kCAIGeneralTickHookBytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        VirtualFree(g_general_tick_tramp, 0, MEM_RELEASE);
        g_general_tick_tramp = nullptr;
        return false;
    }
    write_abs_jmp(target, reinterpret_cast<uint64_t>(&hoiv_hook_general_tick));
    if (adapter::kCAIGeneralTickHookBytes > 14) {
        std::memset(target + 14, 0x90, adapter::kCAIGeneralTickHookBytes - 14);
    }
    FlushInstructionCache(GetCurrentProcess(), target, adapter::kCAIGeneralTickHookBytes);
    DWORD ignored = 0;
    VirtualProtect(target, adapter::kCAIGeneralTickHookBytes, old_protect, &ignored);
    g_orig_general_tick = reinterpret_cast<GeneralTickFn>(g_general_tick_tramp);
    g_general_patched.store(true);
    return true;
}

bool install_stolen_hook(
    uint32_t rva,
    uint32_t stolen,
    void* dest,
    uint8_t* saved,
    uint8_t** tramp_out) {
    if (g_module_base == nullptr || dest == nullptr || saved == nullptr || tramp_out == nullptr ||
        stolen < 14 || stolen > 24) {
        return false;
    }
    uint8_t* target = g_module_base + rva;
    uint8_t* tramp = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (tramp == nullptr) {
        return false;
    }
    std::memcpy(saved, target, stolen);
    std::memcpy(tramp, target, stolen);
    write_abs_jmp(tramp + stolen, reinterpret_cast<uint64_t>(target + stolen));
    DWORD old_protect = 0;
    if (!VirtualProtect(target, stolen, PAGE_EXECUTE_READWRITE, &old_protect)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    write_abs_jmp(target, reinterpret_cast<uint64_t>(dest));
    if (stolen > 14) {
        std::memset(target + 14, 0x90, stolen - 14);
    }
    FlushInstructionCache(GetCurrentProcess(), target, stolen);
    DWORD ignored = 0;
    VirtualProtect(target, stolen, old_protect, &ignored);
    *tramp_out = tramp;
    return true;
}

void remove_stolen_hook(uint32_t rva, uint32_t stolen, uint8_t* saved, uint8_t** tramp_out) {
    if (g_module_base != nullptr && saved != nullptr) {
        uint8_t* target = g_module_base + rva;
        DWORD old_protect = 0;
        if (VirtualProtect(target, stolen, PAGE_EXECUTE_READWRITE, &old_protect)) {
            std::memcpy(target, saved, stolen);
            FlushInstructionCache(GetCurrentProcess(), target, stolen);
            DWORD ignored = 0;
            VirtualProtect(target, stolen, old_protect, &ignored);
        }
    }
    if (tramp_out != nullptr && *tramp_out != nullptr) {
        VirtualFree(*tramp_out, 0, MEM_RELEASE);
        *tramp_out = nullptr;
    }
}

bool patch_org_create() {
    if (g_org_patched.load()) {
        return true;
    }
    if (!adapter::front_factory_bytes_match(g_module_base + adapter::kFrontFactoryRva) ||
        !adapter::front_tick_bytes_match(g_module_base + adapter::kFrontTickRva) ||
        !adapter::army_group_factory_bytes_match(g_module_base + adapter::kArmyGroupFactoryRva) ||
        !adapter::military_minister_create_bytes_match(
            g_module_base + adapter::kMilitaryMinisterCreateRva)) {
        return false;
    }
    if (!install_stolen_hook(
            adapter::kFrontFactoryRva,
            adapter::kFrontFactoryHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_front_factory),
            g_saved_front_factory,
            &g_front_factory_tramp)) {
        return false;
    }
    g_orig_front_factory = reinterpret_cast<FrontFactoryFn>(g_front_factory_tramp);
    if (!install_stolen_hook(
            adapter::kFrontTickRva,
            adapter::kFrontTickHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_front_tick),
            g_saved_front_tick,
            &g_front_tick_tramp)) {
        remove_stolen_hook(
            adapter::kFrontFactoryRva,
            adapter::kFrontFactoryHookBytes,
            g_saved_front_factory,
            &g_front_factory_tramp);
        g_orig_front_factory = nullptr;
        return false;
    }
    g_orig_front_tick = reinterpret_cast<FrontTickFn>(g_front_tick_tramp);
    if (!install_stolen_hook(
            adapter::kArmyGroupFactoryRva,
            adapter::kArmyGroupFactoryHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_ag_factory),
            g_saved_ag_factory,
            &g_ag_factory_tramp)) {
        remove_stolen_hook(
            adapter::kFrontTickRva, adapter::kFrontTickHookBytes, g_saved_front_tick, &g_front_tick_tramp);
        remove_stolen_hook(
            adapter::kFrontFactoryRva,
            adapter::kFrontFactoryHookBytes,
            g_saved_front_factory,
            &g_front_factory_tramp);
        g_orig_front_factory = nullptr;
        g_orig_front_tick = nullptr;
        return false;
    }
    g_orig_ag_factory = reinterpret_cast<ArmyGroupFactoryFn>(g_ag_factory_tramp);
    if (!install_stolen_hook(
            adapter::kMilitaryMinisterCreateRva,
            adapter::kMilitaryMinisterCreateHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_mil_create),
            g_saved_mil_create,
            &g_mil_create_tramp)) {
        remove_stolen_hook(
            adapter::kArmyGroupFactoryRva,
            adapter::kArmyGroupFactoryHookBytes,
            g_saved_ag_factory,
            &g_ag_factory_tramp);
        remove_stolen_hook(
            adapter::kFrontTickRva, adapter::kFrontTickHookBytes, g_saved_front_tick, &g_front_tick_tramp);
        remove_stolen_hook(
            adapter::kFrontFactoryRva,
            adapter::kFrontFactoryHookBytes,
            g_saved_front_factory,
            &g_front_factory_tramp);
        g_orig_front_factory = nullptr;
        g_orig_front_tick = nullptr;
        g_orig_ag_factory = nullptr;
        return false;
    }
    g_orig_mil_create = reinterpret_cast<MinisterCreateFn>(g_mil_create_tramp);
    g_org_patched.store(true);
    return true;
}

void reset_land_actor_probes() {
    g_probe_move_enters.store(0, std::memory_order_relaxed);
    g_probe_mass_enters.store(0, std::memory_order_relaxed);
    g_probe_exec_enters.store(0, std::memory_order_relaxed);
    g_probe_exec_tag.store(0, std::memory_order_relaxed);
    g_probe_exec_vt0.store(0, std::memory_order_relaxed);
    g_probe_exec_vt1.store(0, std::memory_order_relaxed);
    g_probe_exec_vt2.store(0, std::memory_order_relaxed);
    g_probe_mass_vt.store(0, std::memory_order_relaxed);
    g_probe_mass_tag.store(0, std::memory_order_relaxed);
    g_probe_move_vt.store(0, std::memory_order_relaxed);
    g_probe_move_tag.store(0, std::memory_order_relaxed);
    g_probe_mass_skips.store(0, std::memory_order_relaxed);
    g_probe_move_skips.store(0, std::memory_order_relaxed);
    g_probe_vol_enters.store(0, std::memory_order_relaxed);
    g_probe_vol_vt.store(0, std::memory_order_relaxed);
    g_probe_vol_tag.store(0, std::memory_order_relaxed);
    g_probe_vol_skips.store(0, std::memory_order_relaxed);
    g_probe_org_enters.store(0, std::memory_order_relaxed);
    g_probe_org_vt.store(0, std::memory_order_relaxed);
    g_probe_org_tag.store(0, std::memory_order_relaxed);
    g_probe_org_skips.store(0, std::memory_order_relaxed);
    g_probe_exec_skips.store(0, std::memory_order_relaxed);
    g_probe_ag_enters.store(0, std::memory_order_relaxed);
    g_probe_ag_vt.store(0, std::memory_order_relaxed);
    g_probe_ag_tag.store(0, std::memory_order_relaxed);
    g_probe_ag_skips.store(0, std::memory_order_relaxed);
    if (g_block != nullptr) {
        g_block->land_actor_move_enters = 0;
        g_block->land_actor_mass_enters = 0;
        g_block->land_actor_exec_enters = 0;
        g_block->land_actor_exec_tag = 0;
        g_block->land_actor_exec_vt0 = 0;
        g_block->land_actor_exec_vt1 = 0;
        g_block->land_actor_exec_vt2 = 0;
        g_block->land_actor_mass_vt = 0;
        g_block->land_actor_mass_tag = 0;
        g_block->land_actor_move_vt = 0;
        g_block->land_actor_move_tag = 0;
        g_block->land_actor_mass_skips = 0;
        g_block->land_actor_move_skips = 0;
        g_block->land_actor_vol_enters = 0;
        g_block->land_actor_vol_vt = 0;
        g_block->land_actor_vol_tag = 0;
        g_block->land_actor_vol_skips = 0;
        g_block->land_actor_org_enters = 0;
        g_block->land_actor_org_vt = 0;
        g_block->land_actor_org_tag = 0;
        g_block->land_actor_org_skips = 0;
        g_block->land_actor_exec_skips = 0;
        g_block->land_actor_ag_enters = 0;
        g_block->land_actor_ag_vt = 0;
        g_block->land_actor_ag_tag = 0;
        g_block->land_actor_ag_skips = 0;
    }
}

bool patch_land_actor_probes() {
    if (g_probe_patched.load()) {
        return true;
    }
    if (g_module_base == nullptr) {
        return false;
    }
    bool any = false;
    if (adapter::land_actor_move_bytes_match(g_module_base + adapter::kLandActorMoveRva) &&
        install_stolen_hook(
            adapter::kLandActorMoveRva,
            adapter::kLandActorMoveHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_probe_move),
            g_saved_probe_move,
            &g_probe_move_tramp)) {
        g_orig_probe_move = reinterpret_cast<LandActorProbeFn>(g_probe_move_tramp);
        any = true;
    }
    if (adapter::land_actor_mass_bytes_match(g_module_base + adapter::kLandActorMassRva) &&
        install_stolen_hook(
            adapter::kLandActorMassRva,
            adapter::kLandActorMassHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_probe_mass),
            g_saved_probe_mass,
            &g_probe_mass_tramp)) {
        g_orig_probe_mass = reinterpret_cast<LandActorProbeFn>(g_probe_mass_tramp);
        any = true;
    }
    if (adapter::land_actor_exec_bytes_match(g_module_base + adapter::kLandActorExecRva) &&
        install_stolen_hook(
            adapter::kLandActorExecRva,
            adapter::kLandActorExecHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_probe_exec),
            g_saved_probe_exec,
            &g_probe_exec_tramp)) {
        g_orig_probe_exec = reinterpret_cast<LandActorProbeFn>(g_probe_exec_tramp);
        any = true;
    }
    if (adapter::volunteer_tick_bytes_match(g_module_base + adapter::kCAIVolunteerGeneralTickRva) &&
        install_stolen_hook(
            adapter::kCAIVolunteerGeneralTickRva,
            adapter::kCAIVolunteerGeneralTickHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_volunteer_tick),
            g_saved_probe_vol,
            &g_probe_vol_tramp)) {
        g_orig_probe_vol = reinterpret_cast<GeneralTickFn>(g_probe_vol_tramp);
        any = true;
    }
    if (adapter::land_org_helper_bytes_match(g_module_base + adapter::kLandOrgHelperRva) &&
        install_stolen_hook(
            adapter::kLandOrgHelperRva,
            adapter::kLandOrgHelperHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_org_helper),
            g_saved_probe_org,
            &g_probe_org_tramp)) {
        g_orig_probe_org = reinterpret_cast<LandActorProbeFn>(g_probe_org_tramp);
        any = true;
    }
    if (adapter::general_org_bytes_match(g_module_base + adapter::kCAIGeneralOrgRva) &&
        install_stolen_hook(
            adapter::kCAIGeneralOrgRva,
            adapter::kCAIGeneralOrgHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_general_org),
            g_saved_general_org,
            &g_general_org_tramp)) {
        g_orig_general_org = reinterpret_cast<LandActorProbeFn>(g_general_org_tramp);
        any = true;
    }
    if (adapter::mass_move_can_bytes_match(g_module_base + adapter::kCMassMoveCommandCanRva) &&
        install_stolen_hook(
            adapter::kCMassMoveCommandCanRva,
            adapter::kCMassMoveCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_mass_move_can),
            g_saved_mass_move_can,
            &g_mass_move_can_tramp)) {
        g_orig_mass_move_can = reinterpret_cast<MassMoveCanFn>(g_mass_move_can_tramp);
        any = true;
    }
    if (adapter::set_theatre_can_bytes_match(g_module_base + adapter::kCSetTheatreCommandCanRva) &&
        install_stolen_hook(
            adapter::kCSetTheatreCommandCanRva,
            adapter::kCSetTheatreCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_theatre_can),
            g_saved_theatre_can,
            &g_theatre_can_tramp)) {
        g_orig_theatre_can = reinterpret_cast<OrgCommandCanFn>(g_theatre_can_tramp);
        any = true;
    }
    if (adapter::army_group_can_bytes_match(g_module_base + adapter::kCArmyGroupCommandCanRva) &&
        install_stolen_hook(
            adapter::kCArmyGroupCommandCanRva,
            adapter::kCArmyGroupCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_ag_can),
            g_saved_ag_can,
            &g_ag_can_tramp)) {
        g_orig_ag_can = reinterpret_cast<OrgCommandCanFn>(g_ag_can_tramp);
        any = true;
    }
    if (adapter::assign_army_group_can_bytes_match(
            g_module_base + adapter::kCAssignToArmyGroupCommandCanRva) &&
        install_stolen_hook(
            adapter::kCAssignToArmyGroupCommandCanRva,
            adapter::kCAssignToArmyGroupCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_assign_ag_can),
            g_saved_assign_ag_can,
            &g_assign_ag_can_tramp)) {
            g_orig_assign_ag_can = reinterpret_cast<OrgCommandCanFn>(g_assign_ag_can_tramp);
        any = true;
    }
    if (adapter::new_front_can_bytes_match(
            g_module_base + adapter::kCOrderNewFrontCommandCanRva) &&
        install_stolen_hook(
            adapter::kCOrderNewFrontCommandCanRva,
            adapter::kCOrderNewFrontCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_front_can),
            g_saved_front_can,
            &g_front_can_tramp)) {
        g_orig_front_can = reinterpret_cast<OrgCommandCanFn>(g_front_can_tramp);
        any = true;
    }
    if (adapter::order_group_can_bytes_match(
            g_module_base + adapter::kCOrderGroupCommandCanRva) &&
        install_stolen_hook(
            adapter::kCOrderGroupCommandCanRva,
            adapter::kCOrderGroupCommandCanHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_order_group_can),
            g_saved_order_group_can,
            &g_order_group_can_tramp)) {
        g_orig_order_group_can = reinterpret_cast<OrgCommandCanFn>(g_order_group_can_tramp);
        any = true;
    }
    if (adapter::theatre_ai_create_bytes_match(g_module_base + adapter::kTheatreAiCreateRva) &&
        install_stolen_hook(
            adapter::kTheatreAiCreateRva,
            adapter::kTheatreAiCreateHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_theatre_ai_create),
            g_saved_theatre_ai,
            &g_theatre_ai_tramp)) {
        g_orig_theatre_ai = reinterpret_cast<LandActorProbeFn>(g_theatre_ai_tramp);
        any = true;
    }
    if (adapter::theatre_create_gate_bytes_match(g_module_base + adapter::kTheatreCreateGateRva) &&
        install_stolen_hook(
            adapter::kTheatreCreateGateRva,
            adapter::kTheatreCreateGateHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_theatre_create_gate),
            g_saved_theatre_gate,
            &g_theatre_gate_tramp)) {
        g_orig_theatre_gate = reinterpret_cast<LandActorProbeFn>(g_theatre_gate_tramp);
        any = true;
    }
    if (adapter::theatre_ctor_bytes_match(g_module_base + adapter::kCTheatreCtorRva) &&
        install_stolen_hook(
            adapter::kCTheatreCtorRva,
            adapter::kCTheatreCtorHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_theatre_ctor),
            g_saved_theatre_ctor,
            &g_theatre_ctor_tramp)) {
        g_orig_theatre_ctor = reinterpret_cast<LandActorProbeFn>(g_theatre_ctor_tramp);
        any = true;
    }
    if (adapter::area_defense_ai_bytes_match(g_module_base + adapter::kAreaDefenseAiRva) &&
        install_stolen_hook(
            adapter::kAreaDefenseAiRva,
            adapter::kAreaDefenseAiHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_area_defense_ai),
            g_saved_area_def_ai,
            &g_area_def_ai_tramp)) {
        g_orig_area_def_ai = reinterpret_cast<LandActorProbeFn>(g_area_def_ai_tramp);
        any = true;
    }
    if (adapter::army_group_ai_bytes_match(g_module_base + adapter::kArmyGroupAiRva) &&
        install_stolen_hook(
            adapter::kArmyGroupAiRva,
            adapter::kArmyGroupAiHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_army_group_ai),
            g_saved_ag_ai,
            &g_ag_ai_tramp)) {
        g_orig_ag_ai = reinterpret_cast<LandActorProbeFn>(g_ag_ai_tramp);
        any = true;
    }
    if (adapter::army_ai_bytes_match(g_module_base + adapter::kArmyAiRva) &&
        install_stolen_hook(
            adapter::kArmyAiRva,
            adapter::kArmyAiHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_army_ai),
            g_saved_army_ai,
            &g_army_ai_tramp)) {
        g_orig_army_ai = reinterpret_cast<LandActorProbeFn>(g_army_ai_tramp);
        any = true;
    }
    if (adapter::army_ai2_bytes_match(g_module_base + adapter::kArmyAi2Rva) &&
        install_stolen_hook(
            adapter::kArmyAi2Rva,
            adapter::kArmyAi2HookBytes,
            reinterpret_cast<void*>(&hoiv_hook_army_ai2),
            g_saved_army_ai2,
            &g_army_ai2_tramp)) {
        g_orig_army_ai2 = reinterpret_cast<LandActorProbeFn>(g_army_ai2_tramp);
        any = true;
    }
    g_probe_patched.store(any);
    return any;
}

void restore_land_actor_probes() {
    if (!g_probe_patched.load() && g_probe_move_tramp == nullptr && g_probe_mass_tramp == nullptr &&
        g_probe_exec_tramp == nullptr && g_probe_vol_tramp == nullptr &&
        g_probe_org_tramp == nullptr && g_general_org_tramp == nullptr &&
        g_mass_move_can_tramp == nullptr && g_theatre_can_tramp == nullptr &&
        g_ag_can_tramp == nullptr && g_assign_ag_can_tramp == nullptr &&
        g_front_can_tramp == nullptr && g_order_group_can_tramp == nullptr &&
        g_theatre_ai_tramp == nullptr && g_theatre_gate_tramp == nullptr &&
        g_theatre_ctor_tramp == nullptr &&
        g_area_def_ai_tramp == nullptr && g_ag_ai_tramp == nullptr &&
        g_army_ai_tramp == nullptr && g_army_ai2_tramp == nullptr) {
        reset_land_actor_probes();
        return;
    }
    remove_stolen_hook(
        adapter::kArmyAi2Rva,
        adapter::kArmyAi2HookBytes,
        g_saved_army_ai2,
        &g_army_ai2_tramp);
    remove_stolen_hook(
        adapter::kArmyAiRva,
        adapter::kArmyAiHookBytes,
        g_saved_army_ai,
        &g_army_ai_tramp);
    remove_stolen_hook(
        adapter::kArmyGroupAiRva,
        adapter::kArmyGroupAiHookBytes,
        g_saved_ag_ai,
        &g_ag_ai_tramp);
    remove_stolen_hook(
        adapter::kAreaDefenseAiRva,
        adapter::kAreaDefenseAiHookBytes,
        g_saved_area_def_ai,
        &g_area_def_ai_tramp);
    remove_stolen_hook(
        adapter::kCTheatreCtorRva,
        adapter::kCTheatreCtorHookBytes,
        g_saved_theatre_ctor,
        &g_theatre_ctor_tramp);
    remove_stolen_hook(
        adapter::kTheatreCreateGateRva,
        adapter::kTheatreCreateGateHookBytes,
        g_saved_theatre_gate,
        &g_theatre_gate_tramp);
    remove_stolen_hook(
        adapter::kTheatreAiCreateRva,
        adapter::kTheatreAiCreateHookBytes,
        g_saved_theatre_ai,
        &g_theatre_ai_tramp);
    remove_stolen_hook(
        adapter::kCOrderGroupCommandCanRva,
        adapter::kCOrderGroupCommandCanHookBytes,
        g_saved_order_group_can,
        &g_order_group_can_tramp);
    remove_stolen_hook(
        adapter::kCOrderNewFrontCommandCanRva,
        adapter::kCOrderNewFrontCommandCanHookBytes,
        g_saved_front_can,
        &g_front_can_tramp);
    remove_stolen_hook(
        adapter::kCAssignToArmyGroupCommandCanRva,
        adapter::kCAssignToArmyGroupCommandCanHookBytes,
        g_saved_assign_ag_can,
        &g_assign_ag_can_tramp);
    remove_stolen_hook(
        adapter::kCArmyGroupCommandCanRva,
        adapter::kCArmyGroupCommandCanHookBytes,
        g_saved_ag_can,
        &g_ag_can_tramp);
    remove_stolen_hook(
        adapter::kCSetTheatreCommandCanRva,
        adapter::kCSetTheatreCommandCanHookBytes,
        g_saved_theatre_can,
        &g_theatre_can_tramp);
    remove_stolen_hook(
        adapter::kCAIGeneralOrgRva,
        adapter::kCAIGeneralOrgHookBytes,
        g_saved_general_org,
        &g_general_org_tramp);
    remove_stolen_hook(
        adapter::kLandOrgHelperRva,
        adapter::kLandOrgHelperHookBytes,
        g_saved_probe_org,
        &g_probe_org_tramp);
    remove_stolen_hook(
        adapter::kCMassMoveCommandCanRva,
        adapter::kCMassMoveCommandCanHookBytes,
        g_saved_mass_move_can,
        &g_mass_move_can_tramp);
    remove_stolen_hook(
        adapter::kCAIVolunteerGeneralTickRva,
        adapter::kCAIVolunteerGeneralTickHookBytes,
        g_saved_probe_vol,
        &g_probe_vol_tramp);
    remove_stolen_hook(
        adapter::kLandActorExecRva,
        adapter::kLandActorExecHookBytes,
        g_saved_probe_exec,
        &g_probe_exec_tramp);
    remove_stolen_hook(
        adapter::kLandActorMassRva,
        adapter::kLandActorMassHookBytes,
        g_saved_probe_mass,
        &g_probe_mass_tramp);
    remove_stolen_hook(
        adapter::kLandActorMoveRva,
        adapter::kLandActorMoveHookBytes,
        g_saved_probe_move,
        &g_probe_move_tramp);
    g_orig_probe_move = nullptr;
    g_orig_probe_mass = nullptr;
    g_orig_probe_exec = nullptr;
    g_orig_probe_vol = nullptr;
    g_orig_probe_org = nullptr;
    g_orig_general_org = nullptr;
    g_orig_mass_move_can = nullptr;
    g_orig_theatre_can = nullptr;
    g_orig_ag_can = nullptr;
    g_orig_assign_ag_can = nullptr;
    g_orig_front_can = nullptr;
    g_orig_order_group_can = nullptr;
    g_orig_theatre_ai = nullptr;
    g_orig_theatre_gate = nullptr;
    g_orig_theatre_ctor = nullptr;
    g_orig_area_def_ai = nullptr;
    g_orig_ag_ai = nullptr;
    g_orig_army_ai = nullptr;
    g_orig_army_ai2 = nullptr;
    g_probe_patched.store(false);
    reset_land_actor_probes();
}

void restore_org_create() {
    if (!g_org_patched.load()) {
        return;
    }
    remove_stolen_hook(
        adapter::kMilitaryMinisterCreateRva,
        adapter::kMilitaryMinisterCreateHookBytes,
        g_saved_mil_create,
        &g_mil_create_tramp);
    remove_stolen_hook(
        adapter::kArmyGroupFactoryRva,
        adapter::kArmyGroupFactoryHookBytes,
        g_saved_ag_factory,
        &g_ag_factory_tramp);
    remove_stolen_hook(
        adapter::kFrontTickRva, adapter::kFrontTickHookBytes, g_saved_front_tick, &g_front_tick_tramp);
    remove_stolen_hook(
        adapter::kFrontFactoryRva,
        adapter::kFrontFactoryHookBytes,
        g_saved_front_factory,
        &g_front_factory_tramp);
    g_orig_front_factory = nullptr;
    g_orig_front_tick = nullptr;
    g_orig_ag_factory = nullptr;
    g_orig_mil_create = nullptr;
    g_org_patched.store(false);
}

void restore_general_tick() {
    if (!g_general_patched.load() || g_module_base == nullptr) {
        g_general_patched.store(false);
        g_orig_general_tick = nullptr;
        if (g_general_tick_tramp != nullptr) {
            VirtualFree(g_general_tick_tramp, 0, MEM_RELEASE);
            g_general_tick_tramp = nullptr;
        }
        return;
    }
    uint8_t* target = g_module_base + adapter::kCAIGeneralTickRva;
    DWORD old_protect = 0;
    if (VirtualProtect(target, adapter::kCAIGeneralTickHookBytes, PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::memcpy(target, g_saved_general_tick, adapter::kCAIGeneralTickHookBytes);
        FlushInstructionCache(GetCurrentProcess(), target, adapter::kCAIGeneralTickHookBytes);
        DWORD ignored = 0;
        VirtualProtect(target, adapter::kCAIGeneralTickHookBytes, old_protect, &ignored);
    }
    g_orig_general_tick = nullptr;
    if (g_general_tick_tramp != nullptr) {
        VirtualFree(g_general_tick_tramp, 0, MEM_RELEASE);
        g_general_tick_tramp = nullptr;
    }
    g_general_patched.store(false);
}

bool patch_move_gate() {
    if (g_move_patched.load()) {
        return true;
    }
    if (!move_signatures_match() ||
        !adapter::move_can_padding_safe(g_module_base + adapter::kMoveCanExecuteRva) ||
        !adapter::move_do_padding_safe(g_module_base + adapter::kMoveExecuteRva)) {
        return false;
    }
    if (!patch_abs_jmp(
            g_module_base + adapter::kMoveCanExecuteRva,
            adapter::kMoveCanExecuteHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_move_can_execute),
            g_saved_move_can)) {
        return false;
    }
    if (!patch_abs_jmp(
            g_module_base + adapter::kMoveExecuteRva,
            adapter::kMoveExecuteHookBytes,
            reinterpret_cast<void*>(&hoiv_hook_move_execute),
            g_saved_move_do)) {
        restore_abs_jmp(
            g_module_base + adapter::kMoveCanExecuteRva,
            adapter::kMoveCanExecuteHookBytes,
            g_saved_move_can);
        return false;
    }
    g_move_patched.store(true);
    return true;
}

void restore_move_gate() {
    if (!g_move_patched.load() || g_module_base == nullptr) {
        g_move_patched.store(false);
        return;
    }
    restore_abs_jmp(
        g_module_base + adapter::kMoveExecuteRva,
        adapter::kMoveExecuteHookBytes,
        g_saved_move_do);
    restore_abs_jmp(
        g_module_base + adapter::kMoveCanExecuteRva,
        adapter::kMoveCanExecuteHookBytes,
        g_saved_move_can);
    g_move_patched.store(false);
}

}  // namespace

void game_reader_bind(void* shared_block) {
    g_block = static_cast<SharedBlock*>(shared_block);
}

bool game_reader_install() {
    if (g_patched.load() && g_iat_patched.load()) {
        g_armed.store(true);
        return true;
    }
    if (!resolve_module() || !signatures_match()) {
        return false;
    }
    if (!patch_get_player()) {
        return false;
    }
    if (!patch_peek_message()) {
        restore_get_player();
        return false;
    }
    reset_land_actor_probes();
    patch_land_actor_probes();
    g_last_capture_ms.store(0);
    g_armed.store(true);
    return true;
}

void game_reader_uninstall() {
    g_armed.store(false);
    g_track_id = 0;
    g_track_gen = 0;
    g_hold_land_ai.store(false);
    g_land_ai_general.store(false);
    g_land_ai_org_create.store(false);
    g_restored_global_ai.store(false);
    g_last_handle_snapshot_ms = 0;
    std::memset(g_major_handle_hash, 0, sizeof(g_major_handle_hash));
    restore_land_actor_probes();
    restore_org_create();
    restore_general_tick();
    restore_move_gate();
    restore_peek_message();
    restore_get_player();
    clear_snapshot();
}

void game_reader_clear() {
    g_track_id = 0;
    g_track_gen = 0;
    g_hold_land_ai.store(false);
    g_land_ai_general.store(false);
    g_land_ai_org_create.store(false);
    g_restored_global_ai.store(false);
    g_last_handle_snapshot_ms = 0;
    std::memset(g_major_handle_hash, 0, sizeof(g_major_handle_hash));
    clear_snapshot();
}

bool game_reader_is_armed() {
    return g_armed.load();
}

}  // namespace hoiv
