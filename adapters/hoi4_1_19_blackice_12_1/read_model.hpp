#pragma once

#include "layout.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace hoiv::adapter {

inline bool is_canonical_user_pointer(uint64_t address) {
    return address >= 0x10000ull && address < 0x00007FFFFFFE0000ull && (address & 0x7) == 0;
}

inline bool pdx_array_bounds_ok(int32_t size, int32_t capacity, int32_t max_size) {
    return size >= 0 && capacity >= size && capacity < 10000 && size <= max_size;
}

inline bool bytes_equal(const uint8_t* actual, const uint8_t* expected, uint32_t count) {
    return actual != nullptr && expected != nullptr && std::memcmp(actual, expected, count) == 0;
}

inline bool get_player_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kGetPlayerBytes, kGetPlayerByteCount);
}

inline bool get_armies_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kGetArmiesBytes, kGetArmiesByteCount);
}

inline bool get_player_padding_safe(const uint8_t* bytes) {
    if (bytes == nullptr) {
        return false;
    }
    for (uint32_t i = kGetPlayerByteCount; i < kGetPlayerHookBytes; ++i) {
        if (bytes[i] != 0xCC) {
            return false;
        }
    }
    return true;
}

inline bool is_known_gamestate_vtable(uint64_t vtable, uint64_t module_base) {
    return vtable == module_base + kCCurrentGameStateVtableRva || vtable == module_base + kCGameStateVtableRva;
}

inline bool is_country_ai_vtable(uint64_t vtable, uint64_t module_base) {
    return vtable == module_base + kCCountryAIVtableRva || vtable == module_base + kCCountryAIVtableAltRva;
}

inline bool is_land_general_vtable(uint64_t vtable, uint64_t module_base) {
    return vtable == module_base + kCAIGeneralVtableRva ||
        vtable == module_base + kCAIVolunteerGeneralVtableRva;
}

inline bool is_military_minister_vtable(uint64_t vtable, uint64_t module_base) {
    return vtable == module_base + kCAIMilitaryMinisterVtableRva;
}

inline bool tag_matches(uint32_t player_tag, uint32_t country_tag) {
    return player_tag == country_tag;
}

inline bool player_index_ok(int32_t index, int32_t country_count) {
    return index >= 0 && index < country_count;
}

inline bool country_tag_usable(int32_t tag) {
    return tag != 0;
}

inline bool human_flag_set(uint8_t flag) {
    return flag != 0;
}

inline bool is_three_letter_tag(const char* text) {
    return text != nullptr && text[0] >= 'A' && text[0] <= 'Z' && text[1] >= 'A' &&
        text[1] <= 'Z' && text[2] >= 'A' && text[2] <= 'Z' && text[3] == '\0';
}

inline constexpr int32_t kLiveSampleCountryTag = kGermanyTestCountryTag;

// Historical P0 fingerprints. Live capture uses kLiveSampleCountryTag.
inline constexpr int32_t kSwissTestCountryTag = 29;

// BlackICE strategic region 210 (Switzerland). St. Gallen is 11623.
// 6945 is Afyon / Asia Minor — a previous false read.
inline constexpr int32_t kSwissTestProvinces[] = {
    636, 658, 661, 663, 3612, 3641, 3660, 3662, 6666, 6683, 9587, 9600, 9618,
    9620, 9622, 9638, 11590, 11601, 11604, 11623, 13124};
inline constexpr int32_t kSwissTestProvinceCount =
    static_cast<int32_t>(sizeof(kSwissTestProvinces) / sizeof(kSwissTestProvinces[0]));
inline constexpr int32_t kStGallenProvince = 11623;

inline bool parse_division_display_name(const char* text, int32_t* number) {
    if (text == nullptr || number == nullptr) {
        return false;
    }
    if (std::memcmp(text, "Division ", 9) != 0) {
        return false;
    }
    int32_t value = 0;
    const char* cursor = text + 9;
    if (*cursor < '1' || *cursor > '9') {
        return false;
    }
    while (*cursor >= '0' && *cursor <= '9') {
        value = value * 10 + (*cursor - '0');
        ++cursor;
        if (value > 99) {
            return false;
        }
    }
    if (*cursor != '\0' && *cursor != ' ' && *cursor != '(') {
        return false;
    }
    *number = value;
    return value > 0;
}

inline bool is_org_display_fourteen(float value) {
    return value >= 13.99f && value <= 14.01f;
}

inline bool is_strength_display_thirty(float value) {
    return value >= 0.29f && value <= 0.31f;
}

inline bool is_org_ratio_full(float value) {
    return value >= 0.99f && value <= 1.01f;
}

inline double fixed_point_to_display(int64_t value) {
    return static_cast<double>(value) / static_cast<double>(kFixedPointOne);
}

inline int32_t fixed_point_display_trunc(int64_t value) {
    return static_cast<int32_t>(value / kFixedPointOne);
}

inline bool is_swiss_org_display_pair(int64_t current, int64_t maximum) {
    return fixed_point_display_trunc(current) == 14 && fixed_point_display_trunc(maximum) == 14;
}

inline bool is_org_max_near_swiss_ui(int64_t maximum) {
    const double value = fixed_point_to_display(maximum);
    return value >= 14.90 && value <= 15.10;
}

inline bool move_ctor_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kMoveCommandBytes, kMoveCommandByteCount);
}

inline bool move_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kMoveCanExecuteBytes, kMoveCanExecuteByteCount);
}

inline bool move_do_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kMoveExecuteBytes, kMoveExecuteByteCount);
}

inline bool int3_padding_safe(const uint8_t* bytes, uint32_t used, uint32_t hooked) {
    if (bytes == nullptr || hooked < used) {
        return false;
    }
    for (uint32_t i = used; i < hooked; ++i) {
        if (bytes[i] != 0xCC) {
            return false;
        }
    }
    return true;
}

inline bool move_can_padding_safe(const uint8_t* bytes) {
    return int3_padding_safe(bytes, kMoveCanExecuteByteCount, kMoveCanExecuteHookBytes);
}

inline bool move_do_padding_safe(const uint8_t* bytes) {
    return int3_padding_safe(bytes, kMoveExecuteByteCount, kMoveExecuteHookBytes);
}

inline bool army_ai_issue_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kArmyAiIssueBytes, kArmyAiIssueByteCount);
}

inline uint64_t pack_army_handle(int32_t id, int32_t generation) {
    return static_cast<uint32_t>(id) |
        (static_cast<uint64_t>(static_cast<uint32_t>(generation)) << 32);
}

inline uint32_t major_handle_hash_index(uint64_t packed, uint32_t slots) {
    const uint64_t mixed = packed * 0x9E3779B97F4A7C15ull;
    return static_cast<uint32_t>(mixed >> 32) & (slots - 1u);
}

inline bool major_handle_hash_insert(uint64_t* table, uint32_t slots, uint64_t packed) {
    if (table == nullptr || slots == 0 || (slots & (slots - 1u)) != 0 || packed == 0) {
        return false;
    }
    uint32_t i = major_handle_hash_index(packed, slots);
    for (uint32_t n = 0; n < slots; ++n) {
        if (table[i] == 0 || table[i] == packed) {
            table[i] = packed;
            return true;
        }
        i = (i + 1u) & (slots - 1u);
    }
    return false;
}

inline bool major_handle_hash_has(const uint64_t* table, uint32_t slots, uint64_t packed) {
    if (table == nullptr || slots == 0 || (slots & (slots - 1u)) != 0 || packed == 0) {
        return false;
    }
    uint32_t i = major_handle_hash_index(packed, slots);
    for (uint32_t n = 0; n < slots; ++n) {
        const uint64_t value = table[i];
        if (value == 0) {
            return false;
        }
        if (value == packed) {
            return true;
        }
        i = (i + 1u) & (slots - 1u);
    }
    return false;
}

inline bool cancel_ctor_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCancelCommandBytes, kCancelCommandByteCount);
}

inline bool cancel_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCancelCanExecuteBytes, kCancelCanExecuteByteCount);
}

inline bool cancel_do_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCancelExecuteBytes, kCancelExecuteByteCount);
}

inline bool writes_allowed(uint8_t enabled, uint8_t read_only, uint32_t max_orders_per_hour) {
    return enabled != 0 && read_only == 0 && max_orders_per_hour > 0;
}

inline bool country_ai_commands_check_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCountryAiCommandsCheckBytes, kCountryAiCommandsCheckByteCount);
}

inline bool ai_writes_allowed(uint8_t enabled, uint8_t read_only) {
    return enabled != 0 && read_only == 0;
}

inline bool is_major_country_tag(int32_t tag) {
    return tag >= kMajorCountryTagBegin && tag <= kMajorCountryTagEnd;
}

inline bool country_ai_commands_off(uint8_t flag) {
    return flag == kCountryAiCommandsOffValue;
}

inline bool country_ai_backref_ok(uint64_t back, uint64_t country) {
    return back != 0 && country != 0 && back == country;
}

inline bool global_ai_toggle_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kGlobalAiToggleBytes, kGlobalAiToggleByteCount);
}

inline bool country_ai_pointer_store_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCountryAiPointerStoreBytes, kCountryAiPointerStoreByteCount);
}

inline bool orders_group_can_ai_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kOrdersGroupCanAiBytes, kOrdersGroupCanAiByteCount);
}

inline bool country_command_groups_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCountryCommandGroupsBytes, kCountryCommandGroupsByteCount);
}

inline bool get_ai_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kGetAiBytes, kGetAiByteCount);
}

inline bool general_tick_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCAIGeneralTickBytes, kCAIGeneralTickByteCount);
}

inline bool front_factory_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kFrontFactoryBytes, kFrontFactoryByteCount);
}

inline bool front_tick_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kFrontTickBytes, kFrontTickByteCount);
}

inline bool army_group_factory_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kArmyGroupFactoryBytes, kArmyGroupFactoryByteCount);
}

inline bool military_minister_create_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kMilitaryMinisterCreateBytes, kMilitaryMinisterCreateByteCount);
}

inline bool land_actor_move_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kLandActorMoveBytes, kLandActorMoveByteCount);
}

inline bool land_actor_mass_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kLandActorMassBytes, kLandActorMassByteCount);
}

inline bool mass_move_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCMassMoveCommandCanBytes, kCMassMoveCommandCanByteCount);
}

inline bool land_actor_exec_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kLandActorExecBytes, kLandActorExecByteCount);
}

inline bool volunteer_tick_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCAIVolunteerGeneralTickBytes, kCAIVolunteerGeneralTickByteCount);
}

inline bool land_org_helper_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kLandOrgHelperBytes, kLandOrgHelperByteCount);
}

inline bool general_org_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCAIGeneralOrgBytes, kCAIGeneralOrgByteCount);
}

inline bool set_theatre_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCSetTheatreCommandCanBytes, kCSetTheatreCommandCanByteCount);
}

inline bool army_group_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCArmyGroupCommandCanBytes, kCArmyGroupCommandCanByteCount);
}

inline bool assign_army_group_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCAssignToArmyGroupCommandCanBytes, kCAssignToArmyGroupCommandCanByteCount);
}

inline bool theatre_ai_create_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kTheatreAiCreateBytes, kTheatreAiCreateByteCount);
}

inline bool theatre_create_gate_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kTheatreCreateGateBytes, kTheatreCreateGateByteCount);
}

inline bool theatre_ctor_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCTheatreCtorBytes, kCTheatreCtorByteCount);
}

inline bool new_front_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCOrderNewFrontCommandCanBytes, kCOrderNewFrontCommandCanByteCount);
}

inline bool area_defense_ai_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kAreaDefenseAiBytes, kAreaDefenseAiByteCount);
}

inline bool army_group_ai_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kArmyGroupAiBytes, kArmyGroupAiByteCount);
}

inline bool army_ai_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kArmyAiBytes, kArmyAiByteCount);
}

inline bool army_ai2_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kArmyAi2Bytes, kArmyAi2ByteCount);
}

inline bool order_group_can_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCOrderGroupCommandCanBytes, kCOrderGroupCommandCanByteCount);
}

inline bool order_group_ctor_b_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCOrderGroupCommandCtorBBytes, kCOrderGroupCommandCtorBByteCount);
}

inline bool army_group_ctor_b_bytes_match(const uint8_t* bytes) {
    return bytes_equal(bytes, kCArmyGroupCommandCtorBBytes, kCArmyGroupCommandCtorBByteCount);
}

inline bool is_orders_or_army_group_vtable(uint64_t vtable, uint64_t orders_vt, uint64_t army_vt) {
    return vtable != 0 && (vtable == orders_vt || vtable == army_vt);
}

inline bool orders_group_ai_blocked(uint8_t flag) {
    return flag == kOrdersGroupAiBlockValue;
}

inline bool global_ai_flag_on(uint8_t flag) {
    return flag == kGlobalAiOnValue;
}

inline bool army_handle_usable(int32_t id, int32_t generation) {
    if (id == 0 && generation == 0) {
        return false;
    }
    const uint64_t packed = static_cast<uint32_t>(id) |
        (static_cast<uint64_t>(static_cast<uint32_t>(generation)) << 32);
    return !is_canonical_user_pointer(packed);
}

inline bool army_handle_id_match(int32_t id, int32_t want_id) {
    return want_id != 0 && id == want_id;
}

inline bool army_handle_match(int32_t id, int32_t gen, int32_t want_id, int32_t want_gen) {
    return army_handle_id_match(id, want_id) && gen == want_gen;
}

inline bool is_hp_display_one_sixty_six(int64_t value) {
    const double hp = fixed_point_to_display(value);
    return hp >= 166.85 && hp <= 166.95;
}

inline bool army_stat_ratio(int64_t current, int64_t maximum, float* out) {
    if (out == nullptr || current < 0) {
        return false;
    }
    const int64_t denom = maximum > kArmyStatFloor ? maximum : kArmyStatFloor;
    double value = static_cast<double>(current) / static_cast<double>(denom);
    if (value < 0.0) {
        value = 0.0;
    }
    if (value > 1.0) {
        value = 1.0;
    }
    *out = static_cast<float>(value);
    return true;
}

inline bool is_swiss_test_province(int32_t province) {
    for (int32_t i = 0; i < kSwissTestProvinceCount; ++i) {
        if (kSwissTestProvinces[i] == province) {
            return true;
        }
    }
    return false;
}

inline bool province_id_ok(int32_t province) {
    return province > 0 && province < 20000;
}

inline bool swiss_test_move_target_ok(int32_t from_province, int32_t to_province) {
    return from_province == kStGallenProvince && province_id_ok(to_province) &&
        to_province != from_province && is_swiss_test_province(to_province);
}

inline bool move_target_ok(int32_t from_province, int32_t to_province) {
    return province_id_ok(from_province) && province_id_ok(to_province) &&
        to_province != from_province;
}

inline void format_country_tag(uint32_t tag, char* out, size_t out_n) {
    if (out == nullptr || out_n == 0) {
        return;
    }
    std::memset(out, 0, out_n);
    const char a = static_cast<char>(tag & 0xFF);
    const char b = static_cast<char>((tag >> 8) & 0xFF);
    const char c = static_cast<char>((tag >> 16) & 0xFF);
    const auto letter = [](char ch) { return ch >= 'A' && ch <= 'Z'; };
    if (out_n >= 4 && letter(a) && letter(b) && letter(c) && ((tag >> 24) == 0)) {
        out[0] = a;
        out[1] = b;
        out[2] = c;
        return;
    }
    if (out_n >= 8) {
        // Index-style tags: print unsigned decimal.
        uint32_t value = tag;
        char tmp[16];
        int n = 0;
        if (value == 0) {
            tmp[n++] = '0';
        }
        while (value > 0 && n < 10) {
            tmp[n++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        }
        int w = 0;
        while (n > 0 && static_cast<size_t>(w + 1) < out_n) {
            out[w++] = tmp[--n];
        }
    }
}

struct LiveRead {
    uint8_t game_started = 0;
    uint8_t country_ok = 0;
    uint8_t division_ok = 0;
    uint8_t org_valid = 0;
    int32_t player_tag = 0;
    int32_t country_count = 0;
    int32_t country_index = -1;
    int32_t division_id = 0;
    int32_t division_generation = 0;
    int32_t division_province = 0;
    float organization = 0.0f;
    uint32_t diag_vt_ok = 0;
    uint32_t diag_tag_nz = 0;
    int32_t diag_vote_idx = -1;
    uint32_t diag_vote_n = 0;
    uint32_t diag_actor_rva = 0;
    int32_t diag_armies = 0;
    int32_t diag_units = 0;
    int64_t org_current = 0;
    int64_t org_max = 0;
    int64_t hp_current = 0;
    int64_t hp_max = 0;
    float hp = 0.0f;
    char tag_text[8] {};
};

}  // namespace hoiv::adapter
