#include "../../../adapters/hoi4_1_19_blackice_12_1/adapter.hpp"
#include "../../../adapters/hoi4_1_19_blackice_12_1/read_model.hpp"
#include "../../../bridge/include/hook_manager.hpp"
#include "../../../bridge/include/version_gate.hpp"
#include "../../../shared/config/config.hpp"
#include "../../../shared/identity/identity.hpp"
#include "../../../shared/ipc/session.hpp"
#include "../../../shared/loader/remote_load.hpp"
#include "../../../shared/process/process.hpp"
#include "../../../shared/win/utf8.hpp"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <string>

namespace {

int g_failures = 0;

void expect(bool cond, const char* name) {
    if (cond) {
        std::printf("PASS %s\n", name);
    } else {
        std::printf("FAIL %s\n", name);
        ++g_failures;
    }
}

std::wstring temp_dir() {
    wchar_t path[MAX_PATH];
    const DWORD n = GetTempPathW(MAX_PATH, path);
    return hoiv::join_path(std::wstring(path, path + n), L"HoiV-p0");
}

bool write_text(const std::wstring& path, const std::string& text) {
    std::ofstream out(path.c_str(), std::ios::trunc);
    if (!out) {
        return false;
    }
    out << text;
    return true;
}

hoiv::RuntimeConfig pinned_config(const hoiv::FileIdentity& exe, const std::wstring& blackice) {
    hoiv::RuntimeConfig cfg = hoiv::default_runtime_config();
    cfg.exe_path = exe.path;
    cfg.expected_sha256_hex = exe.sha256_hex;
    cfg.expected_pe_timestamp = exe.pe_timestamp;
    cfg.expected_product_version = hoiv::adapter::kHoi4VersionPrefix;
    cfg.blackice_descriptor = blackice;
    cfg.expected_blackice_version = hoiv::adapter::kBlackIceVersionPrefix;
    cfg.allow_test_host = 1;
    return cfg;
}

void test_defaults() {
    const hoiv::RuntimeConfig cfg = hoiv::default_runtime_config();
    expect(cfg.enabled == 0, "default enabled=0");
    expect(cfg.read_only == 1, "default read_only=1");
    expect(cfg.skip_theatre_ai == 0, "default skip_theatre_ai=0");
    expect(cfg.max_orders_per_hour == 0, "default max_orders_per_hour=0");
}

void test_gate_offline(const hoiv::FileIdentity& host, const std::wstring& blackice_ok) {
    hoiv::BlackiceIdentity blackice {};
    std::string error;
    expect(hoiv::read_blackice_version(blackice_ok, &blackice, &error), "read blackice descriptor");

    hoiv::GateInput input;
    input.exe = host;
    input.blackice = blackice;
    input.config = pinned_config(host, blackice_ok);
    input.have_blackice = true;
    hoiv::GateResult gate = hoiv::evaluate_version_gate(input);
    expect(gate.version_ok && gate.code == hoiv::ErrorCode::Ok, "pinned test host passes");

    hoiv::RuntimeConfig unpinned = input.config;
    unpinned.expected_sha256_hex.clear();
    input.config = unpinned;
    gate = hoiv::evaluate_version_gate(input);
    expect(!gate.version_ok && gate.code == hoiv::ErrorCode::VersionNotPinned, "unpinned hash refuses");

    input.config = pinned_config(host, blackice_ok);
    input.config.expected_sha256_hex = std::string(64, '0');
    gate = hoiv::evaluate_version_gate(input);
    expect(!gate.version_ok && gate.code == hoiv::ErrorCode::HashMismatch, "hash mismatch refuses");

    input.config = pinned_config(host, blackice_ok);
    input.config.expected_pe_timestamp = host.pe_timestamp + 1;
    gate = hoiv::evaluate_version_gate(input);
    expect(!gate.version_ok && gate.code == hoiv::ErrorCode::PeTimestampMismatch, "pe mismatch refuses");

    input.config = pinned_config(host, blackice_ok);
    input.config.allow_test_host = 0;
    gate = hoiv::evaluate_version_gate(input);
    expect(!gate.version_ok && gate.code == hoiv::ErrorCode::WrongProcess, "non-hoi4 image refuses");

    input.config = pinned_config(host, blackice_ok);
    input.exe.product_version = "1.0.0.0";
    input.exe.raw_version = "1.19.1.0";
    gate = hoiv::evaluate_version_gate(input);
    expect(gate.version_ok && gate.code == hoiv::ErrorCode::Ok, "rawVersion 1.19 overrides VERSIONINFO 1.0");

    input.config = pinned_config(host, blackice_ok);
    input.exe.product_version = "1.18.0";
    input.exe.raw_version.clear();
    gate = hoiv::evaluate_version_gate(input);
    expect(!gate.version_ok && gate.code == hoiv::ErrorCode::VersionMismatch, "1.18 version refuses");
}

void test_read_model() {
    const uint8_t get_player[] = {0x8B, 0x81, 0x30, 0x0A, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
    expect(hoiv::adapter::get_player_bytes_match(get_player), "GetPlayer bytes match");
    expect(hoiv::adapter::get_player_padding_safe(get_player), "GetPlayer int3 padding is hookable");
    const uint8_t get_armies[] = {0x48, 0x8D, 0x81, 0x90, 0x02, 0x00, 0x00, 0xC3};
    expect(hoiv::adapter::get_armies_bytes_match(get_armies), "GetArmies bytes match");
    uint8_t bad[14] {};
    expect(!hoiv::adapter::get_player_bytes_match(bad), "wrong bytes fail closed");
    expect(!hoiv::adapter::is_canonical_user_pointer(0), "null pointer rejected");
    expect(!hoiv::adapter::is_canonical_user_pointer(0x123), "unaligned pointer rejected");
    expect(hoiv::adapter::is_canonical_user_pointer(0x0000000140001000ull), "canonical user pointer accepted");
    expect(hoiv::adapter::pdx_array_bounds_ok(3, 8, 512), "valid pdx array bounds");
    expect(!hoiv::adapter::pdx_array_bounds_ok(9, 8, 512), "size above capacity rejected");
    expect(!hoiv::adapter::pdx_array_bounds_ok(-1, 8, 512), "negative size rejected");
    expect(hoiv::adapter::tag_matches(12, 12), "matching country tag");
    expect(hoiv::adapter::tag_matches(0, 0), "index 0 may be a real country");
    expect(!hoiv::adapter::tag_matches(12, 13), "mismatched country tag rejected");
    expect(hoiv::adapter::player_index_ok(0, 190), "player index 0 is valid");
    expect(!hoiv::adapter::player_index_ok(-1, 190), "player index -1 is empty");
    expect(!hoiv::adapter::player_index_ok(190, 190), "player index at count is empty");
    expect(!hoiv::adapter::country_tag_usable(0), "tag 0 is the empty country slot");
    expect(hoiv::adapter::human_flag_set(1), "human flag set");
    expect(!hoiv::adapter::human_flag_set(0), "human flag clear");
    char tag[8] {};
    hoiv::adapter::format_country_tag(0x00524547u, tag, sizeof(tag));
    expect(std::string(tag) == "GER", "letter tag formats as GER");
    expect(hoiv::adapter::kSwissTestCountryTag == 29, "BlackICE SWI is country tag 29");
    expect(hoiv::adapter::is_swiss_test_province(11623), "St. Gallen is a Swiss test province");
    expect(!hoiv::adapter::is_swiss_test_province(6945), "Afyon 6945 is not Swiss");
    int32_t division_number = 0;
    expect(hoiv::adapter::parse_division_display_name("Division 6", &division_number), "Division 6 name parses");
    expect(division_number == 6, "Division 6 number is 6");
    expect(hoiv::adapter::is_org_display_fourteen(14.0f), "UI org 14 matches");
    expect(!hoiv::adapter::is_org_display_fourteen(50.0f), "vanilla-scale org is not the Swiss UI 14");
    float ratio = 0.0f;
    expect(hoiv::adapter::army_stat_ratio(100000, 100000, &ratio), "full CFixedPoint org ratio exists");
    expect(hoiv::adapter::is_org_ratio_full(ratio), "100000/100000 is full org");
    expect(hoiv::adapter::army_stat_ratio(30000, 100000, &ratio), "strength ratio exists");
    expect(hoiv::adapter::is_strength_display_thirty(ratio), "30000/100000 is 30 percent");
    expect(hoiv::adapter::army_stat_ratio(14, 14, &ratio), "display-scale pair still computes");
    expect(ratio > 0.13f && ratio < 0.15f, "14/14 uses the game floor of 100");
    expect(hoiv::adapter::is_swiss_org_display_pair(1423076, 1497075), "live Swiss CFixedPoint truncates to 14/14");
    expect(hoiv::adapter::is_org_max_near_swiss_ui(1497075), "14.97 is the Swiss panel max org");
    expect(hoiv::adapter::is_hp_display_one_sixty_six(16690000), "166.9 is the Swiss panel HP");
    expect(hoiv::adapter::army_handle_usable(17, 3), "nonzero handle id is usable");
    expect(!hoiv::adapter::army_handle_usable(0, 0), "null handle is not usable");
    expect(!hoiv::adapter::army_handle_usable(921052056, 32759), "Swiss +0x1C0 pointer is not a handle");
    expect(hoiv::adapter::army_handle_id_match(51, 51), "tracked handle id matches");
    expect(!hoiv::adapter::army_handle_id_match(51, 0), "no tracked handle does not match");
    expect(!hoiv::adapter::army_handle_id_match(52, 51), "different handle id does not match");
    expect(hoiv::adapter::army_handle_match(51, 2459, 51, 2459), "tracked handle id and generation match");
    expect(!hoiv::adapter::army_handle_match(51, 2459, 51, 2476), "same id different generation does not match");
    expect(!hoiv::adapter::swiss_test_move_target_ok(11590, 11604), "Romandy brigade is not the St. Gallen test move");
    expect(hoiv::adapter::kArmyHandleOffset == 0x18u, "CMoveCommand copies the handle from CArmy+0x18");
    expect(!hoiv::adapter::writes_allowed(0, 0, 1), "writes stay off when enabled=0");
    expect(!hoiv::adapter::writes_allowed(1, 1, 1), "writes stay off when read_only=1");
    expect(!hoiv::adapter::writes_allowed(1, 0, 0), "writes stay off when max_orders=0");
    expect(hoiv::adapter::writes_allowed(1, 0, 1), "writes allowed only with all three gates");
    expect(hoiv::adapter::swiss_test_move_target_ok(11623, 11604), "Swiss neighbor is a valid historical test move");
    expect(!hoiv::adapter::swiss_test_move_target_ok(11623, 11623), "same province is not a Swiss test move");
    expect(!hoiv::adapter::swiss_test_move_target_ok(11623, 6945), "Afyon is not a Swiss test move");
    expect(hoiv::adapter::move_target_ok(6282, 3312), "German neighbor ids are a valid live move");
    expect(!hoiv::adapter::move_target_ok(6282, 6282), "same province is not a live move");
    expect(!hoiv::adapter::move_target_ok(0, 3312), "province 0 is not a live move");
    expect(hoiv::adapter::kMoveCommandByteCount == 10u, "CMoveCommand ctor fingerprint is pinned");
    expect(hoiv::adapter::kMoveCommandHandleOffset == 0x38u, "CMoveCommand stores the army handle at +0x38");
    expect(hoiv::adapter::kArmyAiIssueRva == 0x00d61c30u, "army AI issue is the plan/AI CMoveCommand site");
    expect(hoiv::adapter::kArmyAiIssueStolenBytes == 21u, "army AI issue trampoline steals 21 bytes");
    expect(hoiv::adapter::pack_army_handle(51, 2476) != 0, "handle pack is nonzero");
    {
        uint64_t table[16] {};
        const uint64_t packed = hoiv::adapter::pack_army_handle(51, 2476);
        expect(hoiv::adapter::major_handle_hash_insert(table, 16, packed), "handle hash insert");
        expect(hoiv::adapter::major_handle_hash_has(table, 16, packed), "handle hash hit");
        expect(!hoiv::adapter::major_handle_hash_has(table, 16, 1), "handle hash miss");
    }
    const uint8_t army_ai[] = {
        0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x8D, 0xAC};
    expect(hoiv::adapter::army_ai_issue_bytes_match(army_ai), "army AI issue fingerprint");
    expect(hoiv::adapter::kCancelCommandBytesSize == 0x48u, "CCancelMovementCommand size is 0x48");
    expect(hoiv::adapter::kCancelCommandByteCount == 10u, "CCancelMovementCommand ctor fingerprint is pinned");
    expect(hoiv::adapter::kCancelCtorFlag == 0, "player cancel ctor flag is 0");
    const uint8_t ai_cmd[] = {0x80, 0xB8, 0x20, 0x0C, 0x00, 0x00, 0x00};
    expect(hoiv::adapter::country_ai_commands_check_bytes_match(ai_cmd), "IsCommandsAllowed check bytes");
    expect(hoiv::adapter::kCountryAiCommandsOffset == 0xC20u, "commands flag is CCountryAI+0xC20");
    expect(hoiv::adapter::kCountryAiPointerOffset == 0x228u, "GetAI is CCountry+0x228");
    expect(hoiv::adapter::kCountryCommandGroupsOffset == 0x548u, "command groups array is CCountry+0x548");
    const uint8_t groups[] = {0x48, 0x8D, 0x81, 0x48, 0x05, 0x00, 0x00, 0xC3};
    expect(hoiv::adapter::country_command_groups_bytes_match(groups), "GetCommandGroups fingerprint");
    const uint8_t get_ai[] = {0x48, 0x8B, 0x81, 0x28, 0x02, 0x00, 0x00, 0xC3};
    expect(hoiv::adapter::get_ai_bytes_match(get_ai), "GetAI fingerprint");
    expect(hoiv::kLandAiPathOrderLock == 1, "order-lock path id unused");
    expect(hoiv::kLandAiPathMoveGate == 2, "move-gate path id unused");
    expect(hoiv::kLandAiPathGeneral == 3, "general-tick path id unused");
    expect(hoiv::kLandAiPathOrgCreate == 4, "org-create path id");
    const uint8_t ag_fac[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
        0x41, 0x57};
    expect(hoiv::adapter::army_group_factory_bytes_match(ag_fac), "CArmyGroup factory fingerprint");
    expect(hoiv::adapter::kFrontOwnerOffset == 0x18u, "CFront owner is +0x18");
    expect(hoiv::adapter::kArmyGroupFactoryRva == 0x00EE10B0u, "AG factory rva");
    const uint8_t gen_tick[] = {
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x49, 0x10, 0x48,
        0x85, 0xC9};
    expect(hoiv::adapter::general_tick_bytes_match(gen_tick), "CAIGeneral[14] fingerprint");
    expect(hoiv::adapter::kCAIGeneralOwnerOffset == 0x08u, "CAIGeneral owner is +0x08");
    expect(hoiv::adapter::kCAIGeneralTickRva == 0x01074470u, "CAIGeneral[14] rva");
    expect(hoiv::adapter::kCountryAiMilitaryMinisterOffset == 0xBC8u, "military minister is CCountryAI+0xBC8");
    expect(hoiv::adapter::kCCountryAIVtableAltRva == 0x02710d20u, "CCountryAI second vtable");
    expect(
        hoiv::adapter::is_country_ai_vtable(0x140000000ull + 0x02710c90ull, 0x140000000ull),
        "primary CCountryAI vtable matches");
    expect(
        hoiv::adapter::is_country_ai_vtable(0x140000000ull + 0x02710d20ull, 0x140000000ull),
        "alternate CCountryAI vtable matches");
    expect(hoiv::adapter::kLandActorMoveRva == 0x01a31660u, "general micro-move parent rva");
    expect(hoiv::adapter::kLandActorMoveOwnerOffset == 0x18u, "army-list mover GetCountry is [rcx+0x18]");
    expect(hoiv::adapter::kLandActorMassRva == 0x002ab450u, "mass-move body rva");
    expect(hoiv::adapter::kLandActorMassHookBytes == 15u, "mass-move trampoline steals 15 bytes");
    expect(hoiv::adapter::kLandActorExecRva == 0x00f3eae0u, "plan execute rva");
    expect(hoiv::adapter::kLandActorExecHookBytes == 16u, "plan execute trampoline steals 16 bytes");
    const uint8_t land_move[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41,
        0x55};
    expect(hoiv::adapter::land_actor_move_bytes_match(land_move), "0x01A31660 fingerprint");
    const uint8_t land_mass[] = {
        0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41,
        0x54};
    expect(hoiv::adapter::land_actor_mass_bytes_match(land_mass), "0x002AB450 fingerprint");
    const uint8_t land_exec[] = {
        0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x48,
        0x08, 0x55};
    expect(hoiv::adapter::land_actor_exec_bytes_match(land_exec), "0x00F3EAE0 fingerprint");
    expect(hoiv::kSchemaVersion == 10u, "army/AG native submit live on schema 10");
    expect(static_cast<uint32_t>(hoiv::Request::TestArmy) == 6u, "TestArmy request id");
    expect(static_cast<uint32_t>(hoiv::Request::TestArmyGroup) == 7u, "TestArmyGroup request id");
    expect(hoiv::adapter::kCAIVolunteerGeneralVtableRva == 0x02a0a7b0u, "CAIVolunteerGeneral vtable");
    expect(hoiv::adapter::kCAIVolunteerGeneralTickRva == 0x01a5d160u, "CAIVolunteerGeneral[14] rva");
    expect(hoiv::adapter::kCAIVolunteerGeneralOwnerOffset == 0x08u, "volunteer owner is +0x08");
    expect(hoiv::adapter::kCAIVolunteerGeneralTickHookBytes == 16u, "volunteer tick trampoline steals 16 bytes");
    const uint8_t vol_tick[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54,
        0x41, 0x56};
    expect(hoiv::adapter::volunteer_tick_bytes_match(vol_tick), "CAIVolunteerGeneral[14] fingerprint");
    expect(
        hoiv::adapter::is_land_general_vtable(0x140000000ull + 0x029613d0ull, 0x140000000ull),
        "CAIGeneral is a land general vtable");
    expect(
        hoiv::adapter::is_land_general_vtable(0x140000000ull + 0x02a0a7b0ull, 0x140000000ull),
        "CAIVolunteerGeneral is a land general vtable");
    expect(
        !hoiv::adapter::is_land_general_vtable(0x140000000ull + 0x02710c90ull, 0x140000000ull),
        "CCountryAI is not a land general vtable");
    expect(
        hoiv::adapter::is_military_minister_vtable(0x140000000ull + 0x02962938ull, 0x140000000ull),
        "CAIMilitaryMinister vtable");
    expect(hoiv::adapter::kCAIMilitaryMinisterOwnerOffset == 0x08u, "military minister owner is +0x08");
    expect(hoiv::adapter::kCSetTheatreCommandVtableRva == 0x0298a870u, "CSetTheatreCommand vtable");
    expect(hoiv::adapter::kCArmyGroupCommandVtableRva == 0x029e3500u, "CArmyGroupCommand vtable");
    expect(hoiv::adapter::kCArmyGroupCommandDoRva == 0x01827540u, "CArmyGroupCommand[10] calls AG factory");
    expect(hoiv::adapter::kCOrderNewFrontCommandVtableRva == 0x029e4180u, "COrderNewFrontCommand vtable");
    expect(hoiv::adapter::kCOrderNewFrontCommandCanRva == 0x01832da0u, "COrderNewFrontCommand[9] rva");
    expect(hoiv::adapter::kCOrderNewFrontCommandCanHookBytes == 14u, "COrderNewFrontCommand[9] trampoline steals 14 bytes");
    const uint8_t new_front_can[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x83, 0x79, 0x5C, 0x00};
    expect(hoiv::adapter::new_front_can_bytes_match(new_front_can), "COrderNewFrontCommand[9] fingerprint");
    expect(hoiv::adapter::kCAssignToArmyGroupCommandVtableRva == 0x029e35c8u, "CAssignToArmyGroupCommand vtable");
    expect(hoiv::adapter::kLandOrgHelperRva == 0x010b4620u, "land org helper rva");
    expect(hoiv::adapter::kLandOrgHelperHookBytes == 16u, "land org helper trampoline steals 16 bytes");
    const uint8_t org_helper[] = {
        0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57,
        0x41, 0x54};
    expect(hoiv::adapter::land_org_helper_bytes_match(org_helper), "0x010B4620 fingerprint");
    expect(hoiv::adapter::kCAIGeneralOrgRva == 0x0107d9c0u, "CAIGeneral[13] org rva");
    expect(hoiv::adapter::kCAIGeneralOrgHookBytes == 16u, "CAIGeneral[13] trampoline steals 16 bytes");
    const uint8_t general_org[] = {
        0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x49, 0x89, 0x6B, 0x18, 0x49, 0x89, 0x73,
        0x20, 0x57};
    expect(hoiv::adapter::general_org_bytes_match(general_org), "CAIGeneral[13] fingerprint");
    expect(hoiv::adapter::kCSetTheatreCommandCanRva == 0x0135af40u, "CSetTheatreCommand[9] rva");
    expect(hoiv::adapter::kCSetTheatreCommandCanHookBytes == 16u, "CSetTheatreCommand[9] trampoline steals 16 bytes");
    const uint8_t theatre_can[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xF9, 0x48,
        0x8B, 0xDA};
    expect(hoiv::adapter::set_theatre_can_bytes_match(theatre_can), "CSetTheatreCommand[9] fingerprint");
    expect(hoiv::adapter::kCArmyGroupCommandCanRva == 0x01831b90u, "CArmyGroupCommand[9] rva");
    expect(hoiv::adapter::kCArmyGroupCommandCanHookBytes == 15u, "CArmyGroupCommand[9] trampoline steals 15 bytes");
    const uint8_t ag_can[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
        0x20};
    expect(hoiv::adapter::army_group_can_bytes_match(ag_can), "CArmyGroupCommand[9] fingerprint");
    expect(
        hoiv::adapter::kCAssignToArmyGroupCommandCanRva == 0x01831d40u,
        "CAssignToArmyGroupCommand[9] rva");
    expect(
        hoiv::adapter::kCAssignToArmyGroupCommandCanHookBytes == 15u,
        "CAssignToArmyGroupCommand[9] trampoline steals 15 bytes");
    const uint8_t assign_ag_can[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
        0x20};
    expect(
        hoiv::adapter::assign_army_group_can_bytes_match(assign_ag_can),
        "CAssignToArmyGroupCommand[9] fingerprint");
    expect(hoiv::adapter::kTheatreAiCreateRva == 0x00eea3e0u, "AI theatre create rva");
    expect(hoiv::adapter::kTheatreAiCreateHookBytes == 16u, "AI theatre create trampoline steals 16 bytes");
    const uint8_t theatre_ai[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x18, 0x88, 0x50, 0x10, 0x48, 0x89, 0x48, 0x08,
        0x55, 0x56};
    expect(hoiv::adapter::theatre_ai_create_bytes_match(theatre_ai), "0x00EEA3E0 fingerprint");
    expect(hoiv::adapter::kTheatreCreateGateRva == 0x00ee67f0u, "AI theatre create gate rva");
    expect(hoiv::adapter::kTheatreCreateGateHookBytes == 16u, "AI theatre create gate trampoline steals 16 bytes");
    const uint8_t theatre_gate[] = {
        0x4C, 0x8B, 0xDC, 0x45, 0x88, 0x4B, 0x20, 0x53, 0x55, 0x57, 0x41, 0x55, 0x41, 0x56,
        0x41, 0x57};
    expect(hoiv::adapter::theatre_create_gate_bytes_match(theatre_gate), "0x00EE67F0 fingerprint");
    expect(hoiv::adapter::kCTheatreCtorRva == 0x00ed9f40u, "CTheatre ctor rva");
    expect(hoiv::adapter::kCTheatreCtorHookBytes == 14u, "CTheatre ctor trampoline steals 14 bytes");
    const uint8_t theatre_ctor[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x89, 0x54, 0x24, 0x10};
    expect(hoiv::adapter::theatre_ctor_bytes_match(theatre_ctor), "CTheatre ctor fingerprint");
    expect(hoiv::adapter::kAreaDefenseAiRva == 0x01085e00u, "AI area-defense poster rva");
    expect(hoiv::adapter::kAreaDefenseAiHookBytes == 15u, "AI area-defense trampoline steals 15 bytes");
    const uint8_t area_def[] = {
        0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41,
        0x56};
    expect(hoiv::adapter::area_defense_ai_bytes_match(area_def), "0x01085E00 fingerprint");
    expect(hoiv::adapter::kArmyGroupAiRva == 0x0105cce0u, "AI army-group poster rva");
    expect(hoiv::adapter::kArmyGroupAiHookBytes == 15u, "AI army-group trampoline steals 15 bytes");
    const uint8_t ag_ai[] = {
        0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50,
        0x10};
    expect(hoiv::adapter::army_group_ai_bytes_match(ag_ai), "0x0105CCE0 fingerprint");
    expect(hoiv::adapter::kArmyAiRva == 0x0105c5f0u, "AI army poster rva");
    expect(hoiv::adapter::kArmyAiHookBytes == 15u, "AI army trampoline steals 15 bytes");
    const uint8_t army_poster[] = {
        0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50,
        0x10};
    expect(hoiv::adapter::army_ai_bytes_match(army_poster), "0x0105C5F0 fingerprint");
    expect(hoiv::adapter::kArmyAi2Rva == 0x01059820u, "AI army poster 2 rva");
    expect(hoiv::adapter::kArmyAi2HookBytes == 16u, "AI army poster 2 trampoline steals 16 bytes");
    const uint8_t army_poster2[] = {
        0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x8B, 0xEC};
    expect(hoiv::adapter::army_ai2_bytes_match(army_poster2), "0x01059820 fingerprint");
    expect(hoiv::adapter::kCOrderGroupCommandVtableRva == 0x029e3370u, "COrderGroupCommand vtable");
    expect(hoiv::adapter::kCOrderGroupCommandCanRva == 0x01832910u, "COrderGroupCommand[9] rva");
    expect(hoiv::adapter::kCOrderGroupCommandCanHookBytes == 16u, "COrderGroupCommand[9] trampoline steals 16 bytes");
    const uint8_t order_group_can[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54,
        0x41, 0x56};
    expect(hoiv::adapter::order_group_can_bytes_match(order_group_can), "COrderGroupCommand[9] fingerprint");
    expect(hoiv::adapter::kCOrderGroupCommandCtorBRva == 0x0181dd70u, "COrderGroupCommand ctor B rva");
    expect(hoiv::adapter::kCOrderGroupCommandBytesSize == 0x60u, "COrderGroupCommand size");
    const uint8_t order_group_ctor[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x48,
        0x83, 0xEC};
    expect(hoiv::adapter::order_group_ctor_b_bytes_match(order_group_ctor), "COrderGroupCommand ctor B fingerprint");
    expect(hoiv::adapter::kCArmyGroupCommandCtorBRva == 0x0181b880u, "CArmyGroupCommand ctor B rva");
    expect(hoiv::adapter::kCArmyGroupCommandBytesSize == 0x80u, "CArmyGroupCommand size");
    const uint8_t ag_ctor[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC,
        0x30};
    expect(hoiv::adapter::army_group_ctor_b_bytes_match(ag_ctor), "CArmyGroupCommand ctor B fingerprint");
    expect(hoiv::adapter::kCTheatreVtableRva == 0x0294ed28u, "CTheatre vtable");
    expect(hoiv::adapter::kUnitParentOffset == 0x02a0u, "unit parent pointer is +0x2A0");
    expect(hoiv::adapter::kCMassMoveCommandVtableRva == 0x0298a488u, "CMassMoveCommand vtable");
    expect(hoiv::adapter::kCMassMoveCommandCanRva == 0x01359010u, "CMassMoveCommand[9] rva");
    expect(hoiv::adapter::kCMassMoveCommandCanHookBytes == 15u, "CMassMoveCommand[9] trampoline steals 15 bytes");
    const uint8_t mass_can[] = {
        0x8B, 0x41, 0x4C, 0x83, 0xF8, 0x01, 0x7C, 0x07, 0x3B, 0x41, 0x34, 0x0F, 0x94, 0xC0, 0xC3};
    expect(hoiv::adapter::mass_move_can_bytes_match(mass_can), "CMassMoveCommand[9] fingerprint");
    expect(hoiv::adapter::kOrdersGroupAiBlockOffset == 0x39u, "plan AI lock is COrdersGroup+0x39");
    expect(hoiv::adapter::orders_group_ai_blocked(1), "ctor default +0x39=1 blocks plan AI");
    expect(!hoiv::adapter::orders_group_ai_blocked(0), "+0x39=0 lets plan AI run");
    expect(
        hoiv::adapter::is_orders_or_army_group_vtable(1, 1, 2),
        "orders-group vtable matches");
    expect(
        !hoiv::adapter::is_orders_or_army_group_vtable(3, 1, 2),
        "other vtable is not an orders group");
    const uint8_t og_can[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x80, 0x79, 0x39, 0x00};
    expect(hoiv::adapter::orders_group_can_ai_bytes_match(og_can), "COrdersGroup[12] fingerprint");
    const uint8_t ai_store[] = {0x49, 0x89, 0x87, 0x28, 0x02, 0x00, 0x00};
    expect(hoiv::adapter::country_ai_pointer_store_bytes_match(ai_store), "CCountry+0x228 store fingerprint");
    expect(hoiv::adapter::is_major_country_tag(1), "GER is major tag 1");
    expect(hoiv::adapter::is_major_country_tag(7), "JAP is major tag 7");
    expect(!hoiv::adapter::is_major_country_tag(29), "SWI is not a major");
    expect(!hoiv::adapter::is_major_country_tag(0), "empty slot is not a major");
    expect(hoiv::adapter::kGermanyTestCountryTag == 1, "BlackICE GER is country tag 1");
    expect(hoiv::adapter::kLiveSampleCountryTag == 1, "live sample is Germany tag 1");
    expect(hoiv::adapter::country_ai_commands_off(0), "commands flag 0 is off");
    expect(!hoiv::adapter::country_ai_commands_off(1), "commands flag 1 is on");
    expect(hoiv::adapter::country_ai_backref_ok(0x10000, 0x10000), "AI backref matches country");
    expect(!hoiv::adapter::country_ai_backref_ok(0, 0x10000), "null AI backref rejected");
    expect(!hoiv::adapter::ai_writes_allowed(0, 0), "AI writes stay off when enabled=0");
    expect(!hoiv::adapter::ai_writes_allowed(1, 1), "AI writes stay off when read_only=1");
    expect(hoiv::adapter::ai_writes_allowed(1, 0), "AI writes allowed without order quota");
    const uint8_t ai_toggle[] = {
        0x80, 0x3D, 0xCE, 0x28, 0x07, 0x03, 0x00, 0x0F, 0x94, 0xC0, 0x88, 0x05,
        0xC5, 0x28, 0x07, 0x03};
    expect(hoiv::adapter::global_ai_toggle_bytes_match(ai_toggle), "console ai toggle bytes match");
    expect(hoiv::adapter::kGlobalAiEnabledRva == 0x03304c9cu, "console ai flag RVA");
    expect(hoiv::adapter::global_ai_flag_on(1), "global AI 1 is on");
    expect(!hoiv::adapter::global_ai_flag_on(0), "global AI 0 is off");
    expect(!hoiv::adapter::is_swiss_org_display_pair(16690000, 16690000), "166.9 is not UI org 14");
    expect(hoiv::adapter::is_three_letter_tag("SWI"), "three letter tag accepted");
    expect(!hoiv::adapter::is_three_letter_tag("swi"), "lowercase tag rejected");
    expect(!hoiv::adapter::is_three_letter_tag("SW"), "short tag rejected");
}

void test_hook_idempotent() {
    hoiv::HookManager hooks;
    expect(hooks.install_if_needed(false) == hoiv::HookManager::Result::Rejected, "hooks reject failed gate");
    expect(!hooks.is_installed(), "hooks stay down after reject");
    expect(hooks.install_if_needed(true) == hoiv::HookManager::Result::Ok, "first install");
    expect(hooks.install_if_needed(true) == hoiv::HookManager::Result::AlreadyInstalled, "second install is no-op");
    expect(hooks.actual_installs() == 1, "actual installs stay 1");
    expect(hooks.uninstall() == hoiv::HookManager::Result::Ok, "uninstall");
    expect(!hooks.is_installed(), "hooks down after uninstall");
    expect(hooks.install_if_needed(true) == hoiv::HookManager::Result::Ok, "reinstall after uninstall");
    expect(hooks.actual_installs() == 2, "reload installs once more");
}

void apply_config(hoiv::SharedBlock* block, const hoiv::RuntimeConfig& cfg) {
    hoiv::copy_wide(block->exe_path, 260, cfg.exe_path);
    hoiv::copy_wide(block->blackice_descriptor, 260, cfg.blackice_descriptor);
    hoiv::copy_narrow(block->expected_sha256_hex, sizeof(block->expected_sha256_hex), cfg.expected_sha256_hex);
    hoiv::copy_narrow(block->expected_product_version, sizeof(block->expected_product_version), cfg.expected_product_version);
    hoiv::copy_narrow(block->expected_blackice_version, sizeof(block->expected_blackice_version), cfg.expected_blackice_version);
    hoiv::copy_narrow(block->adapter_id, sizeof(block->adapter_id), cfg.adapter_id);
    block->expected_pe_timestamp = cfg.expected_pe_timestamp;
    block->enabled = 0;
    block->read_only = 1;
    block->allow_test_host = 1;
    block->max_orders_per_hour = 0;
}

bool resolve_exports(hoiv::RemoteBridge* remote, hoiv::SharedBlock* block) {
    for (int i = 0; i < 100 && block->module_handle == 0; ++i) {
        Sleep(50);
    }
    if (block->module_handle == 0) {
        return false;
    }
    remote->module = block->module_handle;
    remote->initialize += remote->module;
    remote->disable += remote->module;
    remote->shutdown += remote->module;
    return true;
}

void test_remote_load(const hoiv::FileIdentity& host, const std::wstring& blackice_ok, const std::wstring& dll) {
    hoiv::IpcSession session {};
    expect(hoiv::ipc_create(&session), "create ipc");
    if (session.block == nullptr) {
        return;
    }
    apply_config(session.block, pinned_config(host, blackice_ok));

    HANDLE process = nullptr;
    DWORD pid = 0;
    std::string error;
    if (!hoiv::create_owned_process(host.path, &process, &pid, &error)) {
        expect(false, "start p0_host");
        hoiv::ipc_close(&session);
        return;
    }
    Sleep(100);

    hoiv::RemoteBridge remote {};
    if (!hoiv::load_bridge_into_process(process, dll, &remote, &error)) {
        std::printf("load error: %s\n", error.c_str());
        expect(false, "load bridge.dll");
        TerminateProcess(process, 1);
        CloseHandle(process);
        hoiv::ipc_close(&session);
        return;
    }
    expect(resolve_exports(&remote, session.block), "publish module handle");

    uint32_t code = 0;
    expect(hoiv::call_remote(process, remote.initialize, 15000, &code, &error), "Bridge_Initialize");
    expect(code == 0, "initialize error=0");
    expect(WaitForSingleObject(session.ready, 5000) == WAIT_OBJECT_0, "ready event");
    expect(session.block->version_ok == 1, "remote version_ok");
    expect(session.block->hooks_installed == 1, "hooks logically installed");
    expect(session.block->write_enabled == 0, "writes stay disabled");
    expect(session.block->read_ok == 0, "test host does not invent a live read");
    expect(session.block->division_ok == 0, "test host has no division snapshot");
    expect(session.block->org_valid == 0, "organization stays unconfirmed");
    expect(session.block->hook_enter_count == 0, "test host does not sample PeekMessageW");
    expect(session.block->hook_actual_installs == 1, "first remote install");

    expect(hoiv::call_remote(process, remote.initialize, 15000, &code, &error), "initialize again");
    expect(session.block->hook_actual_installs == 1, "reload does not stack hooks");
    expect(session.block->hooks_installed == 1, "hooks still installed after second init");

    expect(hoiv::call_remote(process, remote.disable, 5000, &code, &error), "Bridge_Disable");
    expect(session.block->hooks_installed == 0, "hooks removed after disable");
    expect(session.block->disabled == 1, "disabled flag set");
    expect(session.block->write_enabled == 0, "writes still disabled after disable");

    ResetEvent(session.ready);
    expect(hoiv::call_remote(process, remote.initialize, 15000, &code, &error), "initialize after disable");
    expect(session.block->hooks_installed == 1, "hooks can return after disable");
    expect(session.block->hook_actual_installs == 2, "re-enable installs once");

    expect(hoiv::call_remote(process, remote.shutdown, 5000, &code, &error), "Bridge_Shutdown");
    expect(hoiv::unload_bridge_from_process(remote, 5000, &error), "FreeLibrary");

    DWORD host_code = STILL_ACTIVE;
    GetExitCodeProcess(process, &host_code);
    expect(host_code == STILL_ACTIVE, "host survives unload");

    HANDLE stop = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\HoiV.P0Host.Shutdown");
    if (stop != nullptr) {
        SetEvent(stop);
        CloseHandle(stop);
    }
    WaitForSingleObject(process, 5000);
    GetExitCodeProcess(process, &host_code);
    expect(host_code == 0, "host exits cleanly");
    CloseHandle(process);
    hoiv::ipc_close(&session);
}

}  // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);
    const std::wstring host_path = hoiv::sibling_path(L"p0_host.exe");
    const std::wstring dll_path = hoiv::sibling_path(L"bridge.dll");
    CreateDirectoryW(temp_dir().c_str(), nullptr);
    const std::wstring blackice = hoiv::join_path(temp_dir(), L"descriptor.mod");
    write_text(blackice, "name=\"BlackICE\"\nversion=\"12.1.0\"\n");

    hoiv::FileIdentity host {};
    std::string error;
    if (!hoiv::read_file_identity(host_path, &host, &error)) {
        std::printf("FAIL read p0_host identity: %s\n", error.c_str());
        return 1;
    }
    expect(hoiv::version_prefix_match(host.product_version, "1.19."), "p0_host product version 1.19.x");

    test_defaults();
    test_gate_offline(host, blackice);
    test_read_model();
    test_hook_idempotent();
    test_remote_load(host, blackice, dll_path);

    std::printf("%s\n", g_failures == 0 ? "P0.2 offline tests passed" : "P0.2 offline tests failed");
    return g_failures == 0 ? 0 : 1;
}
