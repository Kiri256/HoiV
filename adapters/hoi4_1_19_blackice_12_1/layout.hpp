#pragma once

#include <cstdint>

namespace hoiv::adapter {

// All RVAs and offsets below are for the hash-pinned HOI4 1.19.1.0 image only.
// Image base 0x140000000. Do not reuse them on any other build.

inline constexpr uint32_t kCurrentGameStateRva = 0x033048c0;
inline constexpr uint32_t kGetPlayerRva = 0x001dbb30;
inline constexpr uint8_t kGetPlayerBytes[] = {0x8B, 0x81, 0x30, 0x0A, 0x00, 0x00, 0xC3};
inline constexpr uint32_t kGetPlayerByteCount = 7;
inline constexpr uint32_t kGetPlayerHookBytes = 14;
inline constexpr uint32_t kGetArmiesRva = 0x006c2410;
inline constexpr uint8_t kGetArmiesBytes[] = {0x48, 0x8D, 0x81, 0x90, 0x02, 0x00, 0x00, 0xC3};
inline constexpr uint32_t kGetArmiesByteCount = 8;

inline constexpr uint32_t kCCurrentGameStateVtableRva = 0x026fb148;
inline constexpr uint32_t kCGameStateVtableRva = 0x026fb0d0;
inline constexpr uint32_t kCCountryVtableRva = 0x027c0e80;
inline constexpr uint32_t kCCountryAIVtableRva = 0x02710c90;
inline constexpr uint32_t kCCountryAIVtableAltRva = 0x02710d20;
inline constexpr uint32_t kCArmyVtableRva = 0x02933d20;
inline constexpr uint32_t kCUnitVtableRva = 0x0292cce8;
inline constexpr uint32_t kCProvinceVtableRva = 0x0294ae78;
inline constexpr uint32_t kCGameIdlerVtableRva = 0x02710270;
inline constexpr uint32_t kCInGameIdlerVtableRva = 0x02942480;
inline constexpr uint32_t kCHumanVtableRva = 0x026fad98;
inline constexpr uint32_t kCGameIdlerSingletonRva = 0x03304d10;
// Live singleton is CInGameIdler (derived). [+0x4F0] is not CCountry*.
// Swiss SP: [idler+0x2F8] pointed at countries[30].
inline constexpr uint32_t kIdlerActorOffset = 0x04F0;
inline constexpr uint32_t kIdlerCountryOffset = 0x02F8;
inline constexpr uint32_t kIdlerScanEnd = 0x0B00;
// CCountry vtable[8] early-out: cmp byte [this+0x145C], 0
// Live SP: this byte is 0 on every country, including the player. Do not use it.
inline constexpr uint32_t kCountryHumanFlagOffset = 0x145C;

inline constexpr const char kRttiCountry[] = ".?AVCCountry@@";
inline constexpr const char kRttiArmy[] = ".?AVCArmy@@";
inline constexpr const char kRttiUnit[] = ".?AVCUnit@@";
inline constexpr const char kRttiProvince[] = ".?AVCProvince@@";
inline constexpr const char kRttiHuman[] = ".?AVCHuman@@";
inline constexpr const char kRttiIdler[] = ".?AVCGameIdler@@";
inline constexpr const char kRttiInGameIdler[] = ".?AVCInGameIdler@@";

// CCurrentGameState::GetPlayer = mov eax, [rcx+0xA30]; ret
// Only 11 direct calls; inlined at most UI/tick sites. Keep as fingerprint, not the sample point.
inline constexpr uint32_t kPlayerTagOffset = 0x0A30;
// Frequent post-load probe: cmp byte [reg+0xA39], 0
inline constexpr uint32_t kGameReadyOffset = 0x0A39;

// CPdxArray<CCountry*> on CGameState: data at +0x310, size at +0x31C
// (vtable getter [9] returns [this+0x31C]; loops use [this+0x310])
inline constexpr uint32_t kCountryArrayDataOffset = 0x0310;
inline constexpr uint32_t kCountryArrayCapacityOffset = 0x0318;
inline constexpr uint32_t kCountryArraySizeOffset = 0x031C;

// CCountry vtable[20] checks [this+8] / [this+0xC]; GetCountryTag reads the first dword.
inline constexpr uint32_t kCountryTagOffset = 0x08;
// CCountry::GetArmies = lea rax, [rcx+0x290]; ret
// Swiss SP 2026-09-13: elements are CArmy* (vtable 0x02933d20) with +0x1F0 locations.
inline constexpr uint32_t kCountryArmiesOffset = 0x0290;

// Inlined CUnit::GetLocation: cmp qword [rbx+0x1F0], 0
inline constexpr uint32_t kUnitLocationOffset = 0x01F0;

// CArmy vtable [36] = mov rax,[rcx+0x428]; mov [rdx],rax; mov rax,rdx; ret
// CArmy vtable [31] = same at +0x420 (HP, Swiss UI 166.9)
// CArmy vtable [38] = max(*(this+0x138)+0x280, 100)
// CArmy vtable [33] = max(*(this+0x138)+0x288, 100)
// has_unit_organization [39] = clamp([36]*100000/[38], 0, 100000)
// Do not call these slots. Read the fields the getters already expose.
// CArmy [84]/[85] = lea rax,[rcx+0x1C0]; ret
// Swiss SP 2026-09-13: [+0x1C0] is a user pointer (0x7FF7....), not {id, generation}.
inline constexpr uint32_t kArmyNameOrPtrOffset = 0x01C0;
// CMoveCommand ctor (0x01350350) passes CArmy* to 0x01223A10, which calls 0x002A6C50:
//   mov rax, [rdx+0x18]; mov [dest], rax; empty-check id/gen; call resolve 0x021FFD50; result-0x10.
// Raw {int32 id, int32 generation} at CArmy+0x18. Do not call the resolver on the game thread.
// Swiss St. Gallen 2026-09-13: 51/2476, stable while org 14.23 -> 14.25.
inline constexpr uint32_t kArmyHandleOffset = 0x0018;

inline constexpr uint32_t kArmyOrgCurrentOffset = 0x0428;
inline constexpr uint32_t kArmyHpCurrentOffset = 0x0420;
inline constexpr uint32_t kArmyStatsPointerOffset = 0x0138;
inline constexpr uint32_t kArmyStatsMaxOrgOffset = 0x0280;
inline constexpr uint32_t kArmyStatsMaxHpOffset = 0x0288;
inline constexpr int64_t kArmyStatFloor = 100;
inline constexpr int64_t kFixedPointOne = 100000;

// Inlined CProvince::GetProvinceID: cmp dword [rdx+0xA4], 0
inline constexpr uint32_t kProvinceIdOffset = 0x00A4;

// CPdxArray<T>: T* data; int32 capacity; int32 size
inline constexpr uint32_t kPdxArrayData = 0;
inline constexpr uint32_t kPdxArrayCapacity = 8;
inline constexpr uint32_t kPdxArraySize = 12;
inline constexpr uint32_t kPdxArrayBytes = 16;

// Country/army object scan window for vtable-validated pointer arrays.
// Army and unit list offsets are not pinned; only CArmy/CUnit vtables are.
inline constexpr uint32_t kCountryScanBegin = 0x20;
inline constexpr uint32_t kCountryScanEnd = 0x2000;
inline constexpr uint32_t kArmyScanBegin = 0x20;
inline constexpr uint32_t kArmyScanEnd = 0x0A00;

inline constexpr int32_t kMaxCountries = 512;
inline constexpr int32_t kMaxArmies = 256;
inline constexpr int32_t kMaxUnits = 512;

inline constexpr uint32_t kCaptureMinIntervalMs = 100;

// CMoveCommand this size from factory mov ecx, 0x88. Player UI: ctor, [9] edx=0, [10].
inline constexpr uint32_t kMoveCommandRva = 0x01350350;
inline constexpr uint8_t kMoveCommandBytes[] = {0x48, 0x89, 0x4C, 0x24, 0x08, 0x53, 0x48, 0x83, 0xEC, 0x60};
inline constexpr uint32_t kMoveCommandByteCount = 10;
inline constexpr uint32_t kMoveCanExecuteRva = 0x013596b0;
inline constexpr uint8_t kMoveCanExecuteBytes[] = {
    0x48, 0x8B, 0x41, 0x28, 0x48, 0x83, 0xC1, 0x28, 0x48, 0xFF, 0x60, 0x50};
inline constexpr uint32_t kMoveCanExecuteByteCount = 12;
inline constexpr uint32_t kMoveCanExecuteHookBytes = 14;
inline constexpr uint32_t kMoveExecuteRva = 0x01356600;
inline constexpr uint8_t kMoveExecuteBytes[] = {
    0x48, 0x8B, 0x41, 0x28, 0x48, 0x83, 0xC1, 0x28, 0x48, 0xFF, 0x60, 0x48};
inline constexpr uint32_t kMoveExecuteByteCount = 12;
inline constexpr uint32_t kMoveExecuteHookBytes = 14;
// Inner object at +0x28. Handle copy dest is inner+0x10 (0x01223A10 -> 0x002A6C50).
inline constexpr uint32_t kMoveCommandInnerOffset = 0x28;
inline constexpr uint32_t kMoveCommandHandleOffset = 0x38;
inline constexpr uint32_t kMoveCanInnerVtableSlot = 10;
inline constexpr uint32_t kMoveDoInnerVtableSlot = 9;
inline constexpr uint32_t kMaxMajorArmyHandles = 2048;
inline constexpr uint32_t kMajorHandleHashSlots = 4096;
inline constexpr uint32_t kLandAiHandleRefreshMs = 5000;
// CArmy-layout object method that constructs CMoveCommand at 0x00d62020 (plan/AI
// issue, not player UI 0x014Bxxxx). Prologue: pushes + lea rbp,[rsp-0x88].
inline constexpr uint32_t kArmyAiIssueRva = 0x00d61c30;
inline constexpr uint8_t kArmyAiIssueBytes[] = {
    0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8D, 0xAC};
inline constexpr uint32_t kArmyAiIssueByteCount = 16;
inline constexpr uint32_t kArmyAiIssueStolenBytes = 21;
inline constexpr uint32_t kArmyAiIssueHookBytes = 14;
inline constexpr uint32_t kMoveCommandBytesSize = 0x88;
inline constexpr uint32_t kMoveCommandVtableSlotCan = 9;
inline constexpr uint32_t kMoveCommandVtableSlotDo = 10;
inline constexpr uint8_t kMoveCtorShiftFlag = 1;
inline constexpr uint32_t kMoveCtorMode = 2;
inline constexpr int32_t kSwissTestMoveProvince = 11604;

// CCancelMovementCommand this size from factory mov ecx, 0x48.
// Player UI 0x0144e2d3: resolve handle -> CArmy*, stack ctor r8=0, [9] edx=0, [10].
// Ctor 0x0134f9d0 copies [CArmy+0x18] into the command.
inline constexpr uint32_t kCancelCommandRva = 0x0134f9d0;
inline constexpr uint8_t kCancelCommandBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x4C, 0x24, 0x08};
inline constexpr uint32_t kCancelCommandByteCount = 10;
inline constexpr uint32_t kCancelCanExecuteRva = 0x01358190;
inline constexpr uint8_t kCancelCanExecuteBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18};
inline constexpr uint32_t kCancelCanExecuteByteCount = 10;
inline constexpr uint32_t kCancelExecuteRva = 0x01355840;
inline constexpr uint8_t kCancelExecuteBytes[] = {
    0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x48, 0x83, 0xEC, 0x20};
inline constexpr uint32_t kCancelExecuteByteCount = 10;
inline constexpr uint32_t kCancelCommandBytesSize = 0x48;
inline constexpr uint32_t kCancelCommandVtableSlotCan = 9;
inline constexpr uint32_t kCancelCommandVtableSlotDo = 10;
inline constexpr uint8_t kCancelCtorFlag = 0;

// CCountryAI::Update (vt[2] 0x002acf30) returns if [this+0x60]==0. Not land orders.
// GetCountry starts with mov rcx, [this+0x08].
// Post-AI-command 0x0029e670: +0xC20 is assert-only (jz +1; int3) then still
// calls command [9]/[10]. Land walks call CMoveCommand ctor+can+do directly
// (0x00d62020, 0x01a2faee). 2026-09-13 game: writing +0xC20 did not stop majors.
// BlackICE 00_countries.txt: 1 GER .. 7 JAP. Not Switzerland.
inline constexpr uint32_t kCountryAiCountryOffset = 0x08;
inline constexpr uint32_t kCountryAiCommandsOffset = 0x0C20;
inline constexpr uint8_t kCountryAiCommandsOffValue = 0;
inline constexpr uint32_t kCountryAiCommandsCheckRva = 0x0029e69f;
inline constexpr uint8_t kCountryAiCommandsCheckBytes[] = {
    0x80, 0xB8, 0x20, 0x0C, 0x00, 0x00, 0x00};
inline constexpr uint32_t kCountryAiCommandsCheckByteCount = 7;
inline constexpr int32_t kMajorCountryTagBegin = 1;
inline constexpr int32_t kMajorCountryTagEnd = 7;
inline constexpr int32_t kGermanyTestCountryTag = 1;

// CCountry+0x228 = CCountryAI*. Create path 0x00705d10 allocates 0xC28, constructs
// 0x002a6d10, then `mov [r15+0x228], rax`.
inline constexpr uint32_t kCountryAiPointerOffset = 0x0228;
inline constexpr uint32_t kCountryAiPointerStoreRva = 0x00705d58;
inline constexpr uint8_t kCountryAiPointerStoreBytes[] = {
    0x49, 0x89, 0x87, 0x28, 0x02, 0x00, 0x00};
inline constexpr uint32_t kCountryAiPointerStoreByteCount = 7;
inline constexpr uint32_t kCountryAiObjectSize = 0x0C28;

// CCountryAI[14] 0x002acc80 creates ministers and sets +0x60=1.
// +0xBC0 Foreign 0xD0, +0xBC8 Military 0x7A0, +0xBD0 Interior 0x460.
// Country+0x223D is checked by military AND foreign/interior. Not land-only.
inline constexpr uint32_t kCountryAiMilitaryMinisterOffset = 0x0BC8;
inline constexpr uint32_t kCAIMilitaryMinisterVtableRva = 0x02962938;
inline constexpr uint32_t kCAIMilitaryMinisterOwnerOffset = 0x0008;
inline constexpr uint32_t kMilitaryMinisterObjectSize = 0x07A0;
inline constexpr uint32_t kMilitaryMinisterGeneralsOffset = 0x0098;
inline constexpr uint32_t kCAIGeneralVtableRva = 0x029613d0;
inline constexpr uint32_t kCAIGeneralParentOffset = 0x0010;
// Owner at +0x08: CCountryAI* or CCountry*. [14] 0x01074470 is the hourly
// land-general tick (minister walks +0x98 and call vt[14]). If +0x10 is null
// it returns; do not write +0x10. Skip the tick for majors. Do not lock
// COrdersGroup/+0x39 — those objects are what we will build later.
inline constexpr uint32_t kCAIGeneralOwnerOffset = 0x0008;
inline constexpr uint32_t kCAIGeneralTickRva = 0x01074470;
inline constexpr uint8_t kCAIGeneralTickBytes[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x50, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x49, 0x10, 0x48,
    0x85, 0xC9};
inline constexpr uint32_t kCAIGeneralTickByteCount = 16;
inline constexpr uint32_t kCAIGeneralTickHookBytes = 16;

// 2026-09-13 game: CAIGeneral[14] armed, GER minister +0x98 size 0, theaters
// and units under them still appeared. Create path is CFront / CArmyGroup.
// CFront factory 0xEEE3A0 stores rcx at CFront+0x18. AG factory 0xEE10B0
// takes CFront* and allocates CArmyGroup 0x250. Do not lock +0x39.
inline constexpr uint32_t kFrontOwnerOffset = 0x0018;
inline constexpr uint32_t kFrontFactoryRva = 0x00eee3a0;
inline constexpr uint8_t kFrontFactoryBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
    0x6C, 0x24, 0xA0};
inline constexpr uint32_t kFrontFactoryByteCount = 17;
inline constexpr uint32_t kFrontFactoryHookBytes = 17;
inline constexpr uint32_t kFrontTickRva = 0x00ef1b50;
inline constexpr uint8_t kFrontTickBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41,
    0x54, 0x41, 0x55};
inline constexpr uint32_t kFrontTickByteCount = 17;
inline constexpr uint32_t kFrontTickHookBytes = 17;
inline constexpr uint32_t kArmyGroupFactoryRva = 0x00ee10b0;
inline constexpr uint8_t kArmyGroupFactoryBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57};
inline constexpr uint32_t kArmyGroupFactoryByteCount = 16;
inline constexpr uint32_t kArmyGroupFactoryHookBytes = 16;
inline constexpr uint32_t kMilitaryMinisterCreateRva = 0x010bb0d0;
inline constexpr uint8_t kMilitaryMinisterCreateBytes[] = {
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xF9, 0x48, 0x8B, 0x49, 0x08, 0x48,
    0x8B, 0x01};
inline constexpr uint32_t kMilitaryMinisterCreateByteCount = 16;
inline constexpr uint32_t kMilitaryMinisterCreateHookBytes = 16;

// COrdersGroup[12] 0x00be8920: if [this+0x39]!=0 return 0. Ctor of the shared
// army-group/orders object (0x00be0580) writes +0x39=1. CArmyGroup[12] walks
// children at +0x230 and fails if any child [12] is 0. This is the plan-AI
// lock, not CCountryAI hourly Update (already proven not land-only).
inline constexpr uint32_t kCOrdersGroupVtableRva = 0x0292bec0;
inline constexpr uint32_t kCArmyGroupVtableRva = 0x0292bf58;
inline constexpr uint32_t kCTheaterGroupVtableRva = 0x029be6c0;
inline constexpr uint32_t kCTheatreVtableRva = 0x0294ed28;
inline constexpr uint32_t kCFrontVtableRva = 0x0294ee20;
inline constexpr uint32_t kUnitParentOffset = 0x02a0;
inline constexpr uint32_t kOrdersGroupAiBlockOffset = 0x39;
inline constexpr uint8_t kOrdersGroupAiBlockValue = 1;
inline constexpr uint32_t kOrdersGroupCanAiRva = 0x00be8920;
inline constexpr uint8_t kOrdersGroupCanAiBytes[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x80, 0x79, 0x39, 0x00};
inline constexpr uint32_t kOrdersGroupCanAiByteCount = 10;
inline constexpr uint32_t kArmyGroupOrdersOffset = 0x0230;
inline constexpr uint32_t kArmyGroupOrdersSizeOffset = 0x023C;
inline constexpr int32_t kMaxArmyGroupOrders = 256;
inline constexpr uint32_t kTheaterGroupScanEnd = 0x0400;
inline constexpr uint32_t kCountryOrderScanEnd = 0x1000;
inline constexpr uint32_t kArmyOrderScanEnd = 0x0400;
// CCountry lea rax,[rcx+0x548]; ret. Callers treat it as CPdxArray and call
// element vt[2]. 2026-09-13 --no-land-ai: scanning the country object only saw
// this header, so lock count was 0 and we fell back to 7 majors / move gate.
inline constexpr uint32_t kCountryCommandGroupsOffset = 0x0548;
inline constexpr uint32_t kCountryCommandGroupsRva = 0x006c2680;
inline constexpr uint8_t kCountryCommandGroupsBytes[] = {
    0x48, 0x8D, 0x81, 0x48, 0x05, 0x00, 0x00, 0xC3};
inline constexpr uint32_t kCountryCommandGroupsByteCount = 8;
inline constexpr uint32_t kCountryAltGroupsOffset = 0x0278;
inline constexpr uint32_t kCountryMilitaryHolderOffset = 0x0FA0;
inline constexpr uint32_t kMilitaryHolderGroupsOffset = 0x0190;
inline constexpr uint32_t kCountryCommandHolderOffset = 0x0F88;
inline constexpr uint32_t kFrontArrayAOffset = 0x0020;
inline constexpr uint32_t kFrontArrayBOffset = 0x0038;
inline constexpr uint32_t kFrontArrayCOffset = 0x0058;
inline constexpr uint32_t kFrontArmyGroupsOffset = 0x0160;
inline constexpr uint32_t kLandObjectInnerEnd = 0x0200;
inline constexpr uint32_t kGetAiRva = 0x006c2400;
inline constexpr uint8_t kGetAiBytes[] = {0x48, 0x8B, 0x81, 0x28, 0x02, 0x00, 0x00, 0xC3};
inline constexpr uint32_t kGetAiByteCount = 8;

// Console `ai` master switch. 1 = on, 0 = off. Turns off focus/production/research
// for every country. 2026-09-13 game: ai_global=0 did that. Do not write 0.
inline constexpr uint32_t kGlobalAiEnabledRva = 0x03304c9c;
inline constexpr uint32_t kGlobalAiToggleRva = 0x002923c7;
inline constexpr uint8_t kGlobalAiToggleBytes[] = {
    0x80, 0x3D, 0xCE, 0x28, 0x07, 0x03, 0x00, 0x0F, 0x94, 0xC0, 0x88, 0x05,
    0xC5, 0x28, 0x07, 0x03};
inline constexpr uint32_t kGlobalAiToggleByteCount = 16;
inline constexpr uint8_t kGlobalAiOnValue = 1;

// Land-actor probes. Exec always calls original.
// Mass body 0x002AB450 always runs: it also posts research and naval mass-move.
// Germany land mass-move is skipped at CMassMoveCommand[9], not by skipping [145].
// Move (0x01A31660) rcx is an army list (CPdxArray-shaped, not a vtable object).
// The function itself calls GetCountry on [rcx+0x18]. Skip original only for Germany.
// Steal 15: 16th byte is the first byte of `push r14`.
// CCountryAI[145] 0x002A7DE0 is a 13-byte thunk then E8/E9 to 0x002AB450.
// 0x00F3EAE0: COrderExecuteCommand from CInGameIdler[4]; do not skip the body.
inline constexpr uint32_t kLandActorMoveRva = 0x01a31660;
inline constexpr uint8_t kLandActorMoveBytes[] = {
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41,
    0x55};
inline constexpr uint32_t kLandActorMoveByteCount = 15;
inline constexpr uint32_t kLandActorMoveHookBytes = 15;
inline constexpr uint32_t kLandActorMoveOwnerOffset = 0x18;
inline constexpr uint32_t kLandActorMassRva = 0x002ab450;
inline constexpr uint8_t kLandActorMassBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x20, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41,
    0x54};
inline constexpr uint32_t kLandActorMassByteCount = 15;
inline constexpr uint32_t kLandActorMassHookBytes = 15;
// CMassMoveCommand ctor 0x0134FDA0 has one caller: CCountryAI[145] body.
// That body also constructs CSetResearchCommand and CNavalMissionMassMoveCommand.
// Skip [9] for Germany only. Do not skip the [145] body.
inline constexpr uint32_t kCMassMoveCommandVtableRva = 0x0298a488;
inline constexpr uint32_t kCMassMoveCommandCanRva = 0x01359010;
inline constexpr uint8_t kCMassMoveCommandCanBytes[] = {
    0x8B, 0x41, 0x4C, 0x83, 0xF8, 0x01, 0x7C, 0x07, 0x3B, 0x41, 0x34, 0x0F, 0x94, 0xC0, 0xC3};
inline constexpr uint32_t kCMassMoveCommandCanByteCount = 15;
inline constexpr uint32_t kCMassMoveCommandCanHookBytes = 15;
inline constexpr uint32_t kLandActorExecRva = 0x00f3eae0;
inline constexpr uint8_t kLandActorExecBytes[] = {
    0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x48,
    0x08, 0x55};
inline constexpr uint32_t kLandActorExecByteCount = 16;
inline constexpr uint32_t kLandActorExecHookBytes = 16;

// CAIVolunteerGeneral[14] 0x01A5D160. Same +0x08 owner and +0x10 early-out as
// CAIGeneral. Body calls 0x01A5BF00, which constructs COrderExecuteCommand and
// posts via 0x0029E7B0. Steal 16: next insn is `push r15`. Skip original only
// for Germany. Do not intercept Idler[4] / 0x00F3EAE0.
inline constexpr uint32_t kCAIVolunteerGeneralVtableRva = 0x02a0a7b0;
inline constexpr uint32_t kCAIVolunteerGeneralOwnerOffset = 0x0008;
inline constexpr uint32_t kCAIVolunteerGeneralTickRva = 0x01a5d160;
inline constexpr uint8_t kCAIVolunteerGeneralTickBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54,
    0x41, 0x56};
inline constexpr uint32_t kCAIVolunteerGeneralTickByteCount = 16;
inline constexpr uint32_t kCAIVolunteerGeneralTickHookBytes = 16;

// Native land-org commands. Player and AI both go through these, then factories.
// Not issued until ctor arguments are confirmed in-game. Closing factories is
// not a substitute for issuing these.
inline constexpr uint32_t kCSetTheatreCommandVtableRva = 0x0298a870;
inline constexpr uint32_t kCSetTheatreCommandCanRva = 0x0135af40;
inline constexpr uint8_t kCSetTheatreCommandCanBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xF9, 0x48,
    0x8B, 0xDA};
inline constexpr uint32_t kCSetTheatreCommandCanByteCount = 16;
inline constexpr uint32_t kCSetTheatreCommandCanHookBytes = 16;
inline constexpr uint32_t kCArmyGroupCommandVtableRva = 0x029e3500;
inline constexpr uint32_t kCArmyGroupCommandDoRva = 0x01827540;
inline constexpr uint32_t kCArmyGroupCommandCanRva = 0x01831b90;
inline constexpr uint8_t kCArmyGroupCommandCanBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
    0x20};
inline constexpr uint32_t kCArmyGroupCommandCanByteCount = 15;
inline constexpr uint32_t kCArmyGroupCommandCanHookBytes = 15;
inline constexpr uint32_t kCOrderNewFrontCommandVtableRva = 0x029e4180;
inline constexpr uint32_t kCOrderNewFrontCommandDoRva = 0x0182dbb0;
inline constexpr uint32_t kCOrderNewFrontCommandCanRva = 0x01832da0;
inline constexpr uint8_t kCOrderNewFrontCommandCanBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x83, 0x79, 0x5C, 0x00};
inline constexpr uint32_t kCOrderNewFrontCommandCanByteCount = 14;
inline constexpr uint32_t kCOrderNewFrontCommandCanHookBytes = 14;
inline constexpr uint32_t kCAssignToArmyGroupCommandVtableRva = 0x029e35c8;
inline constexpr uint32_t kCAssignToArmyGroupCommandCanRva = 0x01831d40;
inline constexpr uint8_t kCAssignToArmyGroupCommandCanBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
    0x20};
inline constexpr uint32_t kCAssignToArmyGroupCommandCanByteCount = 15;
inline constexpr uint32_t kCAssignToArmyGroupCommandCanHookBytes = 15;
inline constexpr uint32_t kCOrderGroupCommandVtableRva = 0x029e3370;
inline constexpr uint32_t kCOrderGroupCommandDoRva = 0x0182b0e0;
inline constexpr uint32_t kCOrderGroupCommandCanRva = 0x01832910;
inline constexpr uint8_t kCOrderGroupCommandCanBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54,
    0x41, 0x56};
inline constexpr uint32_t kCOrderGroupCommandCanByteCount = 16;
inline constexpr uint32_t kCOrderGroupCommandCanHookBytes = 16;
inline constexpr uint32_t kCOrderGroupCommandCtorBRva = 0x0181dd70;
inline constexpr uint8_t kCOrderGroupCommandCtorBBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x48,
    0x83, 0xEC};
inline constexpr uint32_t kCOrderGroupCommandCtorBByteCount = 16;
inline constexpr uint32_t kCOrderGroupCommandBytesSize = 0x60;
inline constexpr uint32_t kCOrderGroupCommandVtableSlotCan = 9;
inline constexpr uint32_t kCOrderGroupCommandVtableSlotDo = 10;
inline constexpr uint32_t kCArmyGroupCommandCtorBRva = 0x0181b880;
inline constexpr uint8_t kCArmyGroupCommandCtorBBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC,
    0x30};
inline constexpr uint32_t kCArmyGroupCommandCtorBByteCount = 15;
inline constexpr uint32_t kCArmyGroupCommandBytesSize = 0x80;
inline constexpr uint32_t kCArmyGroupCommandVtableSlotCan = 9;
inline constexpr uint32_t kCArmyGroupCommandVtableSlotDo = 10;

// CAIGeneral[13] 0x0107D9C0. rcx is the general. Calls 0x01081FE0 three times
// then 0x01058380 -> AG/army posters. Do not skip the whole [13]: micro-move
// is already filtered at 0x01A31660. Set TLS so German theatre/AG/army/front
// command [9] and posters fail; recruit commands are not these [9]s.
inline constexpr uint32_t kCAIGeneralOrgRva = 0x0107d9c0;
inline constexpr uint8_t kCAIGeneralOrgBytes[] = {
    0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x10, 0x49, 0x89, 0x6B, 0x18, 0x49, 0x89, 0x73,
    0x20, 0x57};
inline constexpr uint32_t kCAIGeneralOrgByteCount = 16;
inline constexpr uint32_t kCAIGeneralOrgHookBytes = 16;

// AI theatre wrapper 0x00EEA3E0. German whole-body skip stopped new theatres
// and also AI recruit/deploy. Always call original so recruit stays with
// vanilla AI. Do not skip CTheatre ctor: returning 0 leaves rbx=0 and
// 0x00EDBC50 reads [rcx+0x24] (observe Germany crashed before SCW).
// Do not hook CSetTheatreCommand[10] apply 0x00EDBF80 (also CFront 0x00EEE3A0).
// Do not skip 0x006EB9B0: lea [rcx+0x310];ret, 23 callers, wrapper recruit walk.
inline constexpr uint32_t kTheatreAiCreateRva = 0x00eea3e0;
inline constexpr uint8_t kTheatreAiCreateBytes[] = {
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x18, 0x88, 0x50, 0x10, 0x48, 0x89, 0x48, 0x08,
    0x55, 0x56};
inline constexpr uint32_t kTheatreAiCreateByteCount = 16;
inline constexpr uint32_t kTheatreAiCreateHookBytes = 16;

// Collects command groups for a new CTheatre. Only callers: wrapper
// 0x00EEA800 / 0x00EEA952. rcx is CCountry*. Return count; wrapper does
// `test eax,eax; jle skip-alloc`. Returning 0 for Germany: no new theatre,
// recruit still runs (wrapper first half), but AI deploy stops. Do not skip.
// CSetTheatreCommand[10] does not call this; CCountry[4] 0x006FA752 is ctor
// from save/read, not CSetTheatre.
// Steal 16: next insn is `sub rsp, 0x48`. Probe only.
inline constexpr uint32_t kTheatreCreateGateRva = 0x00ee67f0;
inline constexpr uint8_t kTheatreCreateGateBytes[] = {
    0x4C, 0x8B, 0xDC, 0x45, 0x88, 0x4B, 0x20, 0x53, 0x55, 0x57, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57};
inline constexpr uint32_t kTheatreCreateGateByteCount = 16;
inline constexpr uint32_t kTheatreCreateGateHookBytes = 16;

// CTheatre ctor. Direct callers: 0x00EEA849 / 0x00EEA984 (the wrapper) and
// 0x006FA752 (inside 0x006F8F50). Steal 14: next insn is `mov [rsp+8], rcx`.
// Probe only. Do not skip. CSetTheatreCommand[10] is 0x013576C0 assign via
// 0x00EDBF80; it does not call this ctor.
inline constexpr uint32_t kCTheatreCtorRva = 0x00ed9f40;
inline constexpr uint8_t kCTheatreCtorBytes[] = {
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x89, 0x54, 0x24, 0x10};
inline constexpr uint32_t kCTheatreCtorByteCount = 14;
inline constexpr uint32_t kCTheatreCtorHookBytes = 14;

// Minister land-org helper. Unique caller 0x010ABA70 (after reinforcement post).
// GetCountry at +0x46. Do not skip: it is not the theatre ctor and may recruit.
// Do not hook CFront 0x00EEE3A0 or CArmyGroup 0x00EE10B0.
inline constexpr uint32_t kLandOrgHelperRva = 0x010b4620;
inline constexpr uint8_t kLandOrgHelperBytes[] = {
    0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57,
    0x41, 0x54};
inline constexpr uint32_t kLandOrgHelperByteCount = 16;
inline constexpr uint32_t kLandOrgHelperHookBytes = 16;

// Unique AI poster for CCreateAreaDefenseCommand / CEditAreaDefenseStateCommand.
// Caller 0x01086CB0 (CAIGeneral[13]/[14] helper). rcx is the general.
// Skip original for Germany. Do not skip 0x01086CB0: it also calls 0x01A31660.
// Do not intercept Idler[4] / 0x00F3EAE0; those apply already-posted execute.
inline constexpr uint32_t kAreaDefenseAiRva = 0x01085e00;
inline constexpr uint8_t kAreaDefenseAiBytes[] = {
    0x48, 0x89, 0x4C, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41,
    0x56};
inline constexpr uint32_t kAreaDefenseAiByteCount = 15;
inline constexpr uint32_t kAreaDefenseAiHookBytes = 15;

// Unique AI poster for CArmyGroupCommand / CAssignToArmyGroupCommand and
// COrderGroupCommand ctor A 0x0181DB50. rcx is an org-walk blob, not a
// vtable object. Skip for Germany via [13]/wrapper TLS. Native commands
// do not go through here.
inline constexpr uint32_t kArmyGroupAiRva = 0x0105cce0;
inline constexpr uint8_t kArmyGroupAiBytes[] = {
    0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50,
    0x10};
inline constexpr uint32_t kArmyGroupAiByteCount = 15;
inline constexpr uint32_t kArmyGroupAiHookBytes = 15;

// AI poster for COrderGroupCommand ctor B 0x0181DD70 (集团军, not 集团军群).
// Unique caller 0x0105C430, sibling of 0x0105CCE0. Skip for Germany via TLS.
// Do not hook Idler-adjacent 0x00F3AE80 (player UI also posts OrderGroup).
inline constexpr uint32_t kArmyAiRva = 0x0105c5f0;
inline constexpr uint8_t kArmyAiBytes[] = {
    0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x4C, 0x89, 0x40, 0x18, 0x48, 0x89, 0x50,
    0x10};
inline constexpr uint32_t kArmyAiByteCount = 15;
inline constexpr uint32_t kArmyAiHookBytes = 15;

// Second AI OrderGroup ctor B poster. Unique caller 0x01058380. Skip for
// Germany via TLS. Volunteer [14] also posts via 0x01A5EA30; Germany already
// skips that tick.
// Steal 16: next insn is `sub rsp, 0x78`.
inline constexpr uint32_t kArmyAi2Rva = 0x01059820;
inline constexpr uint8_t kArmyAi2Bytes[] = {
    0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
    0x8B, 0xEC};
inline constexpr uint32_t kArmyAi2ByteCount = 16;
inline constexpr uint32_t kArmyAi2HookBytes = 16;

}  // namespace hoiv::adapter
