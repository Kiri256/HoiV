# HOI4 1.19.1.0 / BlackICE 12.1 逆向底稿

截至 2026-09-20。只服务当前钉扎构建。换构建整份作废，禁止复用 RVA。

运行时常数和指纹以 `adapters/hoi4_1_19_blackice_12_1/layout.hpp` 为准。本文是地图，不抄第二份字节。扫描器在 `tools/re_scan/`，不进默认 CMake。命令索引 `build/re_cmd_index.json` 绑定本构建 SHA-256。

读没读对、算不算实现，只看 `AI_IMPLEMENTED_FEATURES_ACCEPTANCE.md`。本文不是验收。适配器里还留着废路常数（例如 `kArmyAiIssueRva = 0x00D61C30`），不表示那条路可用。

## 怎么用

先看「当前图像」。查偏移看「对象图」。发单看「玩家写入」。找陆军 AI 看「行动者」。不要从废路再开一条平行猜测。

每个新候选只做三件事：函数边界、直接调用者、对象 RTTI/国家。缺一项就排除。静态相似不算进展；进游戏后 `enters` / `seq` / `probe` 不动，换点。

## 构建身份

```text
exe: C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe
rawVersion: 1.19.1.0（launcher-settings.json；exe VERSIONINFO 1.0.0.0 不能单独门控）
SHA-256: 16022851eaa571728aa3a0b5fd5f990a56da57e2249a4c1b9cfb30336f59b120
PE 时间戳: 1781617671
Image base: 0x140000000
BlackICE: 12.1.0（mod\1137372539\descriptor.mod，supported_version=1.19.2.0）
```

`launcher --identify` 写入 `config.ini` 后才允许注入。不要用 2019 年论坛地址。

| 用途 | 值 |
|---|---|
| 热路径 | 德国 tag 1（BlackICE `00_countries.txt`：1 GER … 7 JAP） |
| 瑞士历史对照 | 槽 / tag 29，圣加仑 11623，句柄 `51/2476`，HP 166.9。不再采 |

## 当前图像

德国采样师原生命令已到达。`--army` 一次出现集团军、集团军群和「德国第1战区」。额外战区走 UI「新战区」=`CAssignToTheaterGroupCommand`。读档、`GetPlayer`、德国 `--cancel`、同进程 `--disable` 恢复走动未过。师模板和运营不在产品范围内。

本构建陆军师移动有三条机制：

```text
有 CAIGeneral
  大臣[14] -> 将军[13]/[14] -> 0x01A31660 -> 0x01A2ED80 -> CMoveCommand

无 CAIGeneral（德国 1936 已见 gens=0）
  CInGameIdler[4] -> 0x00F3EAE0 -> COrderExecuteCommand
  走的是已有计划，不是新的 CMoveCommand

有 CAIVolunteerGeneral
  [14] 0x01A5D160 -> 0x01A5BF00 -> COrderExecuteCommand（经 0x0029E7B0 发布）
```

`CMoveCommand` 构造器全镜像只有五处：海军一、玩家 UI 二、将军链二。没有第四条陆军 AI 口。`CCountryAI[145]` 没有 `E8` 是因为走虚表。

德国 tag 1 现行拦截（`skip_theatre_ai` 不控制这些闸）：

| 作用 | 钩点 | 做法 |
|---|---|---|
| 微操 | `0x01A31660` | 跳过 |
| 集体移动 | `[145]` 本体照跑；`CMassMoveCommand[9]` `0x01359010` | 只挡 `[9]`，避免停科研 |
| 支援军 | `CAIVolunteerGeneral[14]` `0x01A5D160` | 跳过 |
| 区域防卫 | 发布口 `0x01085E00` | 跳过。不拦 Idler[4] |
| 战区 | 包装照跑；闸 `0x00EE67F0` 照跑 | 整段让闸返回 0：无新战区、能招募、不部署。已撤 |
| 集团军群 | `0x0105CCE0` | 德国 TLS 跳过 |
| 集团军 | `0x0105C5F0`、`0x01059820` | 德国 TLS 跳过 |
| 计划执行 | Idler `0x00F3EAE0` | 挂钩不跳过 |

2026-09-20 操作者确认：ctor 跳过内战前崩溃，已撤。整段让 `0x00EE67F0` 返回 0：无新战区、能招募、不部署、不崩，已撤；撤后 `--status` `org=683 skip=0 ag skip=42766`，可以部署。`skip_th` 只是未用配置项。不要关工厂，不要拦 `0x00EDBF80`，不要拦 Idler 旁路 `0x00F3AE80`。集团军/集团军群走玩家 ctor，不走 AI 发布口。

## 工作方法

1. 先建命令调用图：`.pdata`、命令 RTTI/vtable、构造器、`0x0029E670` / `0x0029E7B0`。缓存绑定本构建哈希。
2. 只留陆军移动和战斗编成。丢掉 `CTaskForce`、海空军、玩家 UI、通用 dispatcher、招募/科研。
3. 优先同时具备：对象类型、国家归属、AI 调用者。
4. 构造器和两个通用发布器只可观测，不能全局拦截。
5. 游戏线程禁止对未知窗口 `VirtualQuery` 宽扫。

## 类型

见过：`CCurrentGameState`、`CGameState`、`CCountry`、`CArmy`、`CUnit`（没有 `CDivision`）、`CProvince`、`CGameIdler`、`CInGameIdler`。

没有：`CLandUnit`、`CUnitStats`、`GetOrganisation`、`CPdxArray<CUnit*>`。战区类名是 `CTheatre`，没有 `CTheater`。

CPdxArray：`+0x00 data`，`+0x08 capacity`，`+0x0C size`。

| 类 | 虚表 RVA |
|---|---|
| CCurrentGameState | `0x026FB148` |
| CGameState | `0x026FB0D0` |
| CCountry | `0x027C0E80` |
| CCountryAI | `0x02710C90`；第二张 `0x02710D20` |
| CArmy | `0x02933D20` |
| CUnit | `0x0292CCE8` |
| CProvince | `0x0294AE78` |
| CGameIdler | `0x02710270` |
| CInGameIdler | `0x02942480` |
| CHuman | `0x026FAD98` |
| CAIMilitaryMinister | `0x02962938` |
| CAIGeneral | `0x029613D0` |
| CAIVolunteerGeneral | `0x02A0A7B0` |
| CMoveCommand | `0x0298A3C0` |
| CCancelMovementCommand | `0x0298A618` |
| COrdersGroup | `0x0292BEC0` |
| CArmyGroup | `0x0292BF58` |
| CFront | `0x0294EE20` |
| CTheatre | `0x0294ED28` |
| CTheaterGroup | `0x029BE6C0` |
| CTaskForce | `0x0293C6D0`（海军） |
| CPdxMouse | `0x02B31950` |

## 对象图

```text
CCurrentGameState / CGameState          单例 RVA 0x033048C0
  +0x310 / +0x31C  CCountry*[]
  +0xA30           玩家 tag（GetPlayer 读这里；瑞士战役函数冷，值为 0）
  +0xA39           开局字节，不是唯一判据

CCountry
  +0x08            tag，等于国家数组下标
  +0x228           CCountryAI*          分配 0xC28，存点 0x00705D58
  +0x290           CArmy*[]             GetArmies 0x006C2410
  +0x548           命令组数组           0x006C2680
  +0x145C          [8] 早退字节，瑞士 190 国全 0
  +0x223D          陆/外/内政都看，禁止写

CCountryAI
  +0x08            CCountry*
  +0x60            Update 跳过；小时 tick 不走 [2]
  +0xBC0 / +0xBC8 / +0xBD0   外交 / 陆军大臣 / 内政
  +0xC20           IsCommandsAllowed，断言不是闸
  [14] 0x002ACC80  创建大臣并写 +0x60=1
  [16]             小时 tick 读 +0x60
  [145] 0x002A7DE0 thunk -> 0x002AB450  含 CMassMoveCommand 和 CSetResearchCommand

CAIMilitaryMinister   大小 0x7A0
  +0x08            所有者
  +0x98            CAIGeneral*[]
  [12] 0x010BB0D0  创建将军
  [14] 0x010ABA70  遍历将军调 [14]；无将军仍发补员

CAIGeneral
  +0x08            CCountryAI*
  +0x10            空则 [14] 直接返回，禁止写这个字段
  [13] 0x0107D9C0  -> 0x01081FE0 -> AG/army 发布口；另到 0x01A31660
  [14] 0x01074470  经 0x01086CB0 -> 0x01A31660

CAIVolunteerGeneral
  +0x08            所有者
  +0x10            空则 [14] 直接返回
  [14] 0x01A5D160  -> 0x01A5BF00 -> COrderExecuteCommand

CArmy
  +0x18 / +0x1C    命令句柄 id / generation
  +0x138           属性块*
  +0x1C0           用户指针，不是句柄
  +0x1F0           CProvince*
  +0x420 / *+0x288 HP 当前 / 最大
  +0x428 / *+0x280 组织度当前 / 最大

CProvince          +0xA4  省份 ID
CFront             +0x18  所有者
COrdersGroup       +0x39  计划 AI 锁；ctor 默认写 1。禁止焊这个字节当产品闸
CTheatre ctor      0x00ED9F40  包装内两处调用；第三处 0x006FA752 不拦
CInGameIdler
  [4]              -> 0x00F3EAE0
  [6]              DoCountryHourlyUpdates
  +0x2F8 / +0x4F0 / +0xA08   不是任意玩家指针
```

GetCountry：`0x002A8D90`。`CCountryAI[1]` 返回 this；`GetCountry` 再读 `+0x08` 得 `CCountry*`。

## 读取

热路径（每 100 ms 最多一次）：

```text
GetPlayer 字节当指纹（不采样）
-> IAT 钩 PeekMessageW（先调原函数）
-> 单例 -> 虚表确认
-> 钉测试国 +0x290
-> 已确认师读位置 / 句柄 / 组织度 / HP
```

`enters` 增加 = 采样在跑。`seq` 增加 = 写过快照。不把游戏指针写出进程。禁止每帧扫 190 国。

| 名称 | RVA / 偏移 | 备注 |
|---|---|---|
| 单例 | `0x033048C0` | RIP 相对加载 |
| GetPlayer | `0x001DBB30` | `8B 81 30 0A 00 00 C3`。瑞士冷 |
| GetAI | `0x006C2400` | `mov rax, [rcx+0x228]; ret` |
| GetArmies | `0x006C2410` | `lea rax, [rcx+0x290]; ret` |
| 省份 ID | `+0xA4` | 内联 GetProvinceID |
| 位置 | CArmy `+0x1F0` | |

不要：tag=0 / 下标 0 / 第一个有军队的国家当玩家；调用 `0x021FFD50` 解析句柄；把组织度 getter `[39]` 当采样点。

组织度脚本范围 0–1，UI 的 14 是显示换算。

## 玩家写入

默认不发单。一种订单成功不能推断另一种可用。游戏内对照见验收文档。

**移动。** 构造 `CMoveCommand`（`0x01350350`，0x88）→ `[9]` edx=0 → `[10]`。句柄在命令 `+0x38`，抄自 `CArmy+0x18`。玩家 UI：`0x014B8993`、`0x014B8E09`。将军链：`0x01A2FAEE`、`0x01A2FC53`。`0x00D62020` 是海军。

**取消。** `CCancelMovementCommand`（`0x0134F9D0`，0x48，`rdx=CArmy*`，r8=0）→ `[9]` `0x01358190` → `[10]` `0x01355840`。玩家点 `0x0144E2D3`。

拦移动 `[9]/[10]` 能停部队，和自己发单冲突，不是抑制路径。

**战区。** 战区和集团军群都必须至少挂一个集团军，不能建空对象。第一次战区随第一条集团军出现：2026-09-20 `--army` 后编制栏同时有「德国第1战区」、集团军群和集团军。额外战区是把已有集团军调到新容器，源侧必须还剩集团军。不是 `CSetTheatreCommand`。

玩家底部「新战区」是 `theatreselector.gui` 的 `new_theater_group_button`，文案键 `NEW_THEATER_GROUP`（「点击创建新的战区并将所有选中的集团军调派其麾下」）。命令是 `CAssignToTheaterGroupCommand`（vt `0x02A0AE00`）。[10] `0x01A61F60`：解析 `+0x28`；有父对象则 `0x00EDCA30` 挂到已有战区；`+0x28` 为空则 `0x00EE1400` 新建。这不是派系 `CTheaterGroup` 专用口。未发。

`CSetTheatreCommand`（vt `0x0298A870`，工厂 `0x01355120`，大小 `0x38`）是指派。[10] `0x013576C0` 找不到匹配就返回。不发。`CTheatre` ctor `0x00ED9F40` 仍只有包装两处和 `CCountry[4]` `0x006FA752`。`CMoveArmiesInTheaterCommand` / `CMoveArmyGroupInTheaterCommand` 在已有战区里挪。

**集团军。** 玩家：`COrderGroupCommand` ctor B `0x0181DD70`（大小 `0x60`）← UI `0x00F3AE80` 经 `0x02231380` 发布。AI 发布口 `0x0105C5F0` / `0x01059820` 不是入口。ctor：`rdx` 是选中对象数组（`CPdxArray`，元素是带 `+0x18` 句柄的师），`r8` 是父对象（AI 用 `0x00BEFF30` = `[obj+0x2A0]`），`r9` 可空。`[9]` `0x01832910` 要能解析 `+0x48` 父句柄；`[10]` `0x0182B0E0` 在有选中成员时走 `0x00BE28F0`，空则 `0x00EE1270` 建 `COrdersGroup`。2026-09-20 `--army` `result=4`：集团军出现，同时出现集团军群和第一个战区（父级不能空）。

**集团军群。** 必须至少挂一个集团军。玩家：`CArmyGroupCommand` ctor B `0x0181B880`（大小 `0x80`）← UI `0x00F3B1A0` 经 `0x02231380`。ctor A `0x0181B3E0` 只被 AI 发布口 `0x0105CCE0` 调用。ctor B：`rdx` 是 `COrdersGroup*` 数组（句柄在对象 `+0x08`），`r8` 是父对象。`[9]` `0x01831B90` 要 `+0x3C` 或 `+0x54` 非空且 `+0x28` 可解析；`[10]` `0x01827540` 调集团军群工厂 `0x00EE10B0`。孩子是集团军，不是师。再开一个集团军群要调走其中一个集团军，不能拿唯一的集团军把旧群掏空。`CAssignToArmyGroupCommand` 是编入，不是创建。单独 `--ag` 未对照。

AI 发布口不是原生命令入口。不拦 `0x00F3AE80`。

## 行动者

### 微操

`0x01A31660` 的 `rcx` 是师列表，不是虚表对象。按 `[rcx+0x18]` 取国家。不要拦单师函数 `0x01A2ED80`。德国按 tag 1 跳过。

同覆盖面、不是师移动：`0x0107D190` 战略部署；`0x0107AFB0` 陆军 HQ 部署/撤回。

### 集体移动

`CCountryAI[145]` 本体约 2467 字节，经 `0x0029E7B0` 还发 `CNavalMissionMassMoveCommand` 和 `CSetResearchCommand`。整段跳过会停科研。德国线程只让 `CMassMoveCommand[9]` 返回 0。不要拦 `0x0029E7B0`。不能偷 thunk `0x002A7DE0` 的 14 字节。

### 志愿军

`CAIVolunteerGeneral[14]` `0x01A5D160` 按德国 tag 且虚表匹配时跳过。外交口 `CSendVolunteerAction` 未拦。

### 计划执行

`CInGameIdler[4]` 调 `0x00F3EAE0`。国家不在 rcx/rdx/r8（见过 `CPdxMouse`）。禁止拦 Idler 执行器。要关自动走，只按国家过滤「谁把计划设成执行」。区域防卫新命令走 `0x01085E00`。

ctor 默认 `COrdersGroup+0x39=1`，计划 AI 一开始就是开的。禁止写这个字节当产品闸。

### 战区 / 集团军群 / 集团军

包装 `0x00EEA3E0` 很热，rcx 是 `CCountry`。前半 `0x006EB9B0`（`lea [rcx+0x310]`）走招募；后半 `0x00EE67F0` 收集编制组后要么新建战区要么 `0x00EF1920` 填已有战区，这就是自动部署。整段跳过包装：招募也停。整段让 `0x00EE67F0` 返回 0：能招募、不部署、无新战区、不崩，已撤。不要跳过 `CTheatre` ctor。不要拦 `0x00EDBF80`（和 `CFront` 共用）。`0x001B11A0` 有 95 处调用，不是战区闸。`0x00BEFF30` 是 `mov rax,[rcx+0x2A0]; ret`，师/编制组上的父对象，不是删除。

集团军群/集团军发布口 rcx 是无镜像虚表的 walk blob，国家从德国 `[13]` 或包装 TLS 继承。

编制辅助 `0x010B4620` 不跳过。战线工厂 `0x00EEE3A0`、集团军工厂 `0x00EE10B0` 不是产品闸。

## 废路

本构建游戏内已失败。禁止再当产品路径。

| 路径 | 游戏内 | 结论 |
|---|---|---|
| `GetPlayer` hook 采样 | `seq=0` | 冷。改消息泵 + 单例 |
| `+0x145C` / Idler `+0x4F0` / 第一个有军队的国家 | tag=1 或空 | 不是玩家 |
| Idler `+0x2F8` / `+0xA08` 当任意玩家 | 指到 30 或省份 6945 | 只作瑞士槽提示 |
| 全表 RTTI / 190 国扫师 / 每帧 `0x800` | 卡顿或 `armies=0` | 禁止宽扫 |
| CArmy `+0x1C0` 当句柄 | 用户指针 | 句柄在 `+0x18` |
| 离开 11623 后跟「境内最后一师」 | 跟错师 | 必须锁句柄 id+generation |
| `CCountryAI+0x60` | `land_ai_off=7`，仍走 | 只跳过 Update |
| 全局 `ai` `0x03304C9C=0` | 国策/生产/科研全停 | 加载后若为 0 则恢复 1 |
| `CCountryAI+0xC20` | 仍走 | `jz +1; int3` 后照发 |
| 跳过 `0x00D61C30` | 仍走 | 海军 `CTaskForce` |
| 拦 `CMoveCommand` `[9]/[10]` | 能停，卡顿，挡自己 | 不是抑制路径 |
| 写 `COrdersGroup+0x39` | 锁不到或焊死计划 | 以后要自己组建 |
| `CAIGeneral[14]` 早退 | `gens=0`，仍建战区 | 没有将军可跳 |
| 战线/集团军工厂 + `[2]` + 大臣 `[12]` | 仍建、仍走 | 关错对象 |
| 跳过编制辅助 `0x010B4620` | 人控德国无战区；`observe` 后仍出现 | 辅助函数不发可见战区 |
| 整段跳过 `0x00EEA3E0` | 不再长战区；招募也停 | 招募留给原版 |
| 跳过 `CTheatre` ctor 返回 0 | 无新战区、招募仍在；德国 observe 内战前崩溃 | 调用方把 rax=0 当 this，`0x00EDBC50` 读 `[rcx+0x24]`。禁止再跳 |
| 整段让 `0x00EE67F0` 返回 0 | 无新战区、能招募、不部署、不崩 | 后半段就是把编制组挂到战区。部署留给原版 |
| 游戏线程宽扫锁计划组 | 卡死 | 禁止再扫 |
| 国家 `+0x223D` | — | 外交/内政一起看 |
| `--no-land-ai` | 上表各闸 | 已废路径 |

瑞士战役全局探针计数含德法，不能当瑞士本国抑制证据。不要再等 `0x00F3EAE0` 的 `exec_tag=1`。

## 未钉扎

1. 任意当前玩家：`GetPlayer` 仍为 0。
2. 同进程 `--disable` 后德国陆军是否立刻恢复走动。
3. 计划执行为哪国：不在 Idler 执行器的前三个参数上。
4. 额外战区：`CAssignToTheaterGroupCommand` 已钉「新战区」按钮，尚未发单。发单对象必须是已有多个集团军里的一个。单独 `--ag` 未对照，且不能对唯一集团军发。战线未发。
5. 德国 `--cancel`。防线/进攻线等其他订单未发。
6. 读档后句柄/对象失效。
7. 国家上除 `+0x290` 外的编制字段；CArmy `[13]` 的 `+0x340`。

## 换构建

1. `--identify`。哈希或时间戳变了，本文和适配器一起作废。
2. 重跑 RTTI、单例 RIP、GetPlayer 字节、国家循环、GetLocation、GetProvinceID、IAT。丢掉旧命令索引。
3. 指纹对不上：停采集和发单，不套旧偏移。
4. 以游戏内 `enters` / `seq` / `probe` 和 UI 为准，不以「hook 已安装」为准。
