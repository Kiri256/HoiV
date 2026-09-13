# 已实现功能与验收记录

截至 2026-09-13。

## 文档定位

本文只记录已经写入仓库、能够被构建或在游戏内复现的功能及其证据。计划中的架构、阶段、P0/M0 门槛和「必须证明」只见 `AI_REALISM_OPTIMIZATION_PLAN.md`。长期规则见 `AGENTS.md`。逆向步骤和废路见 `AI_REVERSE_ENGINEERING.md`。

本文不预写未来阶段规格，也不把文档或 `descriptor.mod` 当成运行时功能。中间试错过程不在这里展开。

## 当前基线

仓库有 P0.1 运行时代码，以及瑞士单师原生移动/取消探针。本机已对 HOI4 1.19.1.0 完成加载、版本识别和停用。瑞士战役下国家槽 29、圣加仑 11623、命令句柄 `51/2476`、组织度与 HP 166.9 已有游戏内对照。`GetPlayer` 仍为 0。一次 `CMoveCommand` 已把同一师从 11623 走到 11604；另一次在 11601 途中被 `CCancelMovementCommand` 取消后停下。操作者手控瑞士，不能当作抗覆盖。不能宣称已经控制该师。主要国家陆军 AI 仍未抑制。

| 能力 | 状态 | 证据 |
|---|---|---|
| bridge DLL | P0.1 已在 HOI4 进程内加载 | `--status`：`version_ok=1 hooks=1 writes=0`，哈希与 `1.19.1.0` 一致 |
| DLL 加载器 | P0.1 已对运行中的 HOI4 加载 | `launcher --load` 后会话可查询；`--disable` 后 `hooks=0 disabled=1` |
| HOI4 版本门控 | 已在游戏会话中通过 | 钉扎 SHA-256 与 PE 时间戳匹配；`product_version=1.19.1.0` |
| BlackICE 构建适配器 | 已钉扎只读布局 | `layout.hpp` 含 GetPlayer / 国家数组 / 国家 `+0x290` / 位置 `+0x1F0` / 省份 `+0xA4` / 组织度 `+0x428` 与 `*(+0x138)+0x280` / HP `+0x420` |
| HOI4 对象读取 | 瑞士战役师对象已对照 | `idx=29` 为 SWI；圣加仑 11623；句柄 `51/2476`；组织度实时恢复、HP 166.9，`org_valid=1`。`GetPlayer` 仍为 0 |
| 状态快照发布 | 部分实现 | `SharedBlock` 含命令句柄、省份、组织度 0–1 比例、HP。不含游戏指针。玩家国家仍钉瑞士 |
| 外部 planner.exe | 有占位进程 | `planner.exe` 只连接会话并退出，不规划 |
| 世界模型 | 未实现 | 无对象生命周期实现 |
| 战略/战役/战术规划 | 未实现 | 无运行时代码 |
| 原生移动订单 | 部分实现 | 瑞士 `51/2476`：`--move` 11604 得到达；途中 `--cancel` 得 `result=8`，停在 11601。默认门控仍关。手控瑞士，无陆军 AI 可对抗。其他订单未做 |
| 防线、进攻线、支援、撤退订单 | 未实现 | 无订单适配器 |
| 反馈闭环 | 未实现 | 无结果采集 |
| 存档读档恢复 | 未实现 | 无持久化实现 |
| 事件日志和回放 | 未实现 | 仅有本地文本日志 |
| 游戏内验收 | P0.1 通过；瑞士单师移动与取消已对照；国家识别、抗 AI、读档未完成 | `51/2476` 能走到 11604，也能在 11601 取消停下。手控瑞士，不能当抗覆盖。`GetPlayer` 仍为 0 |

默认配置为 `enabled=0`、`read_only=1`、`max_orders_per_hour=0`。P0.1 即使版本通过也不打开写入。

## P0 记录

门槛定义见计划中的「P0：可行性探针」。下表与计划中的验收记录行一一对应。任一行未通过，按计划放弃项目。

### 环境

```text
HOI4 版本：1.19.1.0（launcher-settings.json rawVersion；exe VERSIONINFO 为 1.0.0.0，不能单独作为门控）
HOI4 exe SHA-256：16022851eaa571728aa3a0b5fd5f990a56da57e2249a4c1b9cfb30336f59b120
PE 时间戳：1781617671
BlackICE 版本：12.1.0（Documents/Paradox Interactive/Hearts of Iron IV/mod/1137372539/descriptor.mod）
操作系统：Windows 10 10.0.26100 x64
DLL 构建号：本地 MinGW-W64 14.2.0 / CMake 3.30.4，2026-09-13 已在 HOI4 进程内加载
adapter 构建号：hoi4_1_19_blackice_12_1，已确认 GetPlayer `8B 81 30 0A 00 00 C3`、玩家 tag `+0xA30`、国家数组 `+0x310/+0x31C`、国家师列表 `+0x290`、师位置 `+0x1F0`、省份 ID `+0xA4`、师句柄 `+0x18`、组织度 `+0x428`/`*(+0x138)+0x280`、HP `+0x420`
planner 构建号：占位进程
观察窗口（游戏小时）：未通过。手控瑞士，该国陆军 AI 本来关闭，到达 11604 后停住不能当窗口证据
```

### 结果

| 项目 | 结果 | 证据 |
|---|---|---|
| DLL 加载 | 通过 | 2026-09-13 `launcher --status`：`schema=1 version_ok=1 hooks=1 writes=0 error=0`，SHA-256 与钉扎值一致 |
| 版本识别 | 通过 | 同会话 `product_version=1.19.1.0`，`last_error=version gate passed; writes remain disabled` |
| 国家读取 | 未通过 | 瑞士战役 `idx=29 tag=29` 与 BlackICE SWI 槽一致，`GetPlayer` 仍为 0，字母 tag 未读到。不能当作任意当前国家/玩家识别 |
| 师对象读取 | 通过 | 瑞士圣加仑：`province=11623`、`org_valid=1`、HP 166.9。命令句柄 `division_id=51 gen=2476`。两次 `--status` 组织度 14.23→14.25，句柄不变。不是下标 18，不是指针，也不是界面「Division 6」 |
| 移动订单创建 | 通过 | 2026-09-13 瑞士圣加仑 `51/2476`：`writes=1` 后 `--move` 11604，`attempts=1 accepted=1 result=4`。地图出现该师朝苏黎世方向的黄色移动箭头，选中框带向上移动标记 |
| 移动订单执行 | 通过 | 2026-09-13 同句柄 `51/2476`：`--move` 11604 后 `result=4`，地图从圣加仑指向伯尔尼。`--status` 为 11623→11601→**11604**，HP 始终 166.9，组织度 14.23→9.59→10.03。操作者确认到达目标。不是 661/11590 那两师 |
| 订单取消 | 通过 | 2026-09-13 同句柄 `51/2476`：`--move` 11604 后在 11601 `result=4`。`--cancel` 得 `attempts=2 result=8`。操作者确认师停住，不再前往 11604 |
| 对抗 AI 覆盖或抑制陆军 AI | 未通过 | 手控瑞士到达 11604 不能当抗覆盖。2026-09-13 主要国家：下列闸均未停住组建或走动，见失败记录 |
| 读档重建 | 未通过 | 未实现 |
| 停用和回退 | 通过 | `--disable` 后 `hooks=0 disabled=1 writes=0`，会话仍可查询。P0.1 未抑制原生 AI，停用后游戏继续自行运行 |

### 失败记录

每次失败记录：游戏构建和 adapter、特征码、发生线程、对象或实体 ID/generation、函数返回值、日志错误码、是否自动停用、是否能回到原生 AI。中间误读（下标当 ID、跟错师、扫错国家）的路径细节只在逆向文档。

**国家读取（未通过）**

- 构建：HOI4 1.19.1.0 / adapter `hoi4_1_19_blackice_12_1`。游戏线程。
- `GetPlayer` 特征码可安装，但瑞士战役该函数不被调用，返回值仍为 0。
- 国家数组可读（190 国），玩家不能由 `+0x145C`、Idler `+0x4F0` 或「第一个有军队的国家」定位。当前热路径钉 BlackICE SWI 槽 29。
- 未自动停用。此条不算任意当前国家/玩家识别通过。

**对抗 AI 覆盖或抑制陆军 AI（未通过）**

均在 2026-09-13、瑞士战役、`writes=1` 后 `--no-land-ai`，游戏线程。钩子未自动停用。操作者确认主要国家部队仍调动或仍会组建。不得标已实现。

| 尝试 | 返回 | 游戏内结果 |
|---|---|---|
| 主要国家 `CCountryAI+0x60` | `result=9 land_ai_off=7` | 部队仍调动。只跳过小时 `Update` |
| 全局 `ai` 字节 `0x03304C9C=0` | `ai_global=0 result=9` | 各国国策、生产、科研全部停。禁止再写 0 |
| 主要国家 `CCountryAI+0xC20` | — | 部队仍调动。是断言，不是闸 |
| 跳过 `0x00D61C30` | — | 部队又动。不是唯一发单口 |
| `CAIGeneral[14]` | `path=general result=9`，`gens=0 ger ai=1 mil=1 gen=0` | 仍创建战区及下属单位。德国 1936 将军数为 0 |
| CFront 工厂 `0x00EEE3A0`、CArmyGroup 工厂 `0x00EE10B0`、战线 `[2]`、大臣 `[12]` | — | 仍创建战区、集团军群、集团军，部队仍移动 |
| 游戏线程对未知窗口 `VirtualQuery` 宽扫 | `result=0 path=none` | 游戏卡死。禁止再扫 |

手控瑞士到达 11604 后停住：该国陆军 AI 本来关闭，已从「观察窗口通过」撤回。

### P0.1 离线证据

2026-09-13 在本机执行 `cmake --build build` 后运行 `build/p0_tests.exe`，结果为 `P0.1 offline tests passed`。

覆盖：默认三门关闭；未钉扎/哈希失配/PE 时间戳失配/非 `hoi4.exe`/1.18 均拒绝；`rawVersion=1.19.1.0` 可覆盖 exe VERSIONINFO `1.0.0.0`；钉扎后的 `p0_host.exe`（产品版本 1.19.2）允许只读加载；hook 二次 `Initialize` 不叠装，`Disable` 后可再装一次；`bridge.dll` 从宿主卸载后宿主仍存活；`write_enabled` 保持 0。

这不是 HOI4 游戏内证据。

### P0.1 游戏内证据

2026-09-13 操作者在 HOI4 运行时执行 `build\launcher.exe --status` / `--disable`：

```text
schema=1 version_ok=1 hooks=1 installs=2 writes=0 disabled=0 error=0
product_version=1.19.1.0
last_error=version gate passed; writes remain disabled

--disable 之后
schema=1 version_ok=1 hooks=0 installs=2 writes=0 disabled=1 error=0
last_error=bridge disabled; hooks uninstalled
```

`installs=2` 且当时 `hooks=1`，表示重复加载没有把 hook 叠成两份。写入始终关闭。

### P0.2 离线证据

2026-09-13 关闭 HOI4 后重新链接 `bridge.dll`，运行 `build/p0_tests.exe`，结果为 `P0.2 offline tests passed`。

覆盖：`GetPlayer` 特征码与 int3 填充比对，错误字节拒绝；空指针、未对齐指针、越界 CPdxArray、tag=0 或 tag 失配均拒绝；测试宿主逻辑安装 hook，`read_ok=0`、`division_ok=0`、`org_valid=0`，不伪造国家和师；`write_enabled` 保持 0；二次 Initialize 不叠 hook。

这不是 HOI4 游戏内证据。国家读取在有对照记录前保持未通过。师对象读取的游戏内对照见上表。

## 后续阶段

P1 及之后的计划验收见计划正文。本文只在对应阶段已经有代码和游戏内证据时，新增该阶段的结果表。

## 不得标记为已实现

即使已经写入计划，在有代码和证据之前也不得标记完成：

- 任意当前国家/玩家识别（`GetPlayer` 仍为 0，瑞士只是钉槽）
- 除已取证的瑞士单师移动创建/执行/取消外的其他原生订单
- 读档重建
- 对抗 AI 覆盖或抑制陆军 AI（手控瑞士上的停住不算）
- 逐师、逐军或战区控制
- 外部规划能力
- 存档恢复
- 多人同步
- 真人化行为
- 长时间稳定性

## 静态检查

代码首次加入后，每次变更执行 `git diff --check`，并检查 ABI schema、hook 安装和卸载、游戏线程与规划线程边界、订单幂等和超时、adapter 版本门控、日志关联字段，以及本文状态与代码是否一致。

2026-09-13：`git diff --check` 无空白错误。`schema_version=1`，`SharedBlock` 已增加只读快照字段，`struct_size` 必须双方一致。版本门控或特征码失败则拒绝发单和采集。写入默认关闭。
