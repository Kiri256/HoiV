# HOI4 1.19.1.0 / BlackICE 12.1 逆向记录

截至 2026-09-13。只记录**当前钉扎构建**上做过什么、看到什么、哪条路废了。换构建必须整份重做，禁止复用旧 RVA。

运行时常数在 `adapters/hoi4_1_19_blackice_12_1/layout.hpp`。一次性扫描器在 `tools/re_scan/`，不进默认 CMake 目标。

游戏内是否读对、是否算实现，只以 `AI_IMPLEMENTED_FEATURES_ACCEPTANCE.md` 为准。本文不是验收。

## 构建身份

```text
exe: C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe
rawVersion: 1.19.1.0（launcher-settings.json；exe VERSIONINFO 是 1.0.0.0，不能单独门控）
SHA-256: 16022851eaa571728aa3a0b5fd5f990a56da57e2249a4c1b9cfb30336f59b120
PE 时间戳: 1781617671
Image base: 0x140000000
BlackICE: 12.1.0（Documents\...\mod\1137372539\descriptor.mod，supported_version=1.19.2.0）
```

本机已装 Python 3.13。安装后要重载 PATH。探索用 Python，已确认模式再固化进 C++ 适配器。旧扫描器仍可现编现跑：

```text
g++ -O2 -std=c++17 -o build\re_<name>.exe tools\re_scan\scan_<name>.cpp
build\re_<name>.exe "C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\hoi4.exe"
```

不要用 2019 年论坛地址（例如 `hoi4.exe+0x0119F834`）。

## 怎么扫

1. `launcher --identify` 钉死 SHA-256、PE 时间戳、`rawVersion`、BlackICE `descriptor.mod`。写入 `config.ini` 后才允许注入。
2. `scan_rtti.cpp` / `scan_strings.cpp` / `scan_xref.cpp` 找类型和断言。
3. `scan_singleton.cpp` 找 `CCurrentGameState*` 的 RIP 槽。
4. `scan_hex.cpp` / `dump_getplayer.cpp` 钉 `GetPlayer` 字节，只当构建指纹。
5. 国家循环、GetArmies、GetLocation、GetProvinceID、组织度字段、命令句柄各自单独确认后再进适配器。
6. 新采样点以「进游戏后 `enters`/`seq` 会动，且 tag/省份能对上 UI」为准。冷 hook 不算。

## 已见到的类型和断言

类型名：`.?AVCCurrentGameState@@`、`.?AVCGameState@@`、`.?AVCCountry@@`、`.?AVCUnit@@`（没有 `CDivision`）、`.?AVCArmy@@`、`.?AVCGameIdler@@`、`.?AVCProvince@@`。

有用断言：`Tag == CCurrentGameState::GetInstance()->GetPlayer()`、`Prov.GetProvinceID() != 0`、`!GetCountry().GetCountry().GetArmies().Contains( this )`、`DoCountryHourlyUpdates`、`organisation_strength` / `max_organisation`（命名属性，不是字段名）。

没有：`GetOrganisation`、`CDivision`、`CPdxArray<CUnit*>` 类型名。

虚表：

| 类 | 虚表 RVA |
|---|---|
| CCurrentGameState | `0x026FB148` |
| CGameState | `0x026FB0D0` |
| CCountry | `0x027C0E80` |
| CArmy | `0x02933D20` |
| CUnit | `0x0292CCE8` |
| CProvince | `0x0294AE78` |
| CGameIdler | `0x02710270` |
| CInGameIdler | `0x02942480` |
| CCountryAI | `0x02710C90` |
| CAIMilitaryMinister | `0x02962938` |
| CMoveCommand | `0x0298A3C0` |
| CCancelMovementCommand | `0x0298A618` |

CCurrentGameState 与 CGameState 虚表相差 `0x78`，按派生处理：国家数组和玩家 tag 在同一对象上。

CPdxArray：

```text
+0x00 T* data
+0x08 int32 capacity
+0x0C int32 size
```

## 已钉扎（只读）

| 名称 | 值 | 证据 |
|---|---|---|
| 单例 | RVA `0x033048c0` | 多处 RIP 相对加载 |
| GetPlayer | RVA `0x001DBB30`，`8B 81 30 0A 00 00 C3` | 函数体 + int3。瑞士战役冷，11 个 call，多数站点内联 `[this+0xA30]` |
| 玩家 tag 字段 | `+0xA30` | 上一条。游戏里 `GetPlayer()` 仍为 0 |
| 开局提示 | `+0xA39` | `cmp byte`，不是唯一判据 |
| 国家 data/size | `+0x310` / `+0x31C` | 循环 + 虚表 getter（约 `[9]`） |
| 国家 tag | `+0x08` | 虚表 `[20]`（`0x013F0DA0`）后 `mov ecx, [rax]`。`country+8` 等于下标 |
| GetArmies / 师列表 | RVA `0x006C2410`，国家 `+0x290` | 瑞士：20 个 **CArmy**，18 个有位置，其一圣加仑 11623 |
| 玩家国家指针 | 未钉扎 | Idler `+0xA08` 指向下标 29。BlackICE `00_countries.txt` 第 29 个 tag 是 SWI。`+0x4F0` 不是 `CCountry*`。`CCountry[8]` 的 `+0x145C` 瑞士战役 190 国全 0 |
| 师位置 | CArmy `+0x1F0` | 内联 `pUnit && pUnit->GetLocation()`（`0x01A5AA70`），对象虚表应为 CProvince |
| 省份 ID | province `+0xA4` | 内联 GetProvinceID（`0x006C33C0` 附近） |
| 组织度当前/最大 | CArmy `+0x428` / `*(+0x138)+0x280` | `[36]`/`[38]`。`[39]` 做 `current*100000/max`，禁止调用。脚本范围 0–1，UI 的 14 是显示换算 |
| HP 当前/最大 | CArmy `+0x420` / `*(+0x138)+0x288` | `[31]`/`[33]`。瑞士 166.9/166.9 |
| 师句柄 | CArmy `+0x18` / `+0x1C` | 瑞士圣加仑 `51/2476`，组织度变化时不变。`+0x1C0` 是用户指针，已废 |
| PeekMessageW | `user32.dll` IAT | 导入表按 DLL/函数名解析，不写死槽 RVA |

热路径：校验 GetPlayer 字节当指纹 → IAT 换 `PeekMessageW`（先调原函数再采样）→ 读单例 → 虚表确认 → 钉 SWI 槽的 `+0x290`。每 100 ms 最多一次。名字/组织度只对已确认的师探一次。禁止每帧扫对象或 190 国。不把游戏指针写出进程。`enters` 增加表示采样在跑，`seq` 增加表示写过快照。

不要：把 tag=0、下标 0、或「第一个有军队的国家」当成玩家；猜别的组织度偏移；在游戏线程扫师对象找 14/14 或英文名；调用 `0x021FFD50` 解析句柄。

## 已钉扎（写入入口）

玩家移动：构造 `CMoveCommand`（RVA `0x01350350`，0x88 字节）后虚表 `[9]`（edx=0）再 `[10]`。句柄写在命令 `+0x38`（内层抄 `CArmy+0x18`，`0x01223A10` → `0x002A6C50`）。

玩家取消：`CCancelMovementCommand`（大小 `0x48`，构造 `0x0134F9D0`，`rdx` 为 `CArmy*`，读 `+0x18`，r8=0）后虚表 `[9]` `0x01358190`、`[10]` `0x01355840`。玩家调用点 `0x0144E2D3`：解析句柄 → 栈上构造 → `[9]` edx=0 → `[10]`。

默认不发单。游戏内对照见验收文档。一种订单成功不能推断另一种可用。

`CMoveCommand` 其他调用点（不是产品闸）：

- `0x00D62020`、`0x01A2FAEE`、`0x01A2FC53`：栈/堆上构造后直接 `[9]`、`[10]`（战线/模拟）
- `0x014B8993`、`0x014B8E09`：玩家 UI

## 陆军对象关系（未当闸）

- `CCountry+0x228`：`CCountryAI*`（分配 `0xC28`，存点 `0x00705D58`）。
- `CCountryAI[14]` `0x002ACC80` 创建大臣：`+0xBC0` 外交、`+0xBC8` 陆军（`CAIMilitaryMinister`，大小 `0x7A0`）、`+0xBD0` 内政。
- 国家 `+0x223D` 陆军/外交/内政都检查，不是陆军专用闸，禁止写。
- 陆军大臣 `[14]` `0x010ABA70` 按 `+0x98` 遍历将军，对每个调虚表 `[14]`。
- `CAIGeneral[14]` `0x01074470`：`[this+0x10]==0` 则返回；`+0x08` 是 `CCountryAI*` 或 `CCountry*`。将军由大臣 `[12]` `0x010BB0D0` 创建（调用点 `0x010BBA9F`）。
- `CArmyGroup` 构造 `0x00BE0580` 的调用点在 `0x00EE10ED`、`0x00EEE687`（CFront 一侧），不是将军 tick。
- CFront 工厂 `0x00EEE3A0`（`rcx` 写入战线 `+0x18`）。集团军工厂 `0x00EE10B0`（`rcx` 为 CFront*）。
- `COrdersGroup+0x39` / `[12]` 能挡计划 AI，但计划组是以后要自己组建的战区/集团军对象。
- 另有 `lea rax, [rcx+0xA30]; ret` 在 `0x00DB61D0`。CArmy `[13]` 是 `mov rax, [rcx+0x340]; add rax, 0x60; ret`，含义未用。没有 `.?AVCUnitStats@@`、`CLandUnit`。`organisation_strength` 在 `0x01697CB0` 是命名属性虚调用。

## 废路

下列均已在本构建游戏内验证失败。禁止再当产品路径。细节对照见验收失败记录。

| 路径 | 现象 | 结论 |
|---|---|---|
| `GetPlayer` hook 当采样点 | 装上后 `seq=0`，函数没被走进 | 冷函数。改消息泵 + 单例 |
| 国家 `+0x145C` / Idler `+0x4F0` / 第一个有军队的国家 | 读到 tag=1 或空 | 不是玩家 |
| Idler `+0x2F8` / `+0xA08` 当任意玩家 | 指到 30 或把 6945 当成圣加仑 | 只作 SWI 槽提示，未钉玩家指针 |
| 全表 RTTI / 190 国扫师 / 每帧扫 `0x800` | 卡顿或 `armies=0` | 禁止游戏线程宽扫 |
| CArmy `+0x1C0` 当句柄 | `921052056/32759` = 用户指针 | 废 |
| 离开 11623 后改选瑞士境内最后一师 | 跟到 661 或 11590 | 必须先锁圣加仑句柄，id+generation 都对 |
| `CCountryAI+0x60`（`[15]` 写成 0） | `land_ai_off=7`，部队仍调动 | 只跳过 `Update`，不是发单闸 |
| 全局 `ai`（`.data` `0x03304C9C`） | 国策/生产/科研全停 | 废。加载后若为 0 则恢复为 1 |
| `CCountryAI+0xC20`（`IsCommandsAllowed`） | 部队仍调动 | `0x0029E670`：0 时 `jz +1; int3`，然后仍走命令 |
| 跳过 `0x00D61C30` | 部队又动 | 不是唯一发单口 |
| 拦 `CMoveCommand` `[9]/[10]` | 能停部队，但和自己发单冲突；当时还卡顿 | 不是抑制陆军 AI 的产品路径 |
| 写 `COrdersGroup+0x39` | 锁不到或焊死计划机构 | 废。以后要自己组建战区/集团军 |
| `CAIGeneral[14]` | `gens=0`，仍创建战区 | 德国 1936 没有将军可跳 |
| CFront/CArmyGroup 工厂 + 战线 `[2]` + 大臣 `[12]` | 仍创建战区、集团军群、集团军，部队仍移动 | 不是唯一组建/发单口，或认主要国家失败而放行 |
| 游戏线程 `VirtualQuery` 宽扫锁计划组 | `result=0 path=none`，卡死 | 禁止再扫 |
| 国家 `+0x223D` | — | 外交/内政一起看，禁止写 |

当前代码里若仍装着 org-create / general tick 钩子，只表示上次尝试还在仓库，不表示抑制成立。

## 未钉扎

1. 玩家/主要国家识别：`GetPlayer` 仍为 0；瑞士测试钉的是 tag 29。德国测试将用 tag 1。
2. 主要国家陆军 AI 的真实行动入口：上表闸均废。要找的是「不再新建战区/集团军、不再发移动单」的行动者，不是焊死计划机构。
3. 除已对照的移动/取消外，其他原生订单入口未取证。
4. 读档后对象失效未做。
5. CCountry 上除 `+0x290` 外的军队组织字段、CArmy `[13]` 的 `+0x340` 含义未用。

## 换构建时

1. 重新 identify，哈希或时间戳变了就整份作废。
2. 重跑 RTTI、单例 RIP、GetPlayer 字节、国家循环、GetLocation、GetProvinceID、IAT。
3. 任一指纹对不上：停用采集和发单，不套旧偏移。
4. 新采样点以游戏内 `enters`/`seq` 和 UI 对照为准，不以「hook 已安装」为准。
