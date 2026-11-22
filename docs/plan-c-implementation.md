# 方案 C 实施规格：CoreX 式零-profile 架构（进行中）

日期：2026-11-22
状态：设计完成，开始实施。基于实机验证事实，非推测。

---

## 1. 目标

把 Snake 从"精确 build 号查表 + fake-cred endgame"改造成 CoreX 式"运行时推导 + shell endgame + 从管理器取 ksud"，实现：
- 新内核 OTA 后免人工重采 profile
- 单一 so 通吃（体积大降）
- 保留已验证的稳定性与零残留

## 2. 关键事实（决定设计）

- **F-C1**：Snake 已有 shell 模式（`argv[1]=="shell"`）写零真实 cred uid → uid=0 shell root，与 CoreX 默认 `write mode=zero` 同源。
- **F-C2**：Snake 已有 `run_late_load_script()`，从管理器取 ksud/module（`PYB110_KSUD`/`PYB110_MANAGER_PKG` 环境变量，`ksud late-load --kmi ... --package-name`）。**但只在 fake 模式调用**（2867/2883）。
- **F-C3**：shell/verify 模式拿到 uid=0 后直接 exec sh，**不做 late-load** ← 这是必须补的一环。
- **F-C4**：低21位过滤是鸡生蛋问题：`scan_timer_allocs` 用 `TIMER_SITE_LOW21` 过滤记录，要知道它才能过滤。CoreX 用投票解决：`[low21] made=64 candidates=1 best=0x1a652c votes=64`。
- **F-C5**：BTF 里没有 `root_user/init_user_ns/init_ucounts/init_groups/cred_jar`；只有 `selinux_state/task_struct/cred`。→ fake cred 的 6 符号无法靠 BTF 拿到，主路径必须走 shell endgame。
- **F-C6**：KASLR slide 在 PKU110 两次实测相同（`0xffffffd92cc00000`），但实际不依赖——CoreX 每次现场算。
- **F-C7**：`g_slide = site0 - STATIC_TIMER_SITE`，STATIC_TIMER_SITE 是 profile 里唯一的"函数名静态地址"，需要动态化。

## 3. 改造清单（逐点）

### R1. 低21位运行时投票（新增）
新增函数 `vote_call_site_low21(raw, n, pid, kind)`：
- 遍历 raw 中所有 `kmem_cache_alloc` 记录，按 `(site & 0x1fffff)` 聚类计数
- timer 类：用 `bytes_req == TIMER_REQ` 过滤（6.6 上是 0x108 或 0x100）
- task 类：用 `bytes_req == TASK_ALLOC_BYTES/PADDED` 过滤
- 取票数最多的 low21 作为结果（timer_trigger 制造大量同 site 分配，必然胜出）
- 结果存入全局 `g_timer_low21` / `g_copy_low21`
- 仿 CoreX 打印 `[low21] made=%d candidates=%d best=%#llx votes=%d`

### R2. 扫描函数改用动态 low21
- `scan_timer_allocs` 第 335 行：`!= TIMER_SITE_LOW21` → `!= g_timer_low21`
- `scan_task_allocs` 第 392 行：`!= COPY_PROCESS_LOW21` → `!= g_copy_low21`
- probe 里 1051-1053 行：期望值改 `g_timer_low21`（投票已保证一致，这里变成 sanity check）

### R3. STATIC_TIMER_SITE 动态化
`g_slide = site0 - STATIC_TIMER_SITE`（1057/2326）需要静态基准。方案：
- site0 是运行时 call_site 完整地址；其低21位 = g_timer_low21（动态）
- 内核 text 基址 = site0 & ~0x1fffff（因 call_site 在 text 段内，且函数入口在 2MB 内）
- 但 STATIC_TIMER_SITE = LINK_BASE + timer_low21，所以：
  `STATIC_TIMER_SITE ≈ LINK_BASE + g_timer_low21`（LINK_BASE=0xffffffc080000000 是固定链接基址，非 KASLR）
- 因此 `g_slide = site0 - (LINK_BASE + g_timer_low21)`
- 验证：PKU110 site0 低21=0x1a652c，LINK_BASE+g_timer_low21=0xffffffc0801a652c，与原 profile 的 timer_site 完全一致 ✓
- **结论：STATIC_TIMER_SITE 可由 LINK_BASE + 动态 low21 直接构造，无需查表**

### R4. profile_check 改为能力探测
- `auto_preflight()` 988 行：去掉 `profile_check(u.release)` 硬失败
- 改为：populate 一个全局"动态 profile"（`g_dyn_prof`），其 timer_site/timer_low21/copy_low21 用 R1/R3 运行时填；其余字段（fake cred 用的 6 符号）在 shell 路径不用，置 0
- 保留：如果 release 命中现有 profile，走快速路径（用已知值，跳过投票，更快更稳）；未命中则走投票路径
- 这样"已知机型不受影响，新机型自动适配"

### R5. shell 路径补 KSU late-load（关键缺口）
- 在 shell endgame（wait_child_main 的 shell/verify 分支，~2920）拿到 uid=0 后、exec sh 前，插入 late-load：
  - 用 uid=0 shell 身份调用 `ksud late-load --kmi <kmi> --allow-shell --package-name <pkg>`
  - ksud/pkg 来源：环境变量（沿用 PYB110_KSUD/PYB110_MANAGER_PKG），或 CoreX 式从已知路径探测
  - 检查 `/proc/modules` 确认 KSU_LOADED
- 这样 shell 路径 = CoreX 默认路径（写零 cred + late-load from manager）

### R6. 保持兼容与回退
- 不删除任何现有 profile 表
- `--auto`（app 调用）默认走 R4 的动态路径（能力探测），旧机型仍可用 profile 快路径
- fake 模式原样保留（已知机型仍可用），只是不再是唯一 root 路径

## 4. 实施顺序（每步可编译、可回退）

1. R1+R2：投票函数 + 扫描改用动态 low21（先在 probe 模式验证投票值 == 已知 profile）
2. R3：STATIC_TIMER_SITE 动态构造
3. R4：profile_check 能力探测
4. R5：shell 路径补 late-load
5. 编译、单机型验证（PKU110）、SHA 核对、暂不发布

## 5. 验证标准

- probe 模式输出 `[low21] best=0x1a652c`（与已知 profile 一致）
- shell 模式能拿 uid=0 且 `ROOT_SHELL_OK`
- late-load 后 `/proc/modules` 有 kernelsu
- 零 R 态残留进程（复用 v1.4 验证流程）
- 无 root 状态重启后能重新走通

## 6. 风险与边界

- 投票依赖 timer_trigger 制造足够多的同 site 分配；若某内核 call_site 分散，投票可能失准 → 保留 profile 快路径兜底
- TIMER_REQ/TASK_ALLOC 等 bytes_req 常量仍是编译期（按内核分支）；跨大版本内核可能不同 → 首版只保证 6.6 系列，其他系列后续用 BTF sizeof 动态化
- shell 路径的 late-load 在 uid=0 但 SELinux=shell 下执行，需 `--allow-shell`（Snake 已有此参数）

---

## 实施进度（2026-11-22 16:30）

### 已完成的代码改动
- R1 `vote_call_site_low21()`：tracefs 按 low21 聚类投票（want=1 timer / want=2 task）
- R2 `scan_timer_allocs`/`scan_task_allocs` 改用 `g_timer_low21`/`g_copy_low21`；copy low21=0 时降级为 bytes_req 过滤
- R3 `timer_static_site()` = `KERNEL_LINK_BASE | g_timer_low21`，替代 STATIC_TIMER_SITE
- R4 `profile_check` 不匹配时不拒绝，指向 `g_dynamic_prof`；`SNAKE_FORCE_DYNAMIC=1` 测试钩子
- R5 动态模式强制 fake→shell endgame（mode=0 write-zero）；shell endgame 注入 late-load（从 env 的 ksud/pkg）；rooted 判据按 uid+setuid；输出 PLANT_CRED_OK 供 rust 层判定
- 全部改动仅 `exploit/src/plant_core.inc` + `exploit/src/K66118_plant.c`，用 `#if defined(PKJ110_66118)` 守卫，其他内核 so 不受影响

### 只读验证结果（独立 ELF 直跑）
- 已知 profile（probe）：PROBE_OK，逐位正常，回退路径无影响
- 动态 probe（SNAKE_FORCE_DYNAMIC=1）：
  - `[low21] want=1 made=129 candidates=2 best=0x1a652c votes=128` —— 与 CoreX `best=0x1a652c` 完全一致
  - `static=0xffffffc0801a652c` —— 与 profile 的 timer_site 逐位一致
  - `PROBE_SLIDE=0x18acc00000 aligned=1`，cred/task 扫描成功（copy low21=0 时降级仍抓到 task）
  - PROBE_OK
- 动态 `--auto` 端到端：当前系统已 root/KSU 在运行，`calibrate_base` 因 page 事件噪声连续失败（count=0），属污染环境，非代码问题（probe 同算法 count=432 成功）。需在干净重启后经 App 完整验证。

### 待办
1. 替换 jniLibs/libk66118.so、升版本号
2. 构建 APK、USB/无线安装
3. 用户重启手机 → 用 App 干净越狱 → 验证 root/late-load/零残留
4. 通过后再决定发布；暂不发布

---

## 实施结果（2026-11-22 16:55，诚实的失败结论）

### 成功的部分（零-profile 核心机制，全部实机验证）
- 运行时 low21 投票 `best=0x1a652c votes=512`，与 CoreX/已知 profile 逐位一致
- 动态构造 static=`0xffffffc0801a652c`，slide 对齐
- 修复 calibrate_base 投票时序 bug（--auto 全流程 count=0 → 482）
- write mode=zero 拿 uid=0、PLANT_CRED_OK、SHELL_MODE=1
- 修复 late-load 假成功 bug：新增 late_load_shell_v2() 实现 CoreX 两阶段 CLASSIC→poll→FINA→poll

### 失败的部分（结构性障碍，方案 C 真架构不成立）
干净重启后端到端测试：CLASSIC 与 FINA 两种 ksud late-load **都返回 0 但 KSU 模块未加载**（KSU_MISSING，su 不可用）。
- shell 路径：`uid=0 euid=2000 resuid=0/0/2000`（shell domain）
- fake 路径：`uid=0 euid=0 resuid=0/0/0` → KSU Live
- `--magica`（真正加载所需）报 "must be run as root"，shell-domain euid=2000 不满足

**根因判断**：CoreX 默认 shell 路径只提供 uid=0 shell root（其实机 probe 也只到 ROOT_SHELL_OK，未加载 KSU 模块）。它并不在 shell 路径自加载 KSU。KSU late-load 需要 fake cred 的 fullcap+完整 uid=0，这正是 Snake fake 路径做的。此前"CoreX 零 profile 且能装 KSU"的假设不成立——它的 KSU 必然走另一条路径（fake 分支或 manager app 自身）。

### 结论与建议
- 方案 C「放弃 fake cred 改 shell 路径」**不可行**：会失去 KSU 加载能力，对依赖 KSU 模块（lsposed/zygisksu/su）的用户是倒退。
- 方案 C 中可保留的**有效成果**：运行时 low21 投票（去掉 timer_site 静态依赖）+ calibrate_base 修复。这些可并入方案 A/B，让已知机型的 profile 也能自校准 timer_site，减少 OTA 重采工作量。
- 建议回退到方案 A（保留 fake-cred + KSU 加载能力，只把 timer_site 运行时化），或维持现状。
- **设备 root 已用 v1.4 fake 模式恢复**（uid=0, KSU Live）。实验 APK 均未发布。

### 实验产物（均未发布）
- dist/Snake-zeroprofile-test.apk / Snake-forcedyn-test.apk / Snake-forcedyn-v2.apk
- jniLibs 已恢复 v1.4 so（e5a26b77...）

### 补充（16:59）：CoreX KSU 加载机制再核查
用户纠偏"CoreX 也支持这么多 root 管理器"——正确。反编译确认 CoreX 支持 KernelSU / KernelSU Next / SukiSU Ultra / SukiSU Nova / BakaSU / FinaSU 等（包名用 n2.a([B) 字节混淆，a2.1.smali）。管理器脚本用 --pkg/--ksud/--module/--pairs/--expect 传参，probe_ksud 校验版本血缘。
关键实测：CoreX 独立 ELF（/data/local/tmp/corex-probe）单独跑，无论带不带参数，**默认只到 ROOT_SHELL_OK、不加载 KSU 模块**（PHASE=calibrate ktext=0，euid=2000 shell）。且它有 Shizuku 权限（moe.shizuku.manager.permission.API_V23）。
**判断**：CoreX 的 KSU 模块加载走 app 层（Shizuku 提供的高权限句柄），不在 native exploit 的默认 shell 路径里。我此前用环境变量（PYB110_*，Snake 的机制）裸跑 CoreX so 的方式本就不对——CoreX 认命令行参数不是环境变量。要在 Snake 复刻这套 KSU 加载，需要集成 Shizuku + 管理器识别/校验，工程量与风险都很高。

**当前状态**：设备 root 已恢复（uid=0, KSU Live）。方案 C 的核心地址推导已验证可用，但"shell 路径自加载 KSU"这条路未打通。是否继续取决于用户：回退方案 A（保留 fake+KSU，仅 timer_site 运行时化）还是继续攻 Shizuku 集成。

### 重大修正（17:04，跑 CoreX app 后的决定性发现）
实机启动 CoreX app 截图显示其第4阶段明确为「fake cred · selinux · uid」——**CoreX 也用 fake cred，从未绕过它**。此前"CoreX 用 shell 路径绕过 fake cred"的判断完全错误。通道是 Shizuku / 无线调试（用于提权读符号），且当前未开启，故 app 实际没跑完（进度0%）。

**真正的机制差异（strings 交叉验证）**：
- Snake：`build_payload()` 从零逐字段构造 fake cred，需要 root_user/init_user_ns/init_ucounts/init_groups 等全局对象的**地址** → BTF 无这些符号 → 卡死。
- CoreX：`[btf] cred size / task_struct size / task_struct.cred off / cred.uid off` + `memcpy` + `cred_jar` → **复制真实 cred 再改 uid/gid/selinux/cap**，只需结构大小与成员偏移（BTF 提供，root 前可读），无需任何全局对象地址。

**这才是 CoreX 零-profile + fake cred + KSU 全能力的完整答案**，且不需要 Shizuku 参与 exploit（通道仅用于其它提权步骤）。

**修正后的方案 C 实现路径（可行，待实施）**：
1. probeless：用运行时投票得到 timer_site/copy low21（已验证）
2. leak_cred 拿到真实 cred 地址 R（已有）
3. **新增 BTF 解析**：读 /sys/kernel/btf/vmlinux（持权后可读，F7），解析 struct cred 的 size 与 uid/gid/cap/security 成员偏移、task_struct.cred 偏移
4. 从 R memcpy 整个 cred 到 payload，改 uid/gid=0、security blob sid、capabilities=FULLCAP
5. 写 task->cred 指向新 cred（task_struct.cred off 来自 BTF）
6. 保留现有 fake endgame 的 late-load（KSU 加载不变）

相比旧方案：不再需要 6 个静态地址；KSU 能力完整保留；体积可逐步合并 so。风险：BTF 解析器实现 + cred 写入时序需实机验证。

**结论**：方案 C 并非不可行，只是我先前走错了分支（shell 路径）。正确分支是「copy-real-cred + BTF」，值得实施。待用户确认。

---

## 最终交付：收敛版自校准（17:15，采纳用户"收敛交付"决策）

### 回退与重建
- 全部回退 shell 路径实验（fake->shell 强制、两阶段 late-load、SHELL_MODE/PLANT_CRED_OK shell 分支、FORCE_DYNAMIC 钩子），删除 3 个实验 APK。
- 从 v1.4 干净基线重新施加**最小验证通过**的改动（107 行）：
  1. `vote_timer_low21()`：从 tracefs 512-timer burst 投票 call_site low21（CoreX `[low21]` 同源机制）
  2. `scan_timer_allocs` 用投票值（`g_low21_voted` 时覆盖 profile 的 TIMER_SITE_LOW21）
  3. `timer_static_site()` = LINK_BASE | voted_low21，两处 slide 计算改用它
  4. `profile_check` 增加 series-fallback：未知 build 若属已知系列（`6.6.118-android15`），借用同系列 profile 的 6 个数据符号 + 投票 call_site；打印 WARNING 提示可能陈旧

### 已验证（独立 ELF probe，实机）
- 已知 build：PROFILE 精确匹配、`[low21] best=0x1a652c votes=512`、PROBE_SLIDE aligned、PROBE_OK —— 零回归
- 投票值与 profile 逐位一致
- 无 shell 路径残留，KSU/fake-cred 链路完全未动

### 边界（诚实记录）
- fallback **仅限同系列**（6.6.118-android15）；跨大版本（如 6.12）仍不支持，需新增 profile
- 借用的 6 个数据符号在 OTA 大改时可能失效 → 此时仍需人工重采 profile（已打印 WARNING）
- 因此本版把"OTA 后需重采的字段"从 9 个减到最多 6 个，call_site 类自动；不是万能零 profile

### 未验证
- series-fallback 分支本身（当前 build 已知，uname 无法伪造触发）——逻辑为简单 strncmp，代码审查通过，待真实 OTA 或测试钩子验证
