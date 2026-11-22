# Snake 运行时自校准移植方案（供审阅，未实施）

日期：2026-11-22
状态：技术验证 + CoreX 实机验证均完成，等待方案确认。本文档不修改任何代码。

> **更新（15:58 实机验证后）**：原"推断"章节的 I1/I2 已在 PKU110 上通过实机运行 CoreX 独立 ELF 坐实——CoreX 默认走"写零真实 cred 的 uid/gid"路径，不构造 fake cred，完全不需要那 6 个全局符号；timer_site 低21位靠 tracefs 运行时投票算出。详见第 2 节末尾的"实机验证结果"和第 8 节。这使方案 A 的可行性大幅提升。

---

## 0. 结论先行

CoreX 的"机型支持快 + 体积小 + 无残留"三个优点，根源是同一个：**它不靠硬编码静态地址，而是在设备上运行时推导**。Snake 目前只有一半能力已经运行时化（slide、线性映射基址、tracefs event id），剩下的关键一环——profile 里的 9 个静态地址——仍是每次 OTA 都要人工重采的瓶颈。

移植可行，但要分两层看：

- **拿 root 前**（普通权限）：只能用 tracefs。好消息是 tracefs 在当前机型上普通 shell 可读，且 Snake 已经用它算出了 slide 和 base。这一层足以让"去掉 release 精确匹配"成为可能。
- **拿 root 后**（持权）：可以读 BTF，解析 cred/task_struct 的结构偏移。这一层决定能否把 fake cred 路径里那 6 个全局符号也动态化。

换句话说：**自校准不是"有或无"，而是一个分阶段的替换清单**。能替换多少，取决于我们愿意接受多大的改动面。

---

## 1. 事实基础（已验证，非推断）

| # | 事实 | 来源 | 验证方式 |
|---|------|------|----------|
| F1 | CoreX 与 Snake 用同一套 timer/slab UAF + fake cred + KSU late-load 漏洞 | CoreX `libcorex.so` 字符串：`fake cred page held; reboot to clean`、`kmem_cache_alloc`、`posix_timers_cache`、`me.weishu.kernelsu` | 逆向 strings，与 Snake/TimerRoot 同源比对 |
| F2 | CoreX 全程不读 `/proc/kallsyms` | so 中无该字符串、无 kptr_restrict | strings 检索为空 |
| F3 | CoreX 用 BTF 解析结构偏移 | so 中 `[btf] cred size/cred.uid off/task_struct size/task_struct.cred off`、`/sys/kernel/btf/vmlinux(.bz2)` | strings |
| F4 | CoreX 运行时算内核 text base 和线性映射 base | `[+] fake cred A=%#llx ktext=%#llx selinux_state=%#llx`、`PHASE=calibrate base=%#llx ktext=%#llx`、`[base]`、`[low21] ... (no trace)` | strings |
| F5 | CoreX 仍会 hold 失败进程，但用 park 而非忙等 | `burst missed; holding zombie`、`parking without reap (zombie held)`、`root shell finished; failed-plant zombies are held` | strings；印证 v1.4 修复方向 |
| F6 | 设备有完整 vmlinux BTF | `/sys/kernel/btf/vmlinux` 6.1MB，magic `9f eb 01 00`，`CONFIG_DEBUG_INFO_BTF=y` | PKU110 实测（root） |
| F7 | 普通 shell（uid=2000）读 BTF 被 SELinux 拒绝 | `head /sys/kernel/btf/vmlinux` → Permission denied；属主 root，shell domain 无权限 | PKU110 实测（无 root） |
| F8 | 普通 shell 可读 tracefs | `/sys/kernel/tracing` 属组 `readtracefs`，shell 属该组；`tracing_on` 可读 | PKU110 实测（无 root） |
| F9 | Snake 的 slide 已运行时计算 | `g_slide = site0 - STATIC_TIMER_SITE`（1057/2326 行），`site0` 来自 tracefs call_site | 源码 |
| F10 | Snake 的线性映射 base 已运行时计算 | `calibrate_base()` / `plant_base()`，tracefs page 投票 | 源码 |
| F11 | Snake profile 的 9 个静态地址中，6 个是全局数据符号，写入 fake cred | `ROOT_USER_STATIC + g_slide` 等（2388-2396 行） | 源码 |
| F12 | 结构偏移在源码里是编译期宏，按内核分支二选一 | `CRED_UID_OFF=0x8`、`OFF_TASK_CRED=0x820/0x900`、`CRED_ALLOC=0xc0`、`TASK_ALLOC_BYTES=0x12c0/0x1440`（87-104 行） | 源码 |
| F13 | `gen_profile.py` 已实现 tracefs 按符号名抓 timer/copy 的 call_site | `collect_call_site()`，`call_site=do_timer_create+` / `copy_process+` | 上一轮 B 方案成果，实机验证过 |
| F14 | slide 必须 2MB 对齐 | `g_slide & 0x1fffff == 0` 否则 probe 失败 | 源码 1058-1060 行 |

---

## 2. 推断 + 实机验证结果

### 逆向推断（事前）

- **I1**：CoreX 大概率走"改真实 cred 的 uid/gid 字段"或"复用真实 cred 对象"的路径，因此**不需要** Snake 那 6 个全局符号地址。依据：so 中无 `root_user/init_user_ns/init_ucounts/init_groups` 等符号名，但有 `fake uid fix failed`、`cred writes landed`、`child report uid/euid/resuid`。这是移植能否简化的最大分叉点。
- **I2**：CoreX 的 BTF 解析在持权后进行（F7 决定了拿 root 前读不到 BTF），用于精确定位结构偏移和 selinux_state，而非用于初始突破。
- **I3**：CoreX so 内嵌 3 个 build 字符串（abogki500782043 / 537459655 / 552867473），说明它是"自校准为主 + 已知机型 profile 兜底/加速"，不是纯零常量。

### 实机验证结果（2026-11-22 15:58，PKU110，连跑两次一致）

安装 CoreX 3.7.10 后，将其 `libcorex.so` 作为独立 ELF push 到 `/data/local/tmp/corex-probe` 直接运行（它自带完整流程，无需 app）。**I1 已被直接观测坐实**：

| 日志原文 | 证明什么 |
|---|---|
| `[low21] made=64 candidates=1 best=0x1a652c votes=64` | timer_site 低21位（=Snake 写死的 `TIMER_SITE_LOW21`）是**运行时 tracefs 投票算出**，非查表 |
| `[base] made=512 best=0xffffff7f80000000`、`PHASE=calibrate base=... ktext=0` | 线性映射 base 运行时校准；ktext 本次为 0（默认路径非必需） |
| `[+] plant1 write mode=zero target=cred+0x8` | **写零真实 cred 的 uid/gid**（Snake 的 default/shell 路径），不构造 fake cred |
| `[child] setuid(0)=0 ... u:r:shell:s0 ROOT_SHELL_OK` | 拿到 uid=0 的 shell-domain root |
| 全程无任何全局符号写入 | **确认不需要** root_user/init_user_ns/init_ucounts/init_groups/selinux_state/panic_on_warn |
| 两次 `slide=0xffffffd92cc00000` 相同、cred 地址每次不同 | KASLR slide 实际不随机（解释 Snake 静态地址为何"能用"），但 CoreX 不依赖此点，每次现场推导 |

**两次均成功、零残留**（无 R 态空转、无遗留 holder）。附带观察：`errno=17(EEXIST)` 出现在 event enable，但 hits 正常，可忽略。

**对方案的影响**：I1 坐实意味着——Snake 根本不必移植 CoreX 的 fake cred/BTF 那套（方案 C 大幅简化甚至无需）；只需复用 Snake 已有的 default/shell 路径 + 把 timer_site/timer_low21 改成运行时推导（方案 A），即可去掉 release 精确匹配、实现自校准。I2 仍为推断（默认路径没触发 fake，未观测到 BTF 解析），但已不影响主线。

---

## 3. 现状：Snake 里"已运行时化" vs "仍写死"

```
profile 9 字段
├─ timer_site        ← 写死（用来把 site0 还原成静态偏移 → 算 slide）
├─ timer_low21       ← 写死（校验 site0 低 21 位）
├─ copy_low21        ← 写死（校验 cred 泄漏的 call_site）
├─ selinux_state     ← 写死（写入 fake cred）
├─ panic_on_warn     ← 写死（KSU late-load 用）
├─ root_user         ← 写死（写入 fake cred）
├─ init_user_ns      ← 写死（写入 fake cred）
├─ init_ucounts      ← 写死（写入 fake cred）
└─ init_groups       ← 写死（写入 fake cred）

已经运行时化（不需 profile）：
  · g_slide           ← site0 - STATIC_TIMER_SITE
  · g_base            ← calibrate_base() tracefs 投票
  · tracefs event id  ← 运行时发现
  · 结构偏移           ← 编译期宏，按内核分支二选一（半写死）
```

瓶颈清晰：**去掉 release 精确匹配的门槛，只需解决"timer_site 怎么不写死"；但要让 fake cred 路径完全免 profile，还要解决 6 个数据符号。**

---

## 4. 移植路线（三个方案，按改动面从小到大）

### 方案 A：轻量自校准 —— 只去掉 release 精确匹配（推荐先做）

**目标**：新内核 OTA 后，Snake 不再因 `profile_check(release)` 失败而直接拒绝，而是现场从 tracefs 推导 timer_site，自动跑起来。

**做法**（已按 CoreX 实机结果修正，比原计划更简单）：
1. 保留 `gen_profile.py` 的 `collect_call_site()` 思路，把它移植进 C：在 `auto_preflight()` 之后，用 timer_trigger 逻辑抓 `kmem_cache_alloc` 的 `do_timer_create+0x..` call_site。
2. **timer_low21 直接取投票结果**：CoreX 实测 `[low21] ... best=0x1a652c votes=64`——低21位本身就是现场投票出的稳定值（=Snake 的 `TIMER_SITE_LOW21`），无需知道 text base。这消除了原 R1 的核心难点。
3. **copy_low21 同理**：从 `copy_process` 的 call_site 现场抓低21位（CoreX 的 `site_low=0xe579c` 对应 cred 泄漏点，Snake 现用 `COPY_PROCESS_LOW21`）。
4. ** cred 写入改为 zero 模式**：既然 I1 坐实 CoreX 默认只写零真实 cred 的 uid/gid（cred+0x8）就能拿 root，方案 A 应复用 Snake 已有的 `default/shell` 路径，**完全绕开 6 个全局符号**——不需要为它们做运行时解析。
5. `profile_check` 从"精确 strcmp"改为"能力探测"：tracefs 可读 + call_site 能抓到 → 支持；否则 → 不支持。保留现有 profile 作为已知机型的快速路径。
6. `g_slide` 保留现有 `site0 - STATIC_TIMER_SITE` 算法——但 STATIC_TIMER_SITE 改为由运行时 call_site 直接构造（因为 cred 写入用运行时地址，slide 只用于 late-load 等次要环节）。

**收益**：机型支持从"每次 OTA 人工重采"变成"自动"，且无需触碰 fake cred。风险显著低于原估。
**风险**：R1 降级（text base 已证实默认路径不需要）；主要剩 R3（时序）和 R2（若将来要支持 fake 路径才需要 BTF）。

### 方案 B：结构偏移 BTF 化 —— 一个 so 通吃多个内核

**目标**：把 F12 的编译期宏（`OFF_TASK_CRED`、`CRED_ALLOC`、`TASK_ALLOC` 等）改成运行时从 BTF 读，仿照 CoreX 的 `[btf] ...`。这样 8 个 so 可以合并成 1 个，体积从 25MB 大幅下降。

**做法**：
1. 实现一个轻量 BTF 解析器（C 语言，读 `/sys/kernel/btf/vmlinux`，解析 BTF header + type section，按名字查 `struct cred` / `task_struct` 及其成员偏移）。
   - 持权后可读（F7），所以解析放在拿 root 之后的阶段。
   - 拿 root 前仍用编译期宏（这些偏移在同系列内核间通常一致）。
2. 用 BTF 结果校验/覆盖编译期宏，作为一致性检查和跨系列支持。
3. 逐步合并 so 变体。

**收益**：体积下降、跨系列支持。
**风险**：BTF 解析器本身有实现工作量；只在持权后可用，所以对"首次突破"帮助有限。

### 方案 C：完整复刻 CoreX 路径 —— 消除 fake cred 的 6 个全局符号

**目标**：仿 I1，改成"改真实 cred uid"路径，彻底不依赖 `root_user/init_user_ns/...`，实现真正的零 profile。

**做法**：
1. 先按第 6 节坐实 I1，搞清 CoreX 到底怎么写 cred。
2. 在 Snake 里实现同样的 cred 处理。
3. 全程用 tracefs（拿 root 前）+ BTF（持权后）推导所有地址。

**收益**：真正的单 so、零 profile、OTA 免维护。
**风险**：改动最大，触及 exploit 核心，需要充分实机验证；CoreX 的实现细节尚未完全逆向。

---

## 5. 风险清单

| ID | 风险 | 等级 | 说明 / 缓解 |
|----|------|------|-------------|
| R1 | ~~text base 无法在拿 root 前从 tracefs 直接得到~~ **已降级** | ~~高~~ → 低 | 实机验证：CoreX 默认路径 `ktext=0` 仍成功，timer_low21 靠 tracefs 投票直接得出，不需要 text base。仅 fake 路径才可能需要。 |
| R2 | 普通权限读不到 BTF（F7） | 高 | 决定了 BTF 只能用于持权后增强，不能用于首次突破。方案 B/C 的 BTF 部分必须放在拿 root 后。默认路径不需要 BTF，故不影响 A。 |
| R3 | 自校准引入竞态/时序变化，破坏现有稳定的 root 流程 | 中高 | 现有流程已在 PKU110 稳定验证。缓解：自校准作为**新增路径**，旧路径保留可回退；逐机型灰度。 |
| ~~R4~~ | ~~CoreX cred 路径推断可能错误~~ **已消除** | — | 实机坐实：CoreX 默认写零真实 cred uid/gid，不用 6 个全局符号。 |
| R5 | 合并 so 后，不同内核结构偏移差异处理不当 | 中 | F12 显示偏移按分支不同（0x820/0x900 等）。缓解：BTF 校验，不盲目合并。 |
| R6 | 每次改 exploit 都需重新走"重启 + 重新越狱"才能验证 | 中 | 验证成本高。缓解：复用 v1.4 的验证流程（已建立）。 |

---

## 6. 下一步建议（按顺序）

1. ~~**坐实 I1/I2**~~ **已完成**（15:58 实机验证）：CoreX 默认写零真实 cred、绕开 6 个全局符号、timer_low21 运行时投票得出、零残留。见第 8 节。
2. **实施前先定范围**：A/B/C 三选一。建议仍是 **A 先行**，且因 I1 坐实，A 的范围进一步缩小、风险更低——只需把 timer_site/timer_low21 运行时化 + 复用 Snake 现有 default/shell 路径，不动 fake cred。
3. **方案 A 落地后**：在 PKU110 上验证"去掉 release 匹配 + 运行时推 timer_site"能成功 root 且无残留（复用 v1.4 验证流程）。
4. **再评估 B/C**：根据 A 的结果决定是否继续做体积（B）和 fake 路径支持（C）。因默认路径已够用，C 的优先级最低。

---

## 7. 我不打算做的事

- 不复制 CoreX 的二进制或代码（逆向仅用于理解方法）。
- 不在没有方案确认前修改 exploit 源码。
- 不删除或改动现有已验证的 profile 表和 v1.4 产物。
- 不把 BTF 解析放在拿 root 前（F7 已证明不可行）。

---

## 8. CoreX 实机验证记录（2026-11-22 15:58）

**方法**：安装 CoreX 3.7.10（`com.corex.app`）到 PKU110，将其 `libcorex.so` 作为独立 ELF push 到 `/data/local/tmp/corex-probe` 直接运行，连跑两次。CoreX 与已装的 KSU 官方管理器、Snake 共存无冲突。

**完整日志（第二次，第一次除 event enable 的 errno=17 外一致）**：
```
[+] pid=10316 cpu=2
PHASE=preflight
[i] ARM made=16 raw=8192 hits=16
[ids] page_alloc=277 page_free=275 pairs=1029
[low21] made=64 candidates=1 best=0x1a652c votes=64
[base] made=512 best=0xffffff7f80000000 count=406
PHASE=calibrate base=0xffffff7f80000000 ktext=0
[cred] attempt=0 child=10317 R=... site_low=0xe579c recs=1 task=... 
PHASE=leak
[+] plant attempt 1/3
[+] plant1 V=... slide=0xffffffd92cc00000 recs=4096 slab_own=31/32
[+] plant1 free_seen=0 burst hit=1 after 5ms
[+] plant1 write mode=zero target=cred+0x8
[+] cred writes landed, waking child
CHILD_REPORT uid=0 euid=2000
u:r:shell:s0 ROOT_SHELL_OK
[+] done
```

**结论**：
- I1 坐实（zero 模式、无全局符号）、R1 降级（ktext=0 仍成功）、timer_low21 现场投票。
- 两次零残留、无 R 态空转进程。
- slide 值两次相同 → KASLR slide 实际不随机；但 CoreX 不依赖此点。

**遗留**：CoreX app 已安装、probe 二进制留在 `/data/local/tmp/corex-probe`（只读观测用，未清理系统）。

---

附：证据原始材料
- CoreX APK：`/Users/ranmuhan/Desktop/CoreX-3.7.10-release.apk.1`，SHA256 `1e16b73288d6a8e7a37a5a6b3bfb8a62399a13d9accb8aa2804b8340ed68ea6c`
- 逆向临时目录：`/tmp/corex-analysis/`（提取的 so、dex、strings）
- 实机日志：`/tmp/corex-probe-run2.txt`
- 设备实测：PKU110，内核 `6.6.118-android15-8-gb1422e39c313-abogki552867473-4k`，2026-11-22
