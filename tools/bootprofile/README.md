# Profile 自动采集

OTA 换内核 build 后，Snake exploit 需要重新采集一组 KASLR 无关的静态地址
（见 `exploit/src/K66118_plant.c`）。本目录把这条流程固化成一条命令，
取代手工 grep 九个符号 + 试错调用点偏移。

## 用法

设备先取得**临时 root**（例如用 TimerRoot 越一次，无需重启），然后：

```sh
NDK=~/Library/Android/sdk/ndk/28.2.13676358 python3 tools/bootprofile/gen_profile.py
```

脚本会自动：
1. `kptr_restrict=0` 后从 `/proc/kallsyms` 读 `_text` + 六个数据符号
2. 用 NDK 编译两个小 helper（timer / fork），推到设备触发分配
3. 从 tracefs `kmem_cache_alloc` 按**符号名**抓 `do_timer_create` 和
   `copy_process` 的调用点（不靠 bytes_req，避免同类大小分配误命中，
   也不受 `posix_timer_add → do_timer_create` 这类改名影响）
4. 按 `静态 = 运行时 - (_text - 0xffffffc080000000)` 折算，直接打印可粘贴的
   `struct k66118_profile` 条目

输出已在本机 6.6.118 / `abogki552867473` 上验证：与现有 profile 逐位一致，
且在不同 KASLR slide 下结果稳定。

## 离线模式

只有 `kallsyms.txt` 没有 live 设备时：

```sh
python3 gen_profile.py --from-kallsyms kallsyms.txt
```

会输出六个数据符号，并把两个调用点标成 TODO（它们必须从 trace 现场采）。

## 关于纯 boot.img 解析

`kallsyms_decode.py` 能从 boot.img 的未压缩 arm64 Image 里解出全部 110538
个符号**名**（token 表 → names 表，已在上述内核验证），但地址表的定位
（Linux 6.x `kallsyms_seqs_of_names` / BASE_RELATIVE 编码）尚未完成，
因此纯离线"给个固件就生成 profile"暂时不可用。当前可靠路径是先取一次
临时 root 用 `gen_profile.py`。
