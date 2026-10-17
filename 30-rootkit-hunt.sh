#!/usr/bin/env bash
source /opt/blueteam/lib.sh
require_root

REPORT="/var/log/blueteam_rootkit_$RUN_TS.log"
exec > >(tee -a "$REPORT") 2>&1
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT   # fixed /tmp paths are symlink-attackable

log "Kernel-level rootkit hunt started"
warn "If the kernel is compromised, everything below can be falsified."
warn "Treat a clean result as 'no evidence found', NOT 'confirmed clean'."

sec() { echo; echo "== $* =="; }

sec "Kernel taint bits (decoded)"
t="$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)"
echo "raw=$t"
declare -a TB=([0]=proprietary [1]=force-loaded [2]=unsafe-smp [3]=force-unloaded \
  [11]=firmware-workaround [12]=out-of-tree [13]=unsigned-module [14]=soft-lockout)
for i in "${!TB[@]}"; do (( (t >> i) & 1 )) && echo "  bit $i set: ${TB[$i]}"; done

sec "Kernel log: module/taint/hook messages"
if dmesg >/dev/null 2>&1; then
  dmesg | grep -iE 'taint|module verification|rootkit|ftrace|kprobe' | tail -50
else
  journalctl -k --no-pager 2>/dev/null | grep -iE 'taint|module|ftrace|kprobe' | tail -50
fi

sec "ftrace enabled/touched functions (ftrace-hooking rootkits)"
for f in /sys/kernel/tracing/enabled_functions /sys/kernel/debug/tracing/enabled_functions \
         /sys/kernel/tracing/touched_functions; do
  [[ -r "$f" ]] && { echo "--- $f ---"; head -100 "$f"; }
done

sec "k/uprobe events (should be empty on a clean box)"
for f in /sys/kernel/tracing/kprobe_events /sys/kernel/debug/tracing/kprobe_events \
         /sys/kernel/tracing/uprobe_events; do
  [[ -r "$f" ]] && { echo "--- $f ---"; cat "$f"; }
done

sec "eBPF programs / links / pinned objects (modern rootkits)"
if command -v bpftool >/dev/null 2>&1; then
  bpftool prog list 2>/dev/null; echo "---"; bpftool link list 2>/dev/null
else
  warn "bpftool not present — eBPF rootkits will be invisible here"
fi
find /sys/fs/bpf -type f 2>/dev/null || true

sec "Loadable modules: /proc/modules vs /sys/module (loadable only)"
cut -d' ' -f1 /proc/modules | sort > "$T/proc.mod"
for m in /sys/module/*; do [[ -e "$m/initstate" ]] && basename "$m"; done | sort > "$T/sys.mod"
echo "--- in /proc/modules, not in /sys/module ---"; comm -23 "$T/proc.mod" "$T/sys.mod"
echo "--- in /sys/module, not in /proc/modules ---"; comm -13 "$T/proc.mod" "$T/sys.mod"
echo "(self-hiding LKMs appear in neither — absence proves nothing)"

sec "vmalloc allocations matching known rootkit names"
grep -iE 'diamorphine|reptile|rootkit|hide|khook' /proc/vmallocinfo 2>/dev/null || echo "none"

sec "kallsyms symbol-NAME diff (KASLR makes addresses useless)"
if [[ -r "${TRUSTED_TOOLS:-}/kallsyms.names.$(uname -r)" ]]; then
  awk '{print $3}' /proc/kallsyms | sort -u > "$T/now.syms"
  diff "$T/now.syms" "${TRUSTED_TOOLS}/kallsyms.names.$(uname -r)" | head -50 || true
else
  warn "No kallsyms name baseline for $(uname -r). Skipping."
fi

# ---- userland (static tools if present, else LOUDLY untrusted) ----
PS="$(trusted_tool ps)";   PS_T=$TOOL_TRUSTED
SS="$(trusted_tool ss)";   SS_T=$TOOL_TRUSTED
[[ "$PS_T" == yes && "$SS_T" == yes ]] || \
  warn ">>> USERLAND CHECKS BELOW USE LOCAL (UNTRUSTED) TOOLS <<<"

sec "Hidden processes (brute-force /proc, confirm via Tgid)"
maxpid="$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)"
"$PS" -eL -o pid= 2>/dev/null | tr -d ' ' | sort -u > "$T/ps.pids"
for ((p=1; p<=maxpid; p++)); do
  [[ -r "/proc/$p/status" ]] || continue
  tgid="$(awk '/^Tgid:/{print $2}' "/proc/$p/status" 2>/dev/null)"
  [[ "$tgid" == "$p" ]] || continue
  grep -qx "$p" "$T/ps.pids" || echo "HIDDEN? pid=$p cmd=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)"
done

sec "Network: ss vs /proc/net/tcp (hook-one-path rootkits)"
"$SS" -tanp 2>/dev/null | awk 'NR>1{print $4}' | sort -u > "$T/ss.ports" || true
echo "ss listening/active endpoints:"; cat "$T/ss.ports"

sec "LD_PRELOAD in process maps (survives env clearing)"
for pid in /proc/[0-9]*; do
  grep -qaE '/(tmp|dev/shm)/|\(deleted\)' "$pid/maps" 2>/dev/null && \
    echo "PID ${pid##*/}: suspicious mapped lib"
done

sec "SUID/SGID files"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' 2>/dev/null || true

sec "File capabilities (cap_setuid on python etc. — missed by SUID scan)"
if command -v getcap >/dev/null 2>&1; then getcap -r / 2>/dev/null; else warn "getcap missing"; fi

sec "Deleted-but-running executables"
for pid in /proc/[0-9]*; do
  exe="$(readlink "$pid/exe" 2>/dev/null)"
  [[ "$exe" == *"(deleted)"* ]] && echo "PID ${pid##*/}: $exe"
done

log "Rootkit hunt report: $REPORT"
log "On confirmed kernel compromise: capture memory (LiME/AVML) off-box, then rebuild."
offbox_reminder "$REPORT"
