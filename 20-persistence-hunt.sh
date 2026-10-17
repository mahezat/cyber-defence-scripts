#!/usr/bin/env bash
source /opt/blueteam/lib.sh
require_root
detect_pkg_mgr

REPORT="/var/log/blueteam_persistence_$RUN_TS.log"
exec > >(tee -a "$REPORT") 2>&1

log "Persistence hunt started (DRY_RUN=$DRY_RUN)"

sec() { echo; echo "== $* =="; }

sec "UID 0 accounts (only root should appear)"
awk -F: '$3==0 {print}' /etc/passwd

sec "Accounts with login shells below UID 1000 (excl. root)"
awk -F: '$3>0 && $3<1000 && $7!~/(nologin|false)/ {print}' /etc/passwd

sec "Empty password hashes"
awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null || true

sec "Sudoers (#includedir is a real directive, not a comment)"
grep -RnvE '^\s*(#[^i]|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null || true

sec "Cron (system + per-user), with contents"
for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
         /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
  [[ -e "$d" ]] || continue
  echo "--- $d ---"
  find "$d" -maxdepth 2 -type f -printf '%M %u %p\n' -exec cat {} \; 2>/dev/null
done

sec "at jobs"
ls -la /var/spool/at /var/spool/cron/atjobs 2>/dev/null || true

sec "Systemd unit FILES not owned by any package"
for base in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system \
            /etc/systemd/user /usr/lib/systemd/user; do
  [[ -d "$base" ]] || continue
  while IFS= read -r -d '' u; do
    pkg_owns "$u" || echo "UNOWNED: $u"
  done < <(find "$base" -type f -print0 2>/dev/null)
done
for h in /root /home/*; do
  u="$h/.config/systemd/user"
  [[ -d "$u" ]] && { echo "--- user units in $u ---"; ls -la "$u"; }
done

sec "Systemd drop-in overrides (*.d/*.conf — classic ExecStartPre hook)"
find /etc/systemd/system -type d -name '*.d' 2>/dev/null | while read -r dd; do
  echo "--- $dd ---"; grep -RniE 'ExecStart|ExecStartPre|ExecStopPost' "$dd" 2>/dev/null
done

sec "Enabled timers"
systemctl list-timers --all --no-pager 2>/dev/null

sec "Suspicious payload patterns in unit files"
grep -RniE 'curl|wget|base64|/dev/tcp|\bpython|\bperl|\bnc\b|\bncat\b|\bsocat\b' \
  /etc/systemd/system /usr/lib/systemd/system /run/systemd/system 2>/dev/null

sec "Init / rc.local (read it, check exec bit)"
ls -la /etc/init.d /etc/rc.d /etc/rc.local 2>/dev/null || true
[[ -e /etc/rc.local ]] && { echo "--- /etc/rc.local ---"; cat /etc/rc.local; }

sec "Shell profiles (all homes, not just /home)"
while IFS=: read -r user _ uid _ _ home shell; do
  [[ -d "$home" ]] || continue
  for rc in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_login"; do
    [[ -f "$rc" ]] || continue
    grep -HniE 'curl|wget|base64|\bpython|\bperl|\bnc\b|/dev/tcp|LD_PRELOAD' "$rc" 2>/dev/null
  done
done < <(getent passwd)
grep -RniE 'curl|wget|base64|/dev/tcp|LD_PRELOAD' \
  /etc/profile /etc/profile.d /etc/bashrc 2>/dev/null || true

sec "ld.so.preload (reading with trusted cat if available)"
CAT="$(trusted_tool cat)"; [[ -s /etc/ld.so.preload ]] && "$CAT" /etc/ld.so.preload || echo "empty"

sec "ld.so.conf.d"
grep -R . /etc/ld.so.conf.d 2>/dev/null || true

sec "modprobe install/options directives (install runs arbitrary commands)"
grep -RnE '^\s*(install|options)\b' /etc/modprobe.d 2>/dev/null || true
grep -R . /etc/modules-load.d 2>/dev/null || true

sec "udev rules invoking programs"
grep -RniE 'RUN|PROGRAM' /etc/udev/rules.d 2>/dev/null || true

sec "PAM: backdoor modules + swapped pam_unix"
grep -RniE 'pam_exec|pam_script|pam_python' /etc/pam.d 2>/dev/null || true
case "$PKG_MGR" in dnf|yum) rpm -V pam 2>/dev/null ;; apt) dpkg -V libpam-modules 2>/dev/null ;; esac
for d in /lib64/security /lib/security /usr/lib/x86_64-linux-gnu/security; do
  [[ -d "$d" ]] || continue
  while IFS= read -r -d '' so; do pkg_owns "$so" || echo "UNOWNED PAM MODULE: $so"; done \
    < <(find "$d" -type f -print0 2>/dev/null)
done

sec "SSH authorized_keys (all homes; note command= / forced options)"
while IFS=: read -r user _ _ _ _ home _; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [[ -f "$f" ]] && { echo "--- $f ---"; cat "$f"; }
  done
done < <(getent passwd)
grep -RniE 'AuthorizedKeysFile|AuthorizedKeysCommand|^Match' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true

sec "Files in temp dirs (all files, not just +x — scripts run via interpreter)"
find /tmp /var/tmp /dev/shm -type f -printf '%M %u %10s %p\n' 2>/dev/null || true

sec "Immutable / append-only files"
for d in /etc /bin /sbin /usr /var/named /var/spool /root; do
  [[ -d "$d" ]] || continue
  lsattr -R "$d" 2>/dev/null | grep -E '^[^/]*[ia]' || true
done

# ---------------- Apply mode ----------------
if [[ "$DRY_RUN" != "1" ]]; then
  log "APPLY: quarantining unowned cron/systemd units"
  while IFS= read -r -d '' f; do
    pkg_owns "$f" && continue
    if [[ "$f" == *.service || "$f" == *.timer ]]; then
      systemctl disable "$(basename "$f")" 2>/dev/null || true
    fi
    quarantine_path "$f"
  done < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
             /etc/cron.monthly /etc/systemd/system -type f -print0 2>/dev/null)

  [[ -s /etc/ld.so.preload ]] && { pkg_owns /etc/ld.so.preload || quarantine_path /etc/ld.so.preload; }
  systemctl daemon-reload 2>/dev/null || true
fi

log "Persistence report: $REPORT"
offbox_reminder "$REPORT"
