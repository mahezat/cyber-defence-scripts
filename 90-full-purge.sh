#!/usr/bin/env bash
source /opt/blueteam/lib.sh
require_root
detect_pkg_mgr

log "FULL PURGE mode. DRY_RUN=$DRY_RUN"
[[ "$DRY_RUN" == "1" ]] && log "DRY: destructive steps print only. Set DRY_RUN=0 to execute."

MGMT_IP="${MGMT_IP:-192.168.1.100}"
PWFILE="/root/.bt_newpw_$RUN_TS"
if [[ "$DRY_RUN" != "1" ]]; then : > "$PWFILE"; chmod 600 "$PWFILE"; fi

# 0. Evidence snapshot BEFORE we destroy anything (read-only, kept even in dry run)
log "Snapshotting volatile state"
{ ps auxf; echo; ss -tupan; echo; cat /etc/passwd; echo; crontab -l 2>/dev/null; } \
  > "$BACKUP_DIR/presnapshot_$RUN_TS.txt" 2>&1 || true

# 1. Reinstall FIRST, while network still works
log "Reinstalling core packages (before isolation)"
mapfile -t PKGS < <(
  case "$PKG_MGR" in
    dnf|yum) pkg_installed_subset $REINSTALL_PACKAGES_RPM ;;
    apt)     pkg_installed_subset $REINSTALL_PACKAGES_DEB ;;
  esac )
if (( ${#PKGS[@]} )); then
  case "$PKG_MGR" in
    dnf) run dnf -y reinstall "${PKGS[@]}" ;;
    yum) run yum -y reinstall "${PKGS[@]}" ;;
    apt) run apt-get update; run apt-get install -y --reinstall "${PKGS[@]}" ;;
  esac
else
  warn "No installed packages matched the reinstall list"
fi
case "$PKG_MGR" in dnf|yum) log "Tampered files:"; rpm -Va 2>/dev/null | grep -vE '^\.{8}' | head -80 ;; esac

# 2. Clear immutable/append-only attrs
log "Clearing immutable/append-only attributes"
for d in /etc /bin /sbin /usr /var /root; do
  find "$d" -xdev \( -type f -o -type d \) -exec chattr -i -a {} + 2>/dev/null || true
done

# 3. Isolate network (all tables + IPv6, keep mgmt + established)
log "Isolating network (mgmt IP: $MGMT_IP)"
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  run systemctl stop firewalld
fi
for ipt in iptables ip6tables; do
  command -v "$ipt" >/dev/null 2>&1 || continue
  run $ipt -F; run $ipt -X; run $ipt -t nat -F; run $ipt -t mangle -F
  run $ipt -P INPUT DROP; run $ipt -P FORWARD DROP; run $ipt -P OUTPUT DROP
  run $ipt -A INPUT  -i lo -j ACCEPT
  run $ipt -A OUTPUT -o lo -j ACCEPT
  run $ipt -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  run $ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
run iptables -A INPUT  -s "$MGMT_IP" -j ACCEPT
run iptables -A OUTPUT -d "$MGMT_IP" -j ACCEPT
run iptables -A INPUT  -p udp --dport 53 -j ACCEPT
run iptables -A INPUT  -p tcp --dport 53 -j ACCEPT
run iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
run iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# 4. Stop non-essential services, never scored/infra ones
log "Stopping non-essential services"
KEEP="systemd|dbus|NetworkManager|network|auditd|rsyslog|journald|getty|${PKG_MGR}"
for s in $SCORED_SERVICES; do KEEP="$KEEP|^$s"; done
while read -r svc _; do
  [[ "$svc" == *.service ]] || continue
  echo "$svc" | grep -qE "$KEEP" && continue
  run systemctl stop "$svc"
done < <(systemctl list-units --type=service --state=running --plain --no-legend)

# 5. Quarantine payload drop zones (incl. dotfiles + dirs)
log "Quarantining temp-dir contents"
shopt -s dotglob nullglob
for f in /tmp/* /var/tmp/* /dev/shm/*; do
  [[ "$f" == */. || "$f" == */.. ]] && continue
  quarantine_path "$f"
done
shopt -u dotglob nullglob

# 6. Restore DNS from golden copy
if [[ -d "$GOLDEN_DNS" ]]; then
  log "Restoring DNS from golden copy"
  backup_file /etc/named.conf
  run cp -a "$GOLDEN_DNS/etc/." /etc/
  run cp -a "$GOLDEN_DNS/var/named/." /var/named/
  run chown -R root:named /var/named
  run find /var/named/{data,dynamic,slaves} -exec chown named:named {} + 2>/dev/null
  command -v restorecon >/dev/null 2>&1 && run restorecon -R /etc/named* /var/named
  svc=named; systemctl list-unit-files | grep -q '^named-chroot' && svc=named-chroot
  if named-checkconf /etc/named.conf; then run systemctl restart "$svc"; else warn "named-checkconf FAILED — not restarting"; fi
else
  warn "No golden DNS backup at $GOLDEN_DNS — DNS NOT restored"
fi

# 7. SSH: restore YOUR keys, harden, validate before restart
log "Resetting SSH"
while IFS=: read -r user _ _ _ _ home _; do
  [[ -d "$home/.ssh" ]] || continue
  for k in authorized_keys authorized_keys2; do
    [[ -f "$home/.ssh/$k" ]] && quarantine_path "$home/.ssh/$k"
  done
done < <(getent passwd)
if [[ -f "$ALLOWED_SSH_KEYS" ]]; then
  run install -d -m 700 /root/.ssh
  run cp "$ALLOWED_SSH_KEYS" /root/.ssh/authorized_keys
  run chmod 600 /root/.ssh/authorized_keys
else
  warn "No $ALLOWED_SSH_KEYS — you may lock yourself out of SSH!"
fi
set_sshd() {
  local key="$1" val="$2" cfg=/etc/ssh/sshd_config
  if grep -qiE "^\s*#?\s*$key\b" "$cfg"; then
    run sed -i "s|^\s*#\?\s*$key\b.*|$key $val|I" "$cfg"
  elif [[ "$DRY_RUN" == "1" ]]; then
    log "DRY: would append '$key $val' to $cfg"
  else
    echo "$key $val" >> "$cfg"; log "appended: $key $val"
  fi
}
backup_file /etc/ssh/sshd_config
set_sshd PermitRootLogin no
set_sshd PasswordAuthentication no
grep -rliE 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config.d 2>/dev/null \
  | while read -r d; do quarantine_path "$d"; done
if sshd -t; then run systemctl restart sshd; else warn "sshd -t FAILED — leaving sshd as-is"; fi

# 8. Rotate ALL passwords and RECORD them
log "Rotating passwords (saved to $PWFILE)"
rotate_pw() {
  local u="$1" pw; pw="$(openssl rand -base64 18)"
  if [[ "$DRY_RUN" == "1" ]]; then log "DRY: would reset $u"; return; fi
  echo "$u:$pw" | chpasswd && { echo "$u:$pw" >> "$PWFILE"; log "reset: $u"; }
}
awk -F: '($3>=1000 && $3<65534) || $3==0 {print $1}' /etc/passwd | sort -u | while read -r u; do
  rotate_pw "$u"
done

# 9. Flag extra UID-0 accounts (don't auto-delete)
log "UID-0 accounts present (investigate any that aren't root):"
awk -F: '$3==0 {print "  "$1}' /etc/passwd

log "Full purge complete. NEW PASSWORDS: $PWFILE (copy off-box, then shred)."
log "Next: verify named serving, check auditd, reinitialize AIDE (aide --init)."
offbox_reminder "$REPORT"
