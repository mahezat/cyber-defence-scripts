#!/usr/bin/env bash
# Interactive: detect what the box can, confirm the rest, write bt.conf.
# Safe to run repeatedly. Writes nothing until you approve.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
say()  { printf '%s\n' "$*"; }
ask()  { local p="$1" d="$2" a; read -r -p "$p [$d]: " a; printf '%s' "${a:-$d}"; }

say "=== blueteam box configuration ==="
if   command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum
elif command -v apt-get >/dev/null 2>&1; then PKG=apt
else PKG=unknown; fi
say "Package manager detected: $PKG"

MYIP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
GW="$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')"
say "This box IP: ${MYIP:-unknown}  (iface ${IFACE:-?})"
say "Default gateway: ${GW:-unknown}"

say ""
say "Currently-running services on this box:"
mapfile -t RUNNING < <(systemctl list-units --type=service --state=running \
  --plain --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' \
  | grep -vE '^(systemd|dbus|getty|user@|init)' | sort)
printf '  %s\n' "${RUNNING[@]}"

say ""
say "MANAGEMENT IP = the machine YOU connect FROM (your laptop/jump host)."
say "The box cannot detect this. If unsure, your gateway's subnet is a hint."
MGMT="$(ask 'Your management IP' "${GW:-192.168.1.100}")"
say ""
say "SCORED SERVICES = what the scoring engine checks (not just what's running)."
SCORED="$(ask 'Scored services (space-separated)' 'sshd named httpd')"
say ""
KEYS="$(ask 'Path to your allowed SSH keys file' '/opt/blueteam/allowed_ssh_keys.txt')"

say ""
say "=============================================================="
say "About to write bt.conf with:"
say "  MGMT_IP         = $MGMT"
say "  SCORED_SERVICES = $SCORED"
say "  ALLOWED_SSH_KEYS= $KEYS"
say "=============================================================="
CONFIRM="$(ask 'Write this to bt.conf? (yes/no)' 'no')"
[[ "$CONFIRM" == "yes" ]] || { say "Aborted. Nothing written."; exit 0; }

[[ -f bt.conf.example ]] || { say "bt.conf.example missing — run from the repo dir."; exit 1; }
cp bt.conf.example bt.conf
sed -i.bak \
  -e "s|^MGMT_IP=.*|MGMT_IP=\"\${MGMT_IP:-$MGMT}\"|" \
  -e "s|^SCORED_SERVICES=.*|SCORED_SERVICES=\"\${SCORED_SERVICES:-$SCORED}\"|" \
  -e "s|^ALLOWED_SSH_KEYS=.*|ALLOWED_SSH_KEYS=\"\${ALLOWED_SSH_KEYS:-$KEYS}\"|" \
  bt.conf && rm -f bt.conf.bak
say ""
say "Wrote bt.conf. Review:  cat bt.conf"
