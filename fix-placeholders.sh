#!/usr/bin/env bash
# One-shot: patch bt.conf with values passed as env vars. No prompts.
# Usage (any you omit is left unchanged):
#   MGMT_IP=10.0.0.5 SCORED="sshd named httpd" KEYS=/root/.ssh/team.pub ./fix-placeholders.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
if [[ ! -f bt.conf ]]; then
  [[ -f bt.conf.example ]] && cp bt.conf.example bt.conf || { echo "no bt.conf/bt.conf.example here"; exit 1; }
fi
patch() {
  local k="$1" v="$2"; [[ -n "$v" ]] || return 0
  if grep -qE "^$k=" bt.conf; then
    sed -i.bak "s|^$k=.*|$k=\"\${$k:-$v}\"|" bt.conf && rm -f bt.conf.bak
    echo "set   $k = $v"
  else
    echo "$k=\"\${$k:-$v}\"" >> bt.conf; echo "added $k = $v"
  fi
}
patch MGMT_IP          "${MGMT_IP:-}"
patch SCORED_SERVICES  "${SCORED:-${SCORED_SERVICES:-}}"
patch ALLOWED_SSH_KEYS "${KEYS:-${ALLOWED_SSH_KEYS:-}}"
echo; echo "Result:"
grep -E '^(MGMT_IP|SCORED_SERVICES|ALLOWED_SSH_KEYS)=' bt.conf
