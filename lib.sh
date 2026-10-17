#!/usr/bin/env bash
# Shared library. source this from every blueteam script.
set -uo pipefail

BT_DIR="${BT_DIR:-/opt/blueteam}"
[[ -f "$BT_DIR/bt.conf" ]] && source "$BT_DIR/bt.conf"

RUN_TS="$(date +%Y%m%d_%H%M%S)"
QUARANTINE="${QUARANTINE:-/root/blueteam_quarantine}/$RUN_TS"
BACKUP_DIR="${BACKUP_DIR:-/root/blueteam_backups}"
LOG_FILE="${LOG_FILE:-/var/log/blueteam.log}"
DRY_RUN="${DRY_RUN:-1}"
TRUSTED_TOOLS="${TRUSTED_TOOLS:-/mnt/trusted_tools}"
OFFBOX_TARGET="${OFFBOX_TARGET:-}"

mkdir -p "$QUARANTINE" "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null || true

log()  { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
warn() { log "WARN: $*" >&2; }
die()  { log "FATAL: $*" >&2; exit 1; }

require_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root"; }

# ---- Package manager detection -------------------------------------------
detect_pkg_mgr() {
  if command -v dnf >/dev/null 2>&1; then PKG_MGR=dnf
  elif command -v yum >/dev/null 2>&1; then PKG_MGR=yum
  elif command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt
  else PKG_MGR=unknown; warn "No supported package manager found"; fi
  log "Package manager: $PKG_MGR"
}

# Is file $1 owned by an installed package? 0 = owned, 1 = unowned/unknown.
pkg_owns() {
  local f="$1"
  case "${PKG_MGR:-unknown}" in
    dnf|yum) rpm -qf "$f" >/dev/null 2>&1 ;;
    apt)     dpkg -S "$f" >/dev/null 2>&1 ;;
    *)       return 1 ;;
  esac
}

# Keep only currently-installed packages from a candidate list.
pkg_installed_subset() {
  local out=()
  for p in "$@"; do
    case "${PKG_MGR:-unknown}" in
      dnf|yum) rpm -q "$p" >/dev/null 2>&1 && out+=("$p") ;;
      apt)     dpkg -s "$p" >/dev/null 2>&1 && out+=("$p") ;;
    esac
  done
  printf '%s\n' "${out[@]}"
}

# ---- Trusted tools -------------------------------------------------------
TOOL_TRUSTED=no
trusted_tool() {
  local tool="$1" p
  if [[ -x "$TRUSTED_TOOLS/$tool" ]]; then
    TOOL_TRUSTED=yes; echo "$TRUSTED_TOOLS/$tool"; return 0
  fi
  p="$(command -v "$tool" 2>/dev/null)"
  TOOL_TRUSTED=no
  if [[ -n "$p" ]]; then
    warn "No external $tool — using LOCAL $p (UNTRUSTED on a compromised host)"
    echo "$p"; return 0
  fi
  warn "No $tool available at all"; return 1
}

# ---- File handling -------------------------------------------------------
backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  local dest="$BACKUP_DIR/${f#/}.$RUN_TS"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest" 2>/dev/null || warn "backup failed: $f"
}

# Move a path into quarantine, neutralised.
quarantine_path() {
  local p="$1"
  [[ -e "$p" ]] || return 0
  local dest="$QUARANTINE/${p#/}"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY quarantine: $p -> $dest"; return 0
  fi
  mkdir -p "$(dirname "$dest")"
  chattr -i -a "$p" 2>/dev/null || true
  local h; h="$(sha256sum "$p" 2>/dev/null | awk '{print $1}')"
  if mv -f "$p" "$dest" 2>/dev/null; then
    chmod 000 "$dest" 2>/dev/null || true
    log "Quarantined: $p -> $dest  sha256=${h:-?}"
  else
    warn "quarantine move failed: $p"
  fi
}

run() {
  if [[ "$DRY_RUN" == "1" ]]; then log "DRY: $*"; else log "RUN: $*"; "$@"; fi
}

# Print an off-box reminder with a ready-to-run scp line. Call at script end.
offbox_reminder() {
  local report="${1:-$LOG_FILE}"
  echo
  log "=============================================================="
  log "COPY EVIDENCE OFF-BOX NOW (local disk is attacker-controlled)."
  if [[ -n "$OFFBOX_TARGET" ]]; then
    log "  scp '$report' '$LOG_FILE' '$OFFBOX_TARGET'"
    log "  scp -r '$QUARANTINE' '$OFFBOX_TARGET'"
  else
    log "  scp '$report' youruser@YOUR_IP:/path/   # set OFFBOX_TARGET in bt.conf to auto-fill"
  fi
  log "=============================================================="
}
