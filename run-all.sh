#!/usr/bin/env bash
# Sequences: persistence hunt -> rootkit hunt -> REVIEW PAUSE -> full purge.
# Hunts always run in report-only mode. The purge only runs after you type a
# confirmation phrase, and honours DRY_RUN from bt.conf/env.
source /opt/blueteam/lib.sh
require_root
detect_pkg_mgr

HUNT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "=== run-all: starting hunt phase (report-only) ==="

log "--- persistence hunt ---"
DRY_RUN=1 bash "$HUNT_DIR/20-persistence-hunt.sh" || warn "persistence hunt exited nonzero"

log "--- rootkit hunt ---"
DRY_RUN=1 bash "$HUNT_DIR/30-rootkit-hunt.sh" || warn "rootkit hunt exited nonzero"

echo
log "=============================================================="
log "HUNT PHASE DONE. Read these reports before continuing:"
log "  ls -t /var/log/blueteam_persistence_*.log | head -1"
log "  ls -t /var/log/blueteam_rootkit_*.log | head -1"
log "=============================================================="
echo
echo "The purge is destructive: it isolates the network, stops services,"
echo "rotates EVERY password, and rewrites SSH. Make sure you have:"
echo "  - read both reports"
echo "  - set MGMT_IP, SCORED_SERVICES, ALLOWED_SSH_KEYS for this box"
echo "  - a way to reach the console if SSH breaks"
echo
read -r -p 'Type  PURGE THIS BOX  to continue, anything else to stop: ' CONFIRM
if [[ "$CONFIRM" != "PURGE THIS BOX" ]]; then
  log "Purge NOT run (no confirmation). Hunt reports are saved."
  exit 0
fi

read -r -p 'Run purge as DRY_RUN first? [Y/n]: ' DR
if [[ "${DR,,}" != "n" ]]; then
  log "--- purge (DRY_RUN=1 preview) ---"
  DRY_RUN=1 bash "$HUNT_DIR/90-full-purge.sh"
  echo
  read -r -p 'Preview done. Type  APPLY  to run for real, anything else to stop: ' GO
  [[ "$GO" == "APPLY" ]] || { log "Stopped after preview. Nothing changed."; exit 0; }
fi

log "--- purge (APPLYING) ---"
DRY_RUN=0 bash "$HUNT_DIR/90-full-purge.sh"
log "=== run-all: complete. Copy /root/.bt_newpw_* and all reports off-box NOW. ==="
