# cyber-defence-scripts

Blue-team incident-response toolkit for CTF defence scenarios (e.g. CCDC-style).
**Report first, change second.** The hunts are read-only; the purge is destructive.

## Read before running
- The purge **isolates the network, stops services, rotates every password, and
  rewrites SSH**. Run the hunts and read their reports first.
- On a compromised host, this repo and its config are attacker-editable. Verify
  integrity with `./gen-manifest.sh --check` against a `MANIFEST.sha256` you kept
  on your own machine.
- Userland rootkit checks are **best-effort** without real static trusted tools.
  A clean report means "no evidence found", not "confirmed clean". Suspected
  kernel compromise -> capture memory off-box and rebuild.

## Layout
| File | Purpose |
|------|---------|
| `bt.conf` | Config. Copy from `bt.conf.example`; set `MGMT_IP`, `SCORED_SERVICES`, `ALLOWED_SSH_KEYS`. |
| `lib.sh` | Shared helpers (logging, quarantine, pkg detection, trusted tools). |
| `20-persistence-hunt.sh` | Report + optional quarantine of persistence mechanisms. |
| `30-rootkit-hunt.sh` | Kernel/userland rootkit indicators. |
| `90-full-purge.sh` | Destructive cleanup + credential rotation. |
| `run-all.sh` | Hunts -> review pause -> optional purge, with confirmations. |
| `gen-manifest.sh` | Generate/verify the SHA256 integrity manifest. |

## Usage
```bash
sudo install -d /opt/blueteam && sudo cp -t /opt/blueteam ./*
sudo cp /opt/blueteam/bt.conf.example /opt/blueteam/bt.conf   # then edit it
sudo DRY_RUN=1 /opt/blueteam/20-persistence-hunt.sh
sudo DRY_RUN=1 /opt/blueteam/30-rootkit-hunt.sh
# review the reports in /var/log/blueteam_*.log, then:
sudo /opt/blueteam/run-all.sh
```

`DRY_RUN=1` (default) previews; `DRY_RUN=0` applies.

## Deliberately not handled
Memory forensics, disk imaging, and malware reverse-engineering. Those are
separate off-box steps. This is response and hardening only.
