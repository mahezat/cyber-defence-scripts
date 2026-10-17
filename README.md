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
| `90-full-purge.sh` | Destructive cleanup + credential rotation. Refuses to run with placeholder config. |
| `run-all.sh` | Hunts -> review pause -> optional purge, with confirmations. |
| `detect-and-configure.sh` | Interactive: auto-detects what the box can, asks for the rest, writes `bt.conf`. |
| `fix-placeholders.sh` | Non-interactive: patch `bt.conf` from env vars in one shot. |
| `gen-manifest.sh` | Generate/verify the SHA256 integrity manifest. |

## Game day
Run in this order on the target VM. Take a snapshot first if you can roll back.

1. **Clone + verify.** Copy your trusted `MANIFEST.sha256` onto the box (scp or
   paste), then:
```bash
   git clone https://github.com/mahezat/cyber-defence-scripts.git
   cd cyber-defence-scripts
   ./gen-manifest.sh --check     # must say OK before you trust these files
```
2. **Configure.** `./detect-and-configure.sh` and answer the 3 prompts. The
   MANAGEMENT IP is the machine YOU connect from — get it right or you lock
   yourself out. Review with `cat bt.conf`.
3. **Deploy.** Scripts expect to live at /opt/blueteam:
```bash
   sudo install -d /opt/blueteam && sudo cp -t /opt/blueteam ./*
```
4. **Snapshot** the VM in Proxmox now, before anything destructive.
5. **Hunt (read-only).** Defaults to DRY_RUN=1:
```bash
   sudo /opt/blueteam/20-persistence-hunt.sh
   sudo /opt/blueteam/30-rootkit-hunt.sh
```
   Read the reports: `ls -t /var/log/blueteam_*.log | head`
6. **Purge.** `sudo /opt/blueteam/run-all.sh` reruns the hunts, pauses for your
   review, previews the purge as a dry run, then asks you to type `APPLY`.
7. **Copy evidence off-box** the moment it finishes: the reports, the quarantine
   dir, and `/root/.bt_newpw_*` (the rotated passwords — lose this and you're
   locked out).

If the config still holds the default placeholder IP, step 6's purge refuses to
run rather than firewalling you off. Override only if you mean it:
`ALLOW_DEFAULTS=1 DRY_RUN=0 /opt/blueteam/90-full-purge.sh`

## Usage reference
`DRY_RUN=1` (default) previews; `DRY_RUN=0` applies. Any config value can be
overridden at runtime, e.g. `MGMT_IP=10.0.0.5 DRY_RUN=0 ./90-full-purge.sh`.

## Deliberately not handled
Memory forensics, disk imaging, and malware reverse-engineering. Those are
separate off-box steps. This is response and hardening only.
