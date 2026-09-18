# DNAC to Eyesight Switch Sync

Pulls the switch inventory from Cisco DNAC / Catalyst Center and reconciles it into Forescout Eyesight (adds new switches, removes/re-adds duplicates per your chosen mode), deployable directly onto an Enterprise Manager.

## Install

```
unzip DnacEyesightSync-v3.zip
cd DnacEyesightSync-v3
sudo ./Deploy.sh
```

Run this **on the EM itself**, as root, from inside the unpacked directory (the zip unpacks into a folder of its own name; `Deploy.sh` and `Remove.sh` are already executable). It:

1. Installs `fw-helper.sh` under `/root/scripts/dnac-eyesight-sync/` and registers the app's keypair (`keys/`) in root's `authorized_keys`, restricted to that one helper — this is what lets the app's **Setup** page change the firewall rule later without a redeploy.
2. Generates a self-signed HTTPS certificate (no prompts; browsers show a one-time trust warning). Replace it later on the app's **Certificates** page — upload your own, or take this EM's own Apache cert with one click.
3. Creates the `DnacEyesightBridge` docker network.
4. Loads and starts the container (auto-restarts on reboot).
5. Opens port 8445 through this EM's own firewall via `fstool fw addhook` (survives a firewall reactivation/reboot) — **open to any source (`0.0.0.0/0`) by default**. Narrow it on the app's **Setup** page, or at install time with `ADMIN_CIDR=192.168.1.0/24 ./Deploy.sh`.

Requires `docker` and `fstool` already present on the EM (standard on a Forescout EM).

Safe to re-run — every step is idempotent; an existing cert, keypair and `data/` are kept.

## Access

```
https://<this-EM's-IP>:8445/
```

Default login: `admin` / `DnacEyesightSync123` — you'll be forced to change this on first sign-in.

Then fill in the **Config** tab (DNAC credentials/URL, Eyesight credentials/URL, switch managers, switch-profile rules, proxy if DNAC needs one to reach the internet) before running or scheduling a sync.

## Uninstall

```
sudo ./Remove.sh
```

Closes the firewall port, removes the container, network, restricted key and helper. Leaves `./data`, `./certs` and `./keys` in place by default (so a later re-`Deploy.sh` doesn't lose config/history/certs). Pass `--purge` to remove those too.

## What's in this package

- `Deploy.sh` / `Remove.sh` — install/uninstall scripts.
- `fw-helper.sh` — the EM-side helper `Deploy.sh` installs (the only command the container may run on the EM).
- `image.tar` — the pre-built Docker image (`docker load`'d by `Deploy.sh`, nothing built at install time).
- Source (`app.py`, `*_client.py`, `sync_engine.py`, `scheduler.py`, `templates/`, `static/`, `Dockerfile`) — for rebuilding the image: `./build-dist.sh` on a machine with Docker produces a fresh `image.tar` and the next zip.
- `certs/`, `data/`, `keys/` — created by `Deploy.sh` on first install; not shipped in the package.
