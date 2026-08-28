# DNAC to Eyesight Switch Sync

Pulls the switch inventory from Cisco DNAC / Catalyst Center and reconciles it into Forescout Eyesight (adds new switches, removes/re-adds duplicates per your chosen mode), deployable directly onto an Enterprise Manager.

## Install

```
sudo ./Deploy.sh
```

Run this **on the EM itself**, as root, from inside this unpacked directory. It:

1. Sets up an HTTPS certificate — interactively asks for one to upload, offers to reuse this EM's own Apache SSL cert, or generates a self-signed one if you don't have either handy.
2. Creates the `DnacEyesightBridge` docker network.
3. Loads and starts the container (auto-restarts on reboot).
4. Opens port 8445 through this EM's own firewall via `fstool fw addhook` (survives a firewall reactivation/reboot).

Unlike the sibling Tech Support Collector, this app never SSHes anywhere — it only makes outbound HTTPS calls (DNAC's REST API, and Eyesight's own CounterACT REST API on this EM), so there's no SSH key/wrapper install step.

Requires `docker` and `fstool` already present on the EM (standard on a Forescout EM).

Safe to re-run — every step is idempotent.

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

Leaves `./data` and `./certs` in place by default (so a later re-`Deploy.sh` doesn't lose config/history/certs). Pass `--purge` to remove those too.

## What's in this package

- `Deploy.sh` / `Remove.sh` — install/uninstall scripts.
- `image.tar` — the pre-built Docker image (`docker load`'d by `Deploy.sh`, nothing built at install time).
- `certs/`, `data/` — created by `Deploy.sh` on first install; not shipped in the package.
