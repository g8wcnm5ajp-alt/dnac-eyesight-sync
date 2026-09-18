"""
fw_client.py -- the container's one line to the EM it runs on: the
firewall rule that scopes access to this app's own HTTPS port.

Deploy.sh registers keys/fw_helper_rsa in root's authorized_keys as a
forced command on /root/scripts/dnac-eyesight-sync/fw-helper.sh (no pty,
no forwarding), so whatever is sent here can only ever become one of
that helper's two verbs. Same pattern as the sibling Tech Support
Collector's forescout_client.py, cut down to get/set of the CIDR.
"""
import json
import os
import re
import subprocess

EM_HOST = os.environ.get("DNAC_EYESIGHT_EM_HOST", "host.docker.internal")
SSH_KEY_PATH = "/keys/fw_helper_rsa"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
CIDR_RE = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}/(?:[0-9]|[12][0-9]|3[0-2])$")


class FwClientError(Exception):
    pass


def valid_cidr(cidr):
    return bool(CIDR_RE.match(cidr or ""))


def _run_verb(verb_command, timeout):
    if not os.path.isfile(SSH_KEY_PATH):
        raise FwClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- this deployment predates the Setup page; re-run Deploy.sh."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}", verb_command,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise FwClientError(f"Request to the EM timed out after {timeout}s.")
    except FileNotFoundError:
        raise FwClientError("ssh is not available in this container.")
    if not p.stdout.strip():
        detail = p.stderr.strip() or f"exit code {p.returncode}"
        raise FwClientError(f"No response from the EM ({detail}).")
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise FwClientError(f"Unexpected (non-JSON) response from the EM: {p.stdout[:300]}")
    if "error" in data:
        raise FwClientError(data["error"])
    return data


def get_admin_cidr(timeout=15):
    return _run_verb("getadmincidr", timeout=timeout)


def set_admin_cidr(cidr, timeout=20):
    if not valid_cidr(cidr):
        raise FwClientError(f"'{cidr}' is not a valid CIDR (expected e.g. 192.168.1.0/24 or 0.0.0.0/0).")
    return _run_verb(f"setadmincidr {cidr}", timeout=timeout)
