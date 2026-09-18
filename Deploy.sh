#!/bin/bash
#
# Deploy.sh -- installs the DNAC-to-Eyesight Switch Sync app directly
# on THIS Enterprise Manager. Run this ON the EM, as root, from inside
# the unpacked DnacEyesightSync directory.
#
# What this does, in order (idempotent -- safe to re-run to pick up a
# newer image; certs/, data/ and keys/ from a previous run are kept):
#   1. Installs fw-helper.sh (the one command the container may run on
#      this EM: read/change the firewall rule for the app's own port)
#      and registers the app's keypair in root's authorized_keys
#      restricted to ONLY that helper -- so the app's Setup page can
#      narrow access later without a redeploy.
#   2. Generates a self-signed HTTPS cert (non-interactive). Replace it
#      later via the app's own Certificates page if you want a real one.
#   3. Creates the DnacEyesightBridge docker network.
#   4. Loads and runs the bundled image -- auto-restarts on reboot.
#   5. Opens the app's port through this EM's own firewall via
#      fstool's own addhook mechanism -- open to any source by default
#      (0.0.0.0/0); narrow it on the app's Setup page, or with
#      ADMIN_CIDR=<cidr> ./Deploy.sh.
#
# Usage: sudo ./Deploy.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="dnac-eyesight-sync"
CONTAINER_NAME="dnac-eyesight-sync"
NETWORK_NAME="DnacEyesightBridge"
HTTPS_PORT=8445
FW_HOOK_NAME="DnacEyesightSyncHelper"
# Source CIDR allowed to reach the app's HTTPS port. Open by default
# (David, 2026-09-18); the app's Setup page changes it live afterwards.
ADMIN_CIDR="${ADMIN_CIDR:-0.0.0.0/0}"

KEY_DIR="${DIR}/keys"
KEY_FILE="${KEY_DIR}/fw_helper_rsa"
KEY_COMMENT="dnac-eyesight-sync-em"
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
HELPER_DIR="/root/scripts/dnac-eyesight-sync"
HELPER="${HELPER_DIR}/fw-helper.sh"
BUNDLED_HELPER="${DIR}/fw-helper.sh"

CERT_DIR="${DIR}/certs"
DATA_DIR="${DIR}/data"
APACHE_CERT="/usr/local/forescout/etc/net_portal_ssl/cert.pem"

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed on this EM." >&2
    exit 1
fi

if [ ! -f "${DIR}/image.tar" ]; then
    echo "Error: ${DIR}/image.tar not found -- run this from inside the unpacked package." >&2
    exit 1
fi

if [ ! -f "$BUNDLED_HELPER" ]; then
    echo "Error: ${BUNDLED_HELPER} not found -- the package is incomplete." >&2
    exit 1
fi

echo "=== 1. Firewall helper + restricted key ==="
mkdir -p "$HELPER_DIR"
cp "$BUNDLED_HELPER" "$HELPER"
chmod 755 "$HELPER"
echo "Installed fw-helper.sh at $HELPER"

mkdir -p "$KEY_DIR"
if [ ! -f "$KEY_FILE" ]; then
    ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N "" -C "$KEY_COMMENT" -q
    echo "Generated new keypair at $KEY_FILE"
else
    echo "Keypair already exists at $KEY_FILE -- not regenerating"
fi
chmod 600 "$KEY_FILE"
chmod 644 "${KEY_FILE}.pub"

mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
touch "$AUTHORIZED_KEYS"
PUBKEY_CONTENT="$(cat "${KEY_FILE}.pub")"
DESIRED_LINE="command=\"${HELPER}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ${PUBKEY_CONTENT}"
if grep -qF "$DESIRED_LINE" "$AUTHORIZED_KEYS" 2>/dev/null; then
    echo "Key already registered in $AUTHORIZED_KEYS -- skipped"
else
    # Compare the key CONTENT, not just the comment (a comment-only check
    # once left a stale entry behind across a keypair regeneration in the
    # sibling app, 2026-09-14). Drop any earlier entry for this app first.
    grep -v "$KEY_COMMENT" "$AUTHORIZED_KEYS" > "${AUTHORIZED_KEYS}.tmp" 2>/dev/null || true
    mv "${AUTHORIZED_KEYS}.tmp" "$AUTHORIZED_KEYS"
    echo "$DESIRED_LINE" >> "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo "Registered restricted key in $AUTHORIZED_KEYS (replaced any stale entry)"
fi

echo
echo "=== 2. HTTPS certificate ==="
mkdir -p "$CERT_DIR"
if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/private.key" ]; then
    echo "Using cert/key already in $CERT_DIR from a previous run -- not touching them"
    echo "(replace them via the app's own Certificates page, or delete both files and re-run for a fresh self-signed one)"
else
    echo "No cert/key found in $CERT_DIR yet -- generating a self-signed one."
    echo "(browsers will show a one-time trust warning; replace it later via the app's own Certificates page)"
    EM_IP_FOR_CERT="$(hostname -I 2>/dev/null | awk '{print $1}')"
    EM_FQDN="$(hostname -f 2>/dev/null || hostname)"
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" \
        -days 825 -subj "/CN=${EM_FQDN}" \
        -addext "subjectAltName=DNS:${EM_FQDN},IP:${EM_IP_FOR_CERT:-127.0.0.1}" \
        >/dev/null 2>&1
    chmod 600 "$CERT_DIR/private.key"
    echo "Generated a self-signed cert for ${EM_FQDN} in $CERT_DIR"
fi

echo
echo "=== 3. Docker network ==="
if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    docker network create "$NETWORK_NAME" >/dev/null
    echo "Created docker network $NETWORK_NAME"
else
    echo "Docker network $NETWORK_NAME already exists -- skipped"
fi

# Docker's "host-gateway" magic value for --add-host is unreliable on
# some bridge-network setups (resolves to <nil> in /etc/hosts). Passing
# the network's real gateway IP is what works every time (sibling app).
BRIDGE_GATEWAY="$(docker network inspect "$NETWORK_NAME" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
if [ -z "$BRIDGE_GATEWAY" ]; then
    echo "Error: could not determine ${NETWORK_NAME}'s gateway IP." >&2
    exit 1
fi
echo "Container will reach this EM via host.docker.internal -> ${BRIDGE_GATEWAY}"

echo
echo "=== 4. Loading and starting the container ==="
docker load -i "${DIR}/image.tar"

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "Removing existing $CONTAINER_NAME container ..."
    docker rm -f "$CONTAINER_NAME" >/dev/null
fi

mkdir -p "$DATA_DIR"

# /host-apache-certs stays mounted read-only so the app's Certificates
# page can still offer this EM's own Apache cert as a one-click option.
docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    --add-host="host.docker.internal:${BRIDGE_GATEWAY}" \
    -p "${HTTPS_PORT}:5000" \
    -v "${KEY_DIR}:/keys:ro" \
    -v "${CERT_DIR}:/certs" \
    -v "${DATA_DIR}:/data" \
    -v "$(dirname "$APACHE_CERT"):/host-apache-certs:ro" \
    -e DNAC_EYESIGHT_EM_HOST=host.docker.internal \
    -e DNAC_EYESIGHT_SSL_CERT=/certs/cert.pem \
    -e DNAC_EYESIGHT_SSL_KEY=/certs/private.key \
    -e DNAC_EYESIGHT_SSL_KEY_PASSWORD_FILE=/certs/key_password.txt \
    "$IMAGE_NAME" >/dev/null

echo "Container $CONTAINER_NAME started"

echo
echo "=== 5. Opening the firewall port (fstool fw addhook) ==="
if [ "$ADMIN_CIDR" = "0.0.0.0/0" ]; then
    echo "Port ${HTTPS_PORT} open to any source -- narrow it on the app's Setup page, or with ADMIN_CIDR=<cidr> ./Deploy.sh"
else
    echo "Restricting access to ${ADMIN_CIDR}"
fi
fstool fw delhook "$FW_HOOK_NAME" >/dev/null 2>&1 || true
fstool fw addhook "$FW_HOOK_NAME" "iptables -I INPUT -s ${ADMIN_CIDR} -m tcp -p tcp --dport ${HTTPS_PORT} -j ACCEPT"
if iptables -L INPUT -n | grep -q "dpt:${HTTPS_PORT}"; then
    echo "Firewall rule for port $HTTPS_PORT confirmed active"
else
    echo "WARNING: could not confirm the firewall rule via iptables -- check by hand." >&2
fi
# What the Setup page reads back; fw-helper.sh keeps it current after that.
echo "${ADMIN_CIDR}" > "${HELPER_DIR}/admin_cidr.state"

EM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

=== Done ===

  https://${EM_IP:-<this-EM-ip>}:${HTTPS_PORT}/

Default login: admin / DnacEyesightSync123
(you will be forced to change this on first sign-in)

Then fill in the Config tab (DNAC + Eyesight credentials, switch
managers/profiles) before running or scheduling a sync. Setup (top
right) narrows which network may reach this page; Certificates
replaces the self-signed cert.

To uninstall later: sudo ./Remove.sh
EOF
