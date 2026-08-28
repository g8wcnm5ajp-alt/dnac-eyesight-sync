#!/bin/bash
#
# Remove.sh -- uninstalls the DNAC-to-Eyesight Switch Sync app from
# this Enterprise Manager. Run this ON the EM, as root, from inside
# the same directory Deploy.sh was run from.
#
# By default this leaves ./data and ./certs in place (so a later
# re-Deploy.sh doesn't lose config/history/certs unnecessarily). Pass
# --purge to also remove those.
#
# Usage: sudo ./Remove.sh [--purge]
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="dnac-eyesight-sync"
NETWORK_NAME="DnacEyesightBridge"
FW_HOOK_NAME="DnacEyesightSyncHelper"
HTTPS_PORT=8445

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

echo "=== 1. Closing the firewall port (fstool fw delhook) ==="
if command -v fstool >/dev/null 2>&1; then
    fstool fw delhook "$FW_HOOK_NAME" 2>/dev/null || echo "(hook '$FW_HOOK_NAME' was not registered -- nothing to remove)"
    if iptables -L INPUT -n 2>/dev/null | grep -q "dpt:${HTTPS_PORT}"; then
        echo "WARNING: a rule for port $HTTPS_PORT still shows in iptables -- check by hand." >&2
    else
        echo "Confirmed: no active rule for port $HTTPS_PORT"
    fi
else
    echo "fstool not found -- skipping firewall cleanup (not running on an EM?)" >&2
fi

echo
echo "=== 2. Removing the container ==="
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    echo "Removed container $CONTAINER_NAME"
else
    echo "Container $CONTAINER_NAME not found -- skipped"
fi

echo
echo "=== 3. Removing the docker network ==="
if docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 \
        && echo "Removed docker network $NETWORK_NAME" \
        || echo "WARNING: could not remove network $NETWORK_NAME (still in use by something else?)" >&2
else
    echo "Docker network $NETWORK_NAME not found -- skipped"
fi

if [ "$PURGE" -eq 1 ]; then
    echo
    echo "=== 4. --purge: removing certs/ and data/ ==="
    rm -rf "${DIR}/certs" "${DIR}/data"
    echo "Removed ${DIR}/certs, ${DIR}/data"
else
    echo
    echo "Leaving ${DIR}/certs and ${DIR}/data in place (pass --purge to remove those too)."
fi

echo
echo "Done."
