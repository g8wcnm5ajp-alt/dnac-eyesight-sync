#!/bin/bash
#
# fw-helper.sh -- the ONLY thing the DNAC-to-Eyesight Switch Sync
# container may run on this EM. Installed by Deploy.sh at
# /root/scripts/dnac-eyesight-sync/fw-helper.sh and registered in
# root's authorized_keys as a forced command on the app's own keypair
# (no pty, no forwarding) -- so the container can read and change the
# firewall rule that scopes access to the app's HTTPS port, and nothing
# else. Same pattern as the sibling Tech Support Collector's
# webapp-query.py, cut down to two verbs.
#
#   getadmincidr            -> {"admin_cidr": "x.x.x.x/nn" | null}
#   setadmincidr <cidr>     -> re-applies the fstool fw hook with the new
#                              source CIDR, records it, confirms via iptables
#
# Output is always one JSON object on stdout; errors are {"error": "..."}.
set -uo pipefail

FW_HOOK_NAME="DnacEyesightSyncHelper"
HTTPS_PORT=8445
STATE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/admin_cidr.state"
OCTET='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
CIDR_RE="^${OCTET}\.${OCTET}\.${OCTET}\.${OCTET}/([0-9]|[12][0-9]|3[0-2])$"

fail() { printf '{"error": "%s"}\n' "$1"; exit 1; }

# shellcheck disable=SC2206
ARGS=(${SSH_ORIGINAL_COMMAND:-})
VERB="${ARGS[0]:-}"

case "$VERB" in
    getadmincidr)
        if [ -s "$STATE_FILE" ]; then
            printf '{"admin_cidr": "%s"}\n' "$(head -1 "$STATE_FILE" | tr -d '[:space:]')"
        else
            printf '{"admin_cidr": null}\n'
        fi
        ;;
    setadmincidr)
        CIDR="${ARGS[1]:-}"
        [ "${#ARGS[@]}" -eq 2 ] || fail "usage: setadmincidr <cidr>"
        [[ "$CIDR" =~ $CIDR_RE ]] || fail "'$CIDR' is not a valid CIDR (expected e.g. 192.168.1.0/24 or 0.0.0.0/0)"
        command -v fstool >/dev/null 2>&1 || fail "fstool not found -- not running on an EM?"
        fstool fw delhook "$FW_HOOK_NAME" >/dev/null 2>&1 || true
        if ! OUT="$(fstool fw addhook "$FW_HOOK_NAME" "iptables -I INPUT -s ${CIDR} -m tcp -p tcp --dport ${HTTPS_PORT} -j ACCEPT" 2>&1)"; then
            fail "fstool fw addhook failed: $(printf '%s' "$OUT" | head -c 300 | tr -d '"\\' | tr '\n' ' ')"
        fi
        CONFIRMED=false
        iptables -L INPUT -n 2>/dev/null | grep -q "dpt:${HTTPS_PORT}" && CONFIRMED=true
        echo "$CIDR" > "$STATE_FILE"
        printf '{"admin_cidr": "%s", "firewall_confirmed": %s}\n' "$CIDR" "$CONFIRMED"
        ;;
    *)
        fail "unknown command"
        ;;
esac
