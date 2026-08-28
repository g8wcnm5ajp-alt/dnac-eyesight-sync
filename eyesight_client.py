"""
Forescout Eyesight (CounterACT switch-plugin REST API) client.

Ported from the original ciscodnacapp_library.py's Authorization/
CiscoDNACPollClass Eyesight-facing methods, with two real bugs fixed
along the way (confirmed by reading the original source end to end,
2026-08-28):

  1. The auth call sent username/password as a URL query string
     (`?username=...&password=...`) -- lands in web/proxy access logs.
     Fixed here to a POST body.
  2. The "does this switch already exist in Eyesight" check used
     Python's `in` operator on the IP strings (a substring test, not
     equality) -- e.g. "192.168.22.21" would falsely match
     "192.168.22.212". Fixed here to exact string equality.
"""
import logging

import requests

log = logging.getLogger("eyesight_client")


class EyesightClientError(Exception):
    pass


class EyesightClient:
    """One instance per sync run -- holds its own auth token, never shared
    across requests to different config (each run reads fresh config)."""

    def __init__(self, base_url, username, password, verify_ssl=False, timeout=60):
        # The Eyesight config field is documented as "host only, no https://" (matching
        # DnacClient's own convention) -- unlike DnacClient, this was missing the scheme
        # prepend, so a bare host like "192.168.22.215" produced an invalid URL. Caught live
        # testing the new Test Connection button, 2026-08-28. Accepts a scheme if one was
        # typed anyway, rather than doubling it up.
        base_url = base_url.strip()
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token = None

    def authenticate(self):
        """POST /fsum/oauth2.0/token -- credentials in the POST body, not the URL."""
        url = f"{self.base_url}/fsum/oauth2.0/token"
        data = {
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
            "client_id": "fs-oauth-client",
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "*/*"}
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight auth failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            self._token = resp.json()["access_token"]
        except (ValueError, KeyError) as e:
            raise EyesightClientError(f"Eyesight auth response missing access_token: {e}")
        return self._token

    def _headers(self):
        if not self._token:
            self.authenticate()
        return {"Content-Type": "application/json", "Accept": "*/*", "Authorization": f"Bearer {self._token}"}

    def get_switch_summary(self):
        """GET /switch/api/v1/switches/summary -- returns the raw list of switch dicts
        (each with at least 'managementAddress')."""
        url = f"{self.base_url}/switch/api/v1/switches/summary"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight switch summary failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            return resp.json().get("switches", [])
        except ValueError as e:
            raise EyesightClientError(f"Eyesight switch summary response wasn't JSON: {e}")

    def add_switches(self, switches):
        """switches: [{comment, connectingAppliance, managementAddress, profileName}, ...].
        POST /switch/api/v1/switches. No-op (returns immediately) if the list is empty."""
        if not switches:
            return
        url = f"{self.base_url}/switch/api/v1/switches"
        body = {"switchToAddList": switches}
        try:
            resp = requests.post(url, json=body, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code not in (200, 201):
            raise EyesightClientError(f"Eyesight add-switches failed: HTTP {resp.status_code} {resp.text[:500]}")

    def delete_switches(self, management_addresses):
        """management_addresses: ["ip", ...]. DELETE /switch/api/v1/switches with a JSON
        body (unusual for DELETE, but that's what this API expects). No-op if empty."""
        if not management_addresses:
            return
        url = f"{self.base_url}/switch/api/v1/switches"
        body = {"switchesToDeleteManagementAddresses": management_addresses}
        try:
            resp = requests.delete(url, json=body, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code not in (200, 204):
            raise EyesightClientError(f"Eyesight delete-switches failed: HTTP {resp.status_code} {resp.text[:500]}")

    # -------------------------------------------------------------------
    # Every other operation the real Switch Plugin REST API exposes
    # (confirmed against its own OpenAPI spec, /switch/api/v2/api-docs,
    # 2026-08-28) -- David's ask: surface all of it in Manual Manage, not
    # just add/remove/list.
    # -------------------------------------------------------------------
    def health_check(self):
        """GET /switch/api/v1/healthCheck -- confirms the Switch Plugin API itself is up and
        accepting requests, separately from whether auth/switches themselves are healthy."""
        url = f"{self.base_url}/switch/api/v1/healthCheck"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight health check failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.text

    def get_switch(self, management_address):
        """GET /switch/api/v1/switches?managementAddress=... -- the single-switch detail view
        (connectivity status, vendor, alerts), not just the summary list's own fields."""
        url = f"{self.base_url}/switch/api/v1/switches"
        try:
            resp = requests.get(
                url, headers=self._headers(), params={"managementAddress": management_address},
                timeout=self.timeout, verify=self.verify_ssl,
            )
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight get-switch failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as e:
            raise EyesightClientError(f"Eyesight get-switch response wasn't JSON: {e}")

    def update_switches(self, switches):
        """switches: [{managementAddress, profileName, connectingAppliance, comment}, ...].
        PUT /switch/api/v1/switches -- changes an EXISTING switch's profile/manager/comment
        (the reconcile engine never calls this; sync_engine's own "Delete mode" re-add covers
        that case by removing then adding fresh instead). No-op if empty."""
        if not switches:
            return
        url = f"{self.base_url}/switch/api/v1/switches"
        body = {"switchToUpdateList": switches}
        try:
            resp = requests.put(url, json=body, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code not in (200, 201):
            raise EyesightClientError(f"Eyesight update-switch failed: HTTP {resp.status_code} {resp.text[:500]}")

    def get_switch_credentials(self, management_address):
        """GET /switch/api/v1/switches/credentials?managementAddress=... -- returns the real
        CLI/SNMP/802.1X secrets configured for this switch. Caller (app.py) is responsible for
        never logging/persisting this response anywhere beyond the live page render."""
        url = f"{self.base_url}/switch/api/v1/switches/credentials"
        try:
            resp = requests.get(
                url, headers=self._headers(), params={"managementAddress": management_address},
                timeout=self.timeout, verify=self.verify_ssl,
            )
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight get-switch-credentials failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as e:
            raise EyesightClientError(f"Eyesight get-switch-credentials response wasn't JSON: {e}")

    def update_switch_credentials(self, switches):
        """switches: [{managementAddress, cliType, cliPassword, cliPrivilegedPassword,
        snmpCommunity, snmpAuthPassword, snmpPrivacyPassword, dot1xRadiusSecret, comment}, ...]
        -- only include the keys actually being changed, per the real API's own partial-update
        semantics. PUT /switch/api/v1/switches/credentials. No-op if empty."""
        if not switches:
            return
        url = f"{self.base_url}/switch/api/v1/switches/credentials"
        body = {"switchToUpdateList": switches}
        try:
            resp = requests.put(url, json=body, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code not in (200, 201):
            raise EyesightClientError(f"Eyesight update-switch-credentials failed: HTTP {resp.status_code} {resp.text[:500]}")

    def get_profile_credentials(self, profile_name):
        """GET /switch/api/v1/profiles/credentials?profileName=... -- the credentials shared by
        every switch assigned to this profile, not a single device's own override."""
        url = f"{self.base_url}/switch/api/v1/profiles/credentials"
        try:
            resp = requests.get(
                url, headers=self._headers(), params={"profileName": profile_name},
                timeout=self.timeout, verify=self.verify_ssl,
            )
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight get-profile-credentials failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as e:
            raise EyesightClientError(f"Eyesight get-profile-credentials response wasn't JSON: {e}")

    def update_profile_credentials(self, profiles):
        """profiles: [{profileName, cliType, cliPassword, cliPrivilegedPassword, snmpCommunity,
        snmpAuthPassword, snmpPrivacyPassword, dot1xRadiusSecret, comment}, ...] -- only include
        the keys actually being changed. PUT /switch/api/v1/profiles/credentials. No-op if empty."""
        if not profiles:
            return
        url = f"{self.base_url}/switch/api/v1/profiles/credentials"
        body = {"profileToUpdateList": profiles}
        try:
            resp = requests.put(url, json=body, headers=self._headers(), timeout=self.timeout, verify=self.verify_ssl)
        except requests.exceptions.RequestException as e:
            raise EyesightClientError(f"Could not reach Eyesight at {self.base_url}: {e}")
        if resp.status_code not in (200, 201):
            raise EyesightClientError(f"Eyesight update-profile-credentials failed: HTTP {resp.status_code} {resp.text[:500]}")
