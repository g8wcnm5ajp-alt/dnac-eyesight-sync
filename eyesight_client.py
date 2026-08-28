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
        if resp.status_code != 200:
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
        if resp.status_code != 200:
            raise EyesightClientError(f"Eyesight delete-switches failed: HTTP {resp.status_code} {resp.text[:500]}")
