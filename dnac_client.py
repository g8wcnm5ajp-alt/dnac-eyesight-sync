"""
Cisco DNAC / Catalyst Center REST API client.

Ported from the original ciscodnacapp_library.py's Authorization/
CiscoDNACPollClass DNAC-facing methods. DNAC in this lab is internet-
hosted (sandboxdnac.cisco.com), reached through an HTTP(S) proxy --
unlike eyesight_client.py, which talks to the EM directly.
"""
import logging

import requests

log = logging.getLogger("dnac_client")

DEFAULT_PAGE_LIMIT = 400  # DNAC's own hard cap is 500 per call; the original config used 400/100.


class DnacClientError(Exception):
    pass


def _build_proxies(proxy_cfg):
    """proxy_cfg: {"enable": bool, "ip": str, "port": str, "username": str, "password": str}.
    Returns a requests-style proxies dict, or None if disabled -- mirrors the original
    ConnectProxyServer's "all protocols, optional basic auth" behavior, simplified to just
    what this app actually uses (DNAC only, https)."""
    if not proxy_cfg or not proxy_cfg.get("enable"):
        return None
    ip = proxy_cfg.get("ip")
    port = proxy_cfg.get("port")
    if not ip or not port:
        raise DnacClientError("Proxy is enabled but ip/port is missing from config.")
    username = proxy_cfg.get("username")
    password = proxy_cfg.get("password")
    if username:
        auth = f"{username}:{password or ''}@"
    else:
        auth = ""
    proxy_url = f"http://{auth}{ip}:{port}"
    return {"http": proxy_url, "https": proxy_url}


class DnacClient:
    """One instance per sync run -- holds its own auth token."""

    def __init__(self, url, username, password, ssl_verify=False, proxy_cfg=None, timeout=60):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify
        self.proxies = _build_proxies(proxy_cfg)
        self.timeout = timeout
        self._token = None

    def authenticate(self):
        """POST /dna/system/api/v1/auth/token with HTTP Basic Auth -> bearer token."""
        token_url = f"https://{self.url}/dna/system/api/v1/auth/token"
        try:
            resp = requests.post(
                token_url, auth=(self.username, self.password), timeout=self.timeout,
                verify=self.ssl_verify, proxies=self.proxies,
            )
        except requests.exceptions.RequestException as e:
            raise DnacClientError(f"Could not reach DNAC at {self.url}: {e}")
        if resp.status_code != 200:
            raise DnacClientError(f"DNAC auth failed: HTTP {resp.status_code} {resp.text[:300]}")
        try:
            self._token = resp.json()["Token"]
        except (ValueError, KeyError) as e:
            raise DnacClientError(f"DNAC auth response missing Token: {e}")
        return self._token

    def _headers(self):
        if not self._token:
            self.authenticate()
        return {"Content-Type": "application/json", "Accept": "application/json", "x-auth-token": self._token}

    def list_devices(self, family_filter=None, page_limit=DEFAULT_PAGE_LIMIT):
        """Paginated GET /dna/intent/api/v1/network-device, looping on DNAC's own
        limit/offset until a page returns fewer than page_limit items. Returns the
        flat list of device dicts (each with at least managementIpAddress/hostname)."""
        devices = []
        offset = 1
        while True:
            params = {"limit": page_limit, "offset": offset}
            if family_filter:
                params["family"] = family_filter
            url = f"https://{self.url}/dna/intent/api/v1/network-device"
            try:
                resp = requests.get(
                    url, headers=self._headers(), params=params, timeout=self.timeout,
                    verify=self.ssl_verify, proxies=self.proxies,
                )
            except requests.exceptions.RequestException as e:
                raise DnacClientError(f"Could not reach DNAC at {self.url}: {e}")
            if resp.status_code != 200:
                raise DnacClientError(f"DNAC device list failed: HTTP {resp.status_code} {resp.text[:300]}")
            try:
                page = resp.json().get("response", [])
            except ValueError as e:
                raise DnacClientError(f"DNAC device list response wasn't JSON: {e}")
            devices.extend(page)
            if len(page) < page_limit:
                break
            offset += len(page)
        return devices
