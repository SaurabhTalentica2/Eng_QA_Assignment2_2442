"""Polite, safety-first HTTP client for testing the local VAmPI target.

All network activity in this project flows through this module so that:
  * a global inter-request delay is always applied (avoid overwhelming VAmPI),
  * a per-instance request counter enforces MAX_REQUESTS_PER_TEST,
  * timeouts and connection errors are handled uniformly,
  * every request is auditable (kept in-memory for the report; no sensitive
    data is persisted to disk per the ethical guidelines).

The client refuses to talk to anything other than a loopback host by default,
which is a hard safeguard against accidentally testing a non-authorized system.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from .config import MAX_REQUESTS_PER_TEST, REQUEST_DELAY_SECONDS, VAMPI_BASE_URL

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


class SafetyError(Exception):
    """Raised when a request would target a non-authorized (non-local) host."""


@dataclass
class Call:
    """A single recorded HTTP interaction (for evidence / audit trail)."""

    method: str
    url: str
    status: Optional[int]
    request_body: Optional[dict] = None
    note: str = ""


@dataclass
class HttpClient:
    base_url: str = VAMPI_BASE_URL
    delay: float = REQUEST_DELAY_SECONDS
    max_requests: int = MAX_REQUESTS_PER_TEST
    timeout: float = 8.0
    _count: int = 0
    calls: List[Call] = field(default_factory=list)

    def __post_init__(self):
        host = urlparse(self.base_url).hostname or ""
        if host not in _LOOPBACK_HOSTS:
            raise SafetyError(
                f"Refusing to test non-local host '{host}'. This tool is only "
                "authorized against a local VAmPI container."
            )

    def _guard(self):
        if self._count >= self.max_requests:
            raise RuntimeError(
                f"Request cap reached ({self.max_requests}). Increase "
                "MAX_REQUESTS_PER_TEST if a test legitimately needs more."
            )
        if self.delay:
            time.sleep(self.delay)
        self._count += 1

    def request(
        self,
        method: str,
        path: str,
        json_body: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        note: str = "",
    ) -> Optional[requests.Response]:
        """Perform a request, recording it. Returns None on connection failure."""
        self._guard()
        url = self.base_url + path
        try:
            resp = requests.request(
                method.upper(),
                url,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
            )
            self.calls.append(
                Call(method.upper(), url, resp.status_code, json_body, note)
            )
            return resp
        except requests.RequestException as exc:
            self.calls.append(Call(method.upper(), url, None, json_body, f"{note} [error: {exc}]"))
            return None

    # Convenience wrappers -------------------------------------------------- #
    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def reset_counter(self):
        self._count = 0
