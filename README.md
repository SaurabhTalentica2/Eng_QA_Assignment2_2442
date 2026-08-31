# API Security Testing Duo (VAmPI)

A two-agent AI system that discovers the API surface of the **VAmPI** (Vulnerable
API) application and tests it for **OWASP API Security Top 10** vulnerabilities,
producing a professional security assessment report with CVSS v3.1 scoring,
proof-of-concept evidence, and prioritized remediation.

Built with **CrewAI + Google Gemini**. All testing targets a **local VAmPI
Docker container only** — see [Ethical Use](#ethical-use).

---

## Architecture

The system pairs two CrewAI agents with a deterministic security-testing engine:

```
                 ┌──────────────────────────┐
  VAmPI (Docker) │  Phase 1: DISCOVERY       │
  localhost:5000 │  Agent: Security          │   discovery.py probes the live
        ▲        │  Researcher               │   target, builds an endpoint
        │        │  -> EndpointCatalog       │   catalog with security metadata
        │        └────────────┬─────────────┘
        │                     │ (catalog passed as context)
        │        ┌────────────▼─────────────┐
        │        │  Phase 2: SECURITY TEST   │   security_tests.py runs OWASP
        └────────│  Agent: API Security      │   modules against the target;
                 │  Tester                   │   only *reproduced* findings are
                 │  -> SecurityReport        │   reported (evidence-based)
                 └────────────┬─────────────┘
                              │
                 ┌────────────▼─────────────┐
                 │  Phase 3: REPORTING       │   exporters.py -> JSON + HTML;
                 │  LLM writes exec summary   │   the security agent summarizes
                 │  over confirmed findings   │   the real findings
                 └──────────────────────────┘
```

**Design rationale — why a hybrid of agents + deterministic tests:**
Security findings must be *true*. LLMs can hallucinate vulnerabilities, so the
actual exploitation is performed by Python test modules that hit the live target
and confirm each weakness empirically. The agents provide the reasoning and
reporting layer (risk framing, executive summary, remediation prioritization).
Every reported vulnerability is backed by a real request/response captured
during the run — nothing is asserted without evidence.

---

## Project structure

```
api-security-duo/
├── main.py                 # CLI entry point
├── requirements.txt
├── .env.example            # copy to .env and add your Gemini key
├── src/
│   ├── config.py           # env config, Gemini LLM, VAmPI target, rate limits
│   ├── http_client.py      # safety-first HTTP client (loopback-only, throttled)
│   ├── schemas.py          # Pydantic models (EndpointCatalog, SecurityReport)
│   ├── discovery.py        # Phase 1: endpoint discovery + cataloging
│   ├── security_tests.py   # Phase 2: OWASP API Top 10 test modules + CVSS
│   ├── agents.py           # CrewAI agent definitions
│   ├── crew.py             # pipeline orchestration (Discovery -> Test -> Report)
│   └── exporters.py        # JSON + HTML report generation
└── output/vampi/           # generated artifacts
    ├── api_catalog.json
    ├── security_report.json
    └── security_report.html
```

---

## Setup

### 1. Prerequisites
- Python 3.9+ (developed on 3.12)
- Docker Desktop / Docker CLI
- A Google Gemini API key (free tier): https://aistudio.google.com/app/apikey

### 2. Start VAmPI (the target)
```bash
docker run --rm --name vampi -p 5000:5000 erev0s/vampi:latest
```
Then initialize its database (one time per container start):
```bash
curl http://localhost:5000/createdb
```
You should see `{ "message": "Database populated." }`.

### 3. Install and configure
```bash
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt   # Windows
# or: source venv/bin/activate && pip install -r requirements.txt

copy .env.example .env        # Windows  (cp on macOS/Linux)
# edit .env and set GEMINI_API_KEY
```

### 4. Run the assessment
```bash
venv\Scripts\python.exe main.py
# options:
#   --url http://localhost:5000   override target (must be local)
#   --out run1                    output/<name> directory
```

Artifacts are written to `output/vampi/`. Open `security_report.html` in a
browser for the formatted report.

---

## What it tests (OWASP API Top 10 coverage)

Each module confirms the issue against the live target before reporting it:

| Test | OWASP category | VAmPI endpoint |
|------|----------------|----------------|
| Excessive Data Exposure | API3:2019 | `GET /users/v1/_debug` |
| Weak JWT / Broken Auth | API2:2019 | `POST /users/v1/login` |
| Mass Assignment (privilege escalation) | API6:2019 | `POST /users/v1/register` |
| Broken Object Level Authorization | API1:2019 | `PUT /users/v1/{username}/password` |
| Missing Rate Limiting | API4:2019 | `POST /users/v1/login` |
| Broken Function Level Authorization | API5:2019 | `GET /users/v1/{username}` |
| Injection / input validation | API8:2019 | `PUT /users/v1/{username}/email` |

The injection module reports only if a payload actually triggers a database
error; this VAmPI build validates the email field, so that test correctly
reports no finding rather than a false positive.

---

## Methodology

1. **Discovery** — attempt to pull VAmPI's OpenAPI spec, then probe the known
   endpoint set to confirm reachability and record HTTP metadata. Endpoints are
   categorized by function and assigned a preliminary risk level.
2. **Security testing** — run each OWASP module through the shared, throttled
   HTTP client. Tests create randomized throwaway accounts, attempt the attack,
   and *verify* success (e.g. BOLA is confirmed by logging in as the victim with
   the attacker-set password; mass assignment is confirmed by reading the
   `admin` flag back from the debug listing).
3. **Scoring** — each confirmed finding gets a CVSS v3.1 base score and vector.
4. **Reporting** — the security agent (Gemini) writes an executive summary over
   the confirmed findings; results are exported to JSON and a styled HTML report.

---

## Ethical Use

This tool follows the assignment's security-testing ethics:

- **Authorized target only.** The HTTP client refuses any host that is not
  loopback (`localhost`/`127.0.0.1`). It cannot be pointed at a live system.
- **Rate limited.** A configurable inter-request delay and a per-test request
  cap prevent overwhelming the target.
- **No sensitive data persisted.** Evidence is truncated and kept only in the
  report; credentials discovered during testing are not logged to disk.
- **No hardcoded secrets.** All configuration (API key, target, limits) comes
  from environment variables.

Never run this against any application you do not own or lack written
permission to test.

---

## Sample results (latest run against VAmPI)

- Endpoints discovered: **10**
- Vulnerabilities confirmed: **6** (2 Critical, 3 High, 1 Medium)
  - API1 BOLA on password change — CVSS 9.3
  - API6 Mass Assignment / privilege escalation — CVSS 9.1
  - API3 Excessive Data Exposure via `_debug` — CVSS 7.5
  - API2 Weak JWT configuration — CVSS 7.3
  - API5 Unauthenticated user record access — CVSS 7.5
  - API4 Missing rate limiting — CVSS 5.3

See `output/vampi/security_report.html` for the full report with evidence.

---

## Known limitations & potential improvements

- The injection module uses error-based detection; blind/time-based SQLi is not
  attempted (VAmPI's email field validates input, so no SQLi is present there).
- CVSS scores are assigned per finding type; a full environmental/temporal CVSS
  calculation is out of scope.
- Discovery relies on the known VAmPI endpoint set as a fallback when no OpenAPI
  spec is served; a generic crawler would generalize to other targets.
- Future work: automated exploit PoC generation, PDF export, and mapping
  findings to NIST/ISO 27001 controls (assignment bonus items).
