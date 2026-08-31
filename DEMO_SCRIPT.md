# Demo Script — API Security Testing Duo (8 minutes)

The assignment requires an **8-minute video** showing live vulnerability
discovery and exploitation. Follow this script. Have two things open: a terminal
in the project root, and your editor showing `src/`.

> Before recording: do NOT open `.env` on camera (it holds your API key).

---

## 0:00 – 0:45 — Intro
- "This is the API Security Testing Duo: a two-agent CrewAI system that discovers
  and security-tests the VAmPI vulnerable API for OWASP API Top 10 issues."
- Explain the hybrid design: agents reason and report; deterministic Python
  modules do the actual, evidence-based exploitation so findings are never
  hallucinated.

## 0:45 – 2:00 — The target (VAmPI) and ethics
- Show VAmPI running in Docker: `docker ps`
- Hit it live: open `http://localhost:5000/users/v1` in a browser.
- Point out the safety design in `src/http_client.py`: loopback-only guard,
  request throttling, per-test caps. "It physically cannot target a live system."

## 2:00 – 3:30 — Phase 1: Discovery
- Open `src/discovery.py`. Walk through the known-endpoint catalog + probing.
- Open `src/agents.py` — show the two agent roles (Security Researcher,
  API Security Tester).

## 3:30 – 4:30 — Phase 2: The security tests
- Open `src/security_tests.py`. Highlight two modules end to end:
  - **BOLA**: register attacker + victim, use attacker's token to change the
    victim's password, then confirm by logging in as the victim.
  - **Mass Assignment**: register with `admin=true`, verify via `_debug`.

## 4:30 – 6:30 — Run it live
- Run: `venv\Scripts\python.exe main.py`
- Narrate the streamed agent output and the final summary:
  10 endpoints discovered, 6 vulnerabilities confirmed.
- Read out the severities/CVSS scores from the summary table.

## 6:30 – 7:30 — The report
- Open `output/vampi/security_report.html` in a browser.
- Scroll through: executive summary, endpoint catalog, and a couple of findings
  showing the CVSS vector, the proof-of-concept evidence, and remediation.

## 7:30 – 8:00 — Wrap up
- Recap OWASP coverage: API1, API2, API3, API4, API5, API6.
- Mention limitations and bonus directions (PDF export, exploit generation,
  NIST/ISO mapping).
- "Every finding here was empirically reproduced against the live target."

---

## Exact commands (copy-paste order)
```powershell
docker ps
curl http://localhost:5000/createdb        # if DB not yet populated
venv\Scripts\python.exe main.py
```
