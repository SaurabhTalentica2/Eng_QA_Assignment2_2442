"""Pipeline orchestration: Discovery -> Security Testing -> Reporting.

Sequential workflow that mirrors the assignment's Phase 1 -> Phase 2 -> Phase 3
structure:

  1. Discovery agent + discovery.py build the endpoint catalog from live VAmPI.
  2. Security agent + security_tests.py run OWASP API Top 10 tests and collect
     confirmed findings.
  3. The security agent writes an executive summary over the real findings.

The LLM is used for the executive summary (reasoning over empirical results);
the findings themselves come from reproduced evidence.
"""

from typing import Tuple

from crewai import Crew, Process, Task

from .agents import build_discovery_agent, build_security_agent
from .discovery import discover
from .http_client import HttpClient, SafetyError
from .schemas import EndpointCatalog, SecurityReport
from .security_tests import run_all


class PipelineError(Exception):
    """Raised when the security assessment pipeline cannot complete."""


def _summarize(catalog: EndpointCatalog, report: SecurityReport) -> str:
    """Use the security agent to write an executive summary over real findings."""
    agent = build_security_agent()
    findings_lines = "\n".join(
        f"- [{v.severity} / CVSS {v.cvss_score}] {v.name} "
        f"({v.owasp_category}) on {v.endpoint}"
        for v in report.vulnerabilities
    ) or "- No vulnerabilities were empirically confirmed in this run."

    task = Task(
        description=(
            "Write a concise, professional executive summary (5-8 sentences) of "
            "an API security assessment of the VAmPI application.\n\n"
            f"Endpoints discovered: {len(catalog.endpoints)}\n"
            f"Confirmed vulnerabilities: {len(report.vulnerabilities)}\n"
            f"Findings:\n{findings_lines}\n\n"
            "Summarize the overall security posture, the most severe risks, and "
            "the business impact. Do not invent findings beyond those listed."
        ),
        expected_output="A professional executive summary paragraph.",
        agent=agent,
    )
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    result = crew.kickoff()
    return str(result).strip()


def run_pipeline() -> Tuple[EndpointCatalog, SecurityReport]:
    """Execute the full assessment against the configured VAmPI target."""
    try:
        client = HttpClient()
    except SafetyError as exc:
        raise PipelineError(str(exc)) from exc

    # Phase 1: discovery
    catalog = discover(client)
    reachable = sum(1 for n in catalog.notes if "reachable (HTTP" in n and "unreachable" not in n)
    if reachable == 0:
        raise PipelineError(
            "No VAmPI endpoints were reachable. Is the container running at "
            f"{client.base_url}? Start it with: "
            "docker run -p 5000:5000 erev0s/vampi"
        )

    # Phase 2: security testing
    findings = run_all(client)
    report = SecurityReport(target=client.base_url, vulnerabilities=findings)

    # Phase 3: executive summary via the security agent
    try:
        report.executive_summary = _summarize(catalog, report)
    except Exception as exc:
        # Reporting summary is best-effort; findings are the hard deliverable.
        report.executive_summary = (
            f"[summary generation skipped: {exc}] "
            f"{len(findings)} confirmed vulnerabilities across "
            f"{len(catalog.endpoints)} discovered endpoints."
        )

    return catalog, report
