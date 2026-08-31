"""CrewAI agent definitions for the API Security Testing Duo.

Design rationale: the actual security testing is performed by deterministic
Python modules (discovery.py, security_tests.py) that hit the live VAmPI target.
The two CrewAI agents provide the reasoning/reporting layer -- they interpret
the empirical results, categorize risk, write the executive summary, and
prioritize remediation. This keeps vulnerability *claims* grounded in real
tool evidence (no hallucinated findings) while still using agent collaboration
for analysis and professional reporting.
"""

from crewai import Agent

from .config import build_llm


def build_discovery_agent() -> Agent:
    return Agent(
        role="Security Researcher with API Reconnaissance Expertise",
        goal=(
            "Discover and catalog all API endpoints of the target VAmPI "
            "application, extracting HTTP methods, parameters, authentication "
            "needs, and categorizing each endpoint by functionality and risk."
        ),
        backstory=(
            "You are an API reconnaissance specialist. You map attack surface "
            "methodically and produce clean, structured endpoint inventories "
            "that downstream security testers can act on."
        ),
        llm=build_llm(),
        verbose=True,
        allow_delegation=False,
    )


def build_security_agent() -> Agent:
    return Agent(
        role="API Security Tester",
        goal=(
            "Analyze confirmed vulnerability findings from OWASP API Top 10 "
            "testing of VAmPI, assign accurate CVSS v3.1 severity, and produce "
            "a professional assessment with proof-of-concept evidence and "
            "prioritized remediation."
        ),
        backstory=(
            "You are a seasoned API penetration tester who writes clear, "
            "evidence-based security reports. You never overstate findings: "
            "every vulnerability you report is backed by reproduced evidence."
        ),
        llm=build_llm(),
        verbose=True,
        allow_delegation=False,
    )
