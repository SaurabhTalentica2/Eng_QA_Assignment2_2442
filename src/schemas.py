"""Pydantic models for the API Security Testing Duo.

Two families of models:
  * Discovery output  -> EndpointCatalog (what endpoints exist + metadata)
  * Security output   -> SecurityReport (what vulnerabilities were found)

These are used both as structured outputs and as a validation layer so the
final artifacts always match a stable schema.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# API Discovery output
# --------------------------------------------------------------------------- #
class Endpoint(BaseModel):
    id: str = Field(..., description="Stable ID, e.g. EP001")
    method: str = Field(..., description="HTTP method, e.g. GET/POST/PUT/DELETE")
    path: str = Field(..., description="URL path template, e.g. /users/v1/{user_id}")
    purpose: str = Field(..., description="What the endpoint does")
    auth_required: bool = Field(..., description="Whether it needs authentication")
    parameters: List[str] = Field(default_factory=list)
    category: str = Field(..., description="e.g. User Management, Book Management")
    risk_level: str = Field(..., description="High | Medium | Low")


class EndpointCatalog(BaseModel):
    """Full output of the API Discovery agent."""

    target: str
    endpoints: List[Endpoint] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Security Testing output
# --------------------------------------------------------------------------- #
class Vulnerability(BaseModel):
    id: str = Field(..., description="Stable ID, e.g. VULN001")
    name: str = Field(..., description="Short vulnerability name")
    owasp_category: str = Field(..., description="e.g. API1:2019 Broken Object Level Authorization")
    endpoint: str = Field(..., description="Affected endpoint, e.g. GET /users/v1/{user_id}")
    severity: str = Field(..., description="Critical | High | Medium | Low")
    cvss_score: float = Field(..., description="CVSS v3.1 base score 0.0-10.0")
    cvss_vector: Optional[str] = Field(None, description="CVSS v3.1 vector string")
    description: str
    evidence: str = Field(..., description="Proof-of-concept request/response evidence")
    remediation: str = Field(..., description="How to fix it")
    confirmed: bool = Field(..., description="Whether the test empirically confirmed it")


class SecurityReport(BaseModel):
    """Full output of the Security Testing agent / pipeline."""

    target: str
    executive_summary: str = ""
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
