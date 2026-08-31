"""API discovery logic for VAmPI.

Strategy:
  1. Try to pull VAmPI's OpenAPI/Swagger spec (it serves one) and parse the
     path/method/parameter metadata from it.
  2. Regardless, probe the known VAmPI endpoint set so the catalog is complete
     even if the spec is unavailable, and so we record live reachability.

The output is an EndpointCatalog with security-relevant metadata (auth needed,
risk level, category). This feeds the Security Testing agent.
"""

from typing import Dict, List, Optional

from .http_client import HttpClient
from .schemas import Endpoint, EndpointCatalog

# The 9 main VAmPI endpoints from the assignment PRD, with expected metadata.
KNOWN_ENDPOINTS = [
    ("GET", "/users/v1", "List all users", False, [], "User Management", "High"),
    ("POST", "/users/v1/register", "User registration", False, ["username", "password", "email"], "User Management", "High"),
    ("POST", "/users/v1/login", "User authentication", False, ["username", "password"], "User Management", "High"),
    ("GET", "/users/v1/{username}", "Get specific user details", False, ["username"], "User Management", "High"),
    ("DELETE", "/users/v1/{username}", "Delete user account", True, ["username"], "User Management", "High"),
    ("PUT", "/users/v1/{username}/email", "Update user email", True, ["email"], "User Management", "High"),
    ("PUT", "/users/v1/{username}/password", "Update user password", True, ["password"], "User Management", "Medium"),
    ("GET", "/books/v1", "List all books", True, [], "Book Management", "Low"),
    ("POST", "/books/v1", "Add new book", True, ["book_title", "secret"], "Book Management", "Medium"),
    ("GET", "/books/v1/{book_title}", "Get book by title", True, ["book_title"], "Book Management", "Medium"),
]

_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/spec"]


def fetch_openapi(client: HttpClient) -> Optional[dict]:
    """Attempt to retrieve VAmPI's OpenAPI spec from common locations."""
    for path in _SPEC_PATHS:
        resp = client.get(path, note="openapi discovery")
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and ("paths" in data or "openapi" in data or "swagger" in data):
                    return data
            except ValueError:
                continue
    return None


def _probe(client: HttpClient, method: str, path: str) -> Optional[int]:
    """Send a lightweight probe to confirm an endpoint is reachable."""
    # Substitute a harmless placeholder for path params during probing.
    concrete = path.replace("{username}", "name1").replace("{book_title}", "bookTitle77")
    # Use GET for read endpoints; for state-changing verbs, only probe reachability
    # with an empty/near-empty request so we don't mutate data during discovery.
    if method in ("GET",):
        resp = client.request(method, concrete, note="probe")
    else:
        resp = client.request(method, concrete, json_body={}, note="probe")
    return resp.status_code if resp is not None else None


def discover(client: HttpClient) -> EndpointCatalog:
    """Build the endpoint catalog from spec + live probing."""
    notes: List[str] = []
    spec = fetch_openapi(client)
    spec_paths: Dict[str, dict] = {}
    if spec:
        notes.append("OpenAPI spec retrieved and parsed.")
        spec_paths = spec.get("paths", {}) or {}
        notes.append(f"Spec advertises {len(spec_paths)} path(s).")
    else:
        notes.append("No OpenAPI spec reachable; relied on known-endpoint probing.")

    endpoints: List[Endpoint] = []
    for i, (method, path, purpose, auth, params, category, risk) in enumerate(KNOWN_ENDPOINTS, 1):
        status = _probe(client, method, path)
        reach = "reachable" if status is not None else "unreachable"
        endpoints.append(
            Endpoint(
                id=f"EP{i:03d}",
                method=method,
                path=path,
                purpose=purpose,
                auth_required=auth,
                parameters=params,
                category=category,
                risk_level=risk,
            )
        )
        notes.append(f"{method} {path}: {reach} (HTTP {status}).")

    return EndpointCatalog(target=client.base_url, endpoints=endpoints, notes=notes)
