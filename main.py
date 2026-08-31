"""CLI entry point for the API Security Testing Duo.

Runs a full OWASP API Top 10 assessment against a LOCAL VAmPI container:

    python main.py                 # uses VAMPI_BASE_URL from .env
    python main.py --url http://localhost:5000
    python main.py --out output/run1

Artifacts are written to output/<run>/ as api_catalog.json,
security_report.json and security_report.html.

ETHICAL USE: only run against your own local VAmPI Docker container.
"""

import argparse
import sys
from pathlib import Path

# CrewAI's verbose logger emits emoji; force UTF-8 on Windows consoles.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from src import config
from src.config import ConfigError, validate_config
from src.crew import PipelineError, run_pipeline
from src.exporters import write_all

ROOT = Path(__file__).parent
OUTPUT_DIR = ROOT / "output"


def main() -> int:
    parser = argparse.ArgumentParser(description="API Security Testing Duo (VAmPI)")
    parser.add_argument("--url", help="Override VAmPI base URL (default from .env)")
    parser.add_argument("--out", help="Output directory (default: output/vampi)")
    args = parser.parse_args()

    if args.url:
        config.VAMPI_BASE_URL = args.url.rstrip("/")

    try:
        validate_config()
    except ConfigError as exc:
        print(f"[config error] {exc}", file=sys.stderr)
        return 2

    print(f"Starting VAmPI security assessment against {config.VAMPI_BASE_URL} ...\n")

    try:
        catalog, report = run_pipeline()
    except PipelineError as exc:
        print(f"[pipeline error] {exc}", file=sys.stderr)
        return 1

    out_dir = OUTPUT_DIR / (args.out or "vampi")
    written = write_all(catalog, report, out_dir)

    print("\n=== Assessment Summary ===")
    print(f"Endpoints discovered      : {len(catalog.endpoints)}")
    print(f"Vulnerabilities confirmed : {len(report.vulnerabilities)}")
    for v in report.vulnerabilities:
        print(f"  - [{v.severity} / CVSS {v.cvss_score}] {v.name} ({v.owasp_category})")
    print("\nArtifacts written:")
    for label, path in written.items():
        print(f"  - {label}: {path}")

    # Success criterion: 5+ confirmed vulnerabilities.
    return 0 if len(report.vulnerabilities) >= 5 else 3


if __name__ == "__main__":
    raise SystemExit(main())
