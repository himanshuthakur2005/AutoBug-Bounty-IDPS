"""Conservative SQL injection indicator check for the local Juice Shop lab.

This module does not attempt authentication bypass, data extraction, time-based
payloads, or destructive actions. It compares a deliberately invalid login
control with a single-quote syntax probe and reports indicators for review.
"""
from datetime import datetime, timezone
from urllib.parse import urlparse
import re

import requests

TARGET = "http://127.0.0.1:3000"
TIMEOUT = 5
LOGIN_PATH = "/rest/user/login"

# Only report common database/parser error signatures; response content is not
# saved, and only a short generic indicator label is included in the report.
ERROR_PATTERNS = {
    "SQL syntax error": re.compile(r"sql syntax|syntax error.*sql|mysql_fetch|sqlite.*error", re.I),
    "Database error": re.compile(r"database error|query failed|sequelize.*error|sqlstate", re.I),
    "Unhandled server error": re.compile(r"internal server error|unhandled exception", re.I),
}


def _validate_target():
    parsed = urlparse(TARGET)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost")
            or parsed.port != 3000 or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("SQLi assessment is restricted to local Juice Shop at 127.0.0.1:3000.")


def _request_login(email):
    _validate_target()
    # Fixed invalid password: this check never attempts to log in as a user.
    response = requests.post(
        f"{TARGET}{LOGIN_PATH}",
        json={"email": email, "password": "AutoBug-Invalid-Password-For-Local-Test"},
        headers={"User-Agent": "AutoBugBounty-IDPS/1.0 (Local Academic Lab)"},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    try:
        body = response.text[:12000]
        indicators = [name for name, pattern in ERROR_PATTERNS.items() if pattern.search(body)]
        return {"status_code": response.status_code, "indicators": indicators,
                "content_type": response.headers.get("Content-Type", "unknown")}
    finally:
        response.close()


def run_sqli_assessment():
    """Compare normal invalid-login control with a quote syntax probe."""
    _validate_target()
    scanned_at = datetime.now(timezone.utc).isoformat()
    control = _request_login("autobug-sqli-control-invalid@example.invalid")
    probe = _request_login("autobug-sqli-probe'@example.invalid")

    new_indicators = sorted(set(probe["indicators"]) - set(control["indicators"]))
    status_changed_to_server_error = (
        probe["status_code"] >= 500 and control["status_code"] < 500
    )
    suspicious = bool(new_indicators or status_changed_to_server_error)

    if new_indicators:
        evidence = "Probe response contained a database/parser error indicator not seen in the control response: " + ", ".join(new_indicators)
    elif status_changed_to_server_error:
        evidence = (f"Control returned HTTP {control['status_code']}; quote probe returned HTTP "
                    f"{probe['status_code']}. This response difference requires manual review.")
    else:
        evidence = (f"Control HTTP {control['status_code']} and quote probe HTTP {probe['status_code']}; "
                    "no new recognized database-error indicator was observed. This does not prove the endpoint is safe.")

    return {
        "project": "AutoBug Bounty IDPS",
        "scan_type": "Conservative SQL injection indicator check",
        "target": TARGET,
        "endpoint": LOGIN_PATH,
        "scanned_at": scanned_at,
        "status": "Potential finding" if suspicious else "No indicator observed",
        "severity": "High - verify manually" if suspicious else "Informational",
        "control_status_code": control["status_code"],
        "probe_status_code": probe["status_code"],
        "control_error_indicators": control["indicators"],
        "probe_error_indicators": probe["indicators"],
        "evidence": evidence,
        "recommendation": (
            "Manually verify only in the authorized lab. Use parameterized queries/prepared statements, "
            "validate input, and return generic errors without database details."
        ),
        "note": ("This is a low-impact indicator check, not proof of SQL injection. It does not test "
                 "authentication bypass, extract data, or run destructive payloads."),
    }
