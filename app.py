
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import json
import sqlite3
import time

import requests
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from modules.security_checks import run_security_checks
from modules.sql_injection import run_sqli_assessment

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = BASE_DIR / "idps.db"

REPORT_DIR.mkdir(parents=True, exist_ok=True)

TARGET = "http://127.0.0.1:3000"
TIMEOUT = 5
BURST_THRESHOLD = 10
BURST_WINDOW_SECONDS = 60

SUSPICIOUS_PATHS = {
    "/.env",
    "/admin",
    "/etc/passwd",
    "/wp-config.php",
    "/.git/config",
}

app = Flask(__name__)
request_windows = defaultdict(deque)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                target TEXT NOT NULL,
                status_code INTEGER,
                finding_count INTEGER NOT NULL,
                report_file TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT NOT NULL,
                rule_name TEXT NOT NULL
            )
        """)

        # New table; existing scans and alerts remain untouched.
        db.execute("""
            CREATE TABLE IF NOT EXISTS security_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                target TEXT NOT NULL,
                check_count INTEGER NOT NULL,
                potential_count INTEGER NOT NULL,
                review_count INTEGER NOT NULL,
                report_file TEXT NOT NULL
            )
        """)

        # SQLi assessment history is separate; existing tables are unchanged.
        db.execute("""
            CREATE TABLE IF NOT EXISTS sqli_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                report_file TEXT NOT NULL
            )
        """)


def save_alert(source, event_type, severity, evidence, rule_name):
    with get_db() as db:
        cursor = db.execute("""
            INSERT INTO alerts
            (created_at, source, event_type, severity, evidence, rule_name)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            utc_now(), source, event_type, severity, evidence, rule_name
        ))
        return cursor.lastrowid


def record_event(source, path, event_time=None):
    now = time.monotonic() if event_time is None else event_time
    normalized_path = urlparse(path).path or "/"
    created = []

    if normalized_path in SUSPICIOUS_PATHS:
        created.append(save_alert(
            source,
            "Suspicious path",
            "Medium",
            f"Observed path: {normalized_path}",
            "SUSPICIOUS_PATH",
        ))

    window = request_windows[source]
    window.append(now)

    while window and now - window[0] > BURST_WINDOW_SECONDS:
        window.popleft()

    if len(window) == BURST_THRESHOLD:
        created.append(save_alert(
            source,
            "Request burst",
            "High",
            f"{len(window)} simulated events within "
            f"{BURST_WINDOW_SECONDS} seconds",
            "REQUEST_BURST",
        ))

    return created


def validate_local_target(target):
    parsed = urlparse(target)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "localhost")
        or parsed.port != 3000
    ):
        raise ValueError("Only the local Juice Shop target is allowed.")


def scan_target(target):
    validate_local_target(target)

    response = requests.get(
        target, timeout=TIMEOUT, allow_redirects=False
    )
    headers = response.headers
    findings = []

    for header, severity in [
        ("Content-Security-Policy", "Medium"),
        ("X-Content-Type-Options", "Low"),
        ("X-Frame-Options", "Low"),
    ]:
        if header not in headers:
            findings.append({
                "title": f"Missing {header}",
                "severity": severity,
                "evidence": f"Response did not include {header}.",
                "recommendation": f"Review the {header} configuration.",
            })

    for cookie in response.raw.headers.getlist("Set-Cookie"):
        lower = cookie.lower()
        for attribute, title in [
            ("httponly", "Cookie without HttpOnly"),
            ("samesite=", "Cookie without SameSite"),
        ]:
            if attribute not in lower:
                findings.append({
                    "title": title,
                    "severity": "Low",
                    "evidence": f"Cookie may lack {attribute}.",
                    "recommendation": f"Review the {attribute} attribute.",
                })

    result = {
        "target": target,
        "scanned_at": utc_now(),
        "status_code": response.status_code,
        "server": headers.get("Server", "Not disclosed"),
        "findings": findings,
        "note": "Preliminary checks only; validate findings manually.",
    }
    response.close()
    return result


def save_json_report(result, prefix):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{prefix}_{stamp}.json"
    path = REPORT_DIR / filename
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return filename


def save_regular_scan(result, filename):
    with get_db() as db:
        db.execute("""
            INSERT INTO scans
            (scanned_at, target, status_code, finding_count, report_file)
            VALUES (?, ?, ?, ?, ?)
        """, (
            result["scanned_at"],
            result["target"],
            result["status_code"],
            len(result["findings"]),
            filename,
        ))


def save_security_scan(checks):
    scanned_at = utc_now()

    report = {
        "project": "AutoBug Bounty IDPS",
        "scan_type": "Security configuration and exposure checks",
        "target": TARGET,
        "scanned_at": scanned_at,
        "check_count": len(checks),
        "potential_count": sum(
            item.get("status") == "Potential finding" for item in checks
        ),
        "review_count": sum(
            item.get("status") in ("Needs review", "Review recommended")
            for item in checks
        ),
        "checks": checks,
        "note": (
            "Automated indicators only. Findings require validation; "
            "not every check proves a vulnerability."
        ),
    }

    filename = save_json_report(report, "security_scan")

    with get_db() as db:
        db.execute("""
            INSERT INTO security_scans
            (scanned_at, target, check_count, potential_count,
             review_count, report_file)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scanned_at,
            TARGET,
            len(checks),
            report["potential_count"],
            report["review_count"],
            filename,
        ))

    return report, filename


def dashboard_data():
    with get_db() as db:
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()

        alerts = db.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 30"
        ).fetchall()

        scan_count = db.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        alert_count = db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        security_scan_count = db.execute(
            "SELECT COUNT(*) FROM security_scans"
        ).fetchone()[0]

        latest_security_scan = db.execute("""
            SELECT * FROM security_scans ORDER BY id DESC LIMIT 1
        """).fetchone()

        sqli_scan_count = db.execute("SELECT COUNT(*) FROM sqli_scans").fetchone()[0]
        latest_sqli_scan = db.execute(
            "SELECT * FROM sqli_scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

    report_files = sorted(
        [
            p.name for p in REPORT_DIR.glob("*.json")
            if p.is_file()
        ],
        reverse=True,
    )[:30]

    return {
        "scans": scans,
        "alerts": alerts,
        "scan_count": scan_count,
        "alert_count": alert_count,
        "security_scan_count": security_scan_count,
        "latest_security_scan": latest_security_scan,
        "sqli_scan_count": sqli_scan_count,
        "latest_sqli_scan": latest_sqli_scan,
        "report_files": report_files,
    }


@app.get("/")
def dashboard():
    return render_template(
        "index.html",
        target=TARGET,
        result=None,
        error=None,
        **dashboard_data(),
    )


@app.post("/scan")
def run_scan():
    try:
        result = scan_target(TARGET)
        filename = save_json_report(result, "scan")
        result["report_file"] = filename
        save_regular_scan(result, filename)

        return render_template(
            "index.html",
            target=TARGET,
            result=result,
            error=None,
            **dashboard_data(),
        )
    except (requests.RequestException, ValueError) as exc:
        app.logger.warning("Regular scan failed: %s", exc)
        return render_template(
            "index.html",
            target=TARGET,
            result=None,
            error=str(exc),
            **dashboard_data(),
        ), 502


@app.get("/security-checks")
def security_checks_page():
    # Opening the page displays the latest saved scan; it does not
    # silently run a new assessment every time the page is refreshed.
    latest_report = None
    history = []

    with get_db() as db:
        history = db.execute("""
            SELECT * FROM security_scans
            ORDER BY id DESC LIMIT 20
        """).fetchall()

        latest = db.execute("""
            SELECT report_file FROM security_scans
            ORDER BY id DESC LIMIT 1
        """).fetchone()

    if latest:
        report_path = REPORT_DIR / latest["report_file"]
        if report_path.is_file():
            try:
                latest_report = json.loads(
                    report_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                latest_report = None

    return render_template(
        "security_checks.html",
        checks=(latest_report or {}).get("checks", []),
        latest_report=latest_report,
        history=history,
        error=None,
    )


@app.post("/security-checks/run")
def run_security_checks_route():
    try:
        checks = run_security_checks()
        report, filename = save_security_scan(checks)
        report["report_file"] = filename

        with get_db() as db:
            history = db.execute("""
                SELECT * FROM security_scans
                ORDER BY id DESC LIMIT 20
            """).fetchall()

        return render_template(
            "security_checks.html",
            checks=checks,
            latest_report=report,
            history=history,
            error=None,
        )
    except (requests.RequestException, ValueError) as exc:
        app.logger.warning("Security assessment failed: %s", exc)
        with get_db() as db:
            history = db.execute("""
                SELECT * FROM security_scans
                ORDER BY id DESC LIMIT 20
            """).fetchall()

        return render_template(
            "security_checks.html",
            checks=[],
            latest_report=None,
            history=history,
            error=str(exc),
        ), 502


@app.get("/sqli")
def sqli_page():
    latest_report = None
    history = []
    with get_db() as db:
        history = db.execute("SELECT * FROM sqli_scans ORDER BY id DESC LIMIT 20").fetchall()
        latest = db.execute("SELECT report_file FROM sqli_scans ORDER BY id DESC LIMIT 1").fetchone()
    if latest:
        report_path = REPORT_DIR / latest["report_file"]
        if report_path.is_file():
            try:
                latest_report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                latest_report = None
    return render_template("sqli.html", latest_report=latest_report, history=history, error=None)


@app.post("/sqli/run")
def run_sqli_route():
    try:
        result = run_sqli_assessment()
        filename = save_json_report(result, "sqli_scan")
        result["report_file"] = filename
        with get_db() as db:
            db.execute("""INSERT INTO sqli_scans
                (scanned_at, target, status, severity, report_file)
                VALUES (?, ?, ?, ?, ?)""",
                (result["scanned_at"], result["target"], result["status"],
                 result["severity"], filename))
        if result["status"] == "Potential finding":
            save_alert("sqli-assessment", "Possible SQL injection indicator", "High",
                       result["evidence"], "SQLI_INDICATOR")
        return redirect(url_for("sqli_page"))
    except (requests.RequestException, ValueError) as exc:
        app.logger.warning("SQLi assessment failed: %s", exc)
        latest_report = None
        with get_db() as db:
            history = db.execute("SELECT * FROM sqli_scans ORDER BY id DESC LIMIT 20").fetchall()
        return render_template("sqli.html", latest_report=latest_report, history=history,
                               error=str(exc)), 502


@app.post("/demo/suspicious-path")
def demo_suspicious_path():
    record_event("demo-source-1", "/.env")
    return redirect(url_for("dashboard"))


@app.post("/demo/request-burst")
def demo_request_burst():
    source = "demo-burst-source"
    for _ in range(BURST_THRESHOLD):
        record_event(source, "/")
    return redirect(url_for("dashboard"))


@app.get("/reports/<path:filename>")
def download_report(filename):
    # Permit only JSON report filenames, never directory traversal.
    if (
        Path(filename).name != filename
        or not filename.endswith(".json")
        or not (REPORT_DIR / filename).is_file()
    ):
        abort(404)

    return send_from_directory(
        REPORT_DIR, filename, as_attachment=True
    )


@app.get("/health")
def health():
    return {"status": "ok", "target": TARGET}


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
