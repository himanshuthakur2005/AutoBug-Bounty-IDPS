
import requests
from urllib.parse import urlparse

TARGET = "http://127.0.0.1:3000"
TIMEOUT = 5
MAX_BODY_BYTES = 8192

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "AutoBugBounty-IDPS/1.0 (Local Academic Lab)"
})


def make_result(name, status, severity, evidence, recommendation):
    return {
        "title": name,
        "status": status,
        "severity": severity,
        "evidence": str(evidence)[:500],
        "recommendation": recommendation,
    }


def local_request(method, path="/", **kwargs):
    """Allow requests only to the configured local Juice Shop host."""
    base = urlparse(TARGET)

    if (
        base.scheme != "http"
        or base.hostname not in ("127.0.0.1", "localhost")
        or base.port != 3000
    ):
        raise ValueError("Scanner is restricted to local Juice Shop.")

    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid local path.")

    url = f"{TARGET}{path}"
    return SESSION.request(
        method,
        url,
        timeout=TIMEOUT,
        allow_redirects=False,
        stream=True,
        **kwargs,
    )


def read_small_body(response):
    """Read a bounded response body and close the connection."""
    try:
        return response.raw.read(MAX_BODY_BYTES, decode_content=True).decode(
            response.encoding or "utf-8", errors="replace"
        )
    finally:
        response.close()


def run_security_checks():
    results = []

    # Base response is reused for the original configuration checks.
    response = local_request("GET")
    headers = response.headers
    cookies = response.raw.headers.getlist("Set-Cookie")
    response.close()

    # 1-4: Common security headers
    for header, severity in [
        ("Content-Security-Policy", "Medium"),
        ("X-Content-Type-Options", "Low"),
        ("Referrer-Policy", "Low"),
        ("Permissions-Policy", "Low"),
    ]:
        present = header in headers
        results.append(make_result(
            header,
            "Present" if present else "Needs review",
            "Info" if present else severity,
            headers.get(header, "Header not present"),
            f"Review the {header} configuration.",
        ))

    # 5: Clickjacking protection
    csp = headers.get("Content-Security-Policy", "").lower()
    frame_protection = (
        "X-Frame-Options" in headers or "frame-ancestors" in csp
    )
    results.append(make_result(
        "Clickjacking protection",
        "Present" if frame_protection else "Needs review",
        "Info" if frame_protection else "Medium",
        "Framing protection detected" if frame_protection
        else "No recognized framing restriction detected",
        "Review CSP frame-ancestors or X-Frame-Options.",
    ))

    # 6: HSTS
    hsts = headers.get("Strict-Transport-Security")
    is_https = urlparse(TARGET).scheme == "https"
    results.append(make_result(
        "HTTP Strict Transport Security",
        "Present" if is_https and hsts
        else "Not applicable" if not is_https
        else "Needs review",
        "Info" if not is_https or hsts else "Low",
        hsts or "HTTPS/HSTS not established for this response",
        "Evaluate HSTS on production HTTPS deployments.",
    ))

    # 7-9: Cookie attributes
    for label, attribute in [
        ("HttpOnly", "httponly"),
        ("Secure", "secure"),
        ("SameSite", "samesite="),
    ]:
        if not cookies:
            status = "Not applicable"
            evidence = "No Set-Cookie headers in this response"
        else:
            missing = []
            for index, cookie in enumerate(cookies, start=1):
                parts = [
                    part.strip().lower()
                    for part in cookie.split(";")
                ]
                if attribute == "samesite=":
                    found = any(p.startswith("samesite=") for p in parts)
                else:
                    found = attribute in parts
                if not found:
                    missing.append(index)

            status = "Needs review" if missing else "Present"
            evidence = (
                f"Cookie positions needing review: {missing}"
                if missing else "Attribute found on all response cookies"
            )

        results.append(make_result(
            f"Cookie {label}", status,
            "Low" if status == "Needs review" else "Info",
            evidence,
            f"Review the {label} attribute for relevant cookies.",
        ))

    # 10-11: Server information disclosure
    for header in ("Server", "X-Powered-By"):
        value = headers.get(header)
        results.append(make_result(
            f"{header} disclosure",
            "Needs review" if value else "Not detected",
            "Low" if value else "Info",
            value or "Header not disclosed",
            "Avoid unnecessary server technology disclosure.",
        ))

    # 12: CORS configuration
    origin = headers.get("Access-Control-Allow-Origin")
    results.append(make_result(
        "CORS configuration",
        "Needs review" if origin == "*" else
        "Not detected" if not origin else "Present",
        "Low" if origin == "*" else "Info",
        f"Access-Control-Allow-Origin: {origin or 'Absent'}",
        "Review allowed origins and credential handling.",
    ))

    # 13: HTTPS configuration
    results.append(make_result(
        "HTTPS configuration",
        "Present" if is_https else "Not applicable",
        "Info",
        f"Target scheme: {urlparse(TARGET).scheme}",
        "Use HTTPS for production applications.",
    ))

    # 14: Cache-Control
    cache_control = headers.get("Cache-Control")
    results.append(make_result(
        "Cache-Control configuration",
        "Present" if cache_control else "Needs review",
        "Info" if cache_control else "Low",
        cache_control or "Cache-Control header absent",
        "Review caching policy for sensitive responses.",
    ))

    # 15: HTTP methods advertised by OPTIONS
    options = local_request("OPTIONS")
    allowed = options.headers.get("Allow", "")
    options.close()
    methods = {m.strip().upper() for m in allowed.split(",")}
    risky = methods.intersection({"TRACE", "PUT", "DELETE"})

    results.append(make_result(
        "HTTP methods",
        "Needs review" if risky else "Not confirmed",
        "Low" if risky else "Info",
        f"Allow header: {allowed or 'Not advertised'}",
        "Verify that advertised methods are intentional; this header "
        "does not prove that a method can perform an action.",
    ))

    # 16: Cross-Origin-Opener-Policy
    coop = headers.get("Cross-Origin-Opener-Policy")
    results.append(make_result(
        "Cross-Origin-Opener-Policy",
        "Present" if coop else "Needs review",
        "Info" if coop else "Low",
        coop or "Header not present",
        "Assess whether an opener isolation policy is appropriate.",
    ))

    # 17: .env exposure indicator
    response = local_request("GET", "/.env")
    status_code = response.status_code
    body = read_small_body(response)
    looks_like_env = any(
        marker in body.lower()
        for marker in ("database_url=", "secret_key=", "api_key=",
                       "password=", "aws_access_key_id=")
    )
    exposed = status_code == 200 and looks_like_env
    results.append(make_result(
        "Exposed .env indicator",
        "Potential finding" if exposed else "Not confirmed",
        "High" if exposed else "Info",
        f"HTTP {status_code}; environment-variable patterns "
        f"{'detected' if looks_like_env else 'not detected'}",
        "If confirmed, remove public access and rotate any exposed secrets.",
    ))

    # 18: .git configuration exposure indicator
    response = local_request("GET", "/.git/config")
    status_code = response.status_code
    body = read_small_body(response)
    git_config = (
        status_code == 200
        and "[core]" in body.lower()
        and "repositoryformatversion" in body.lower()
    )
    results.append(make_result(
        "Exposed .git/config indicator",
        "Potential finding" if git_config else "Not confirmed",
        "High" if git_config else "Info",
        f"HTTP {status_code}; Git configuration signature "
        f"{'detected' if git_config else 'not detected'}",
        "Block public access to repository metadata if exposed.",
    ))

    # 19: Directory listing indicator
    response = local_request("GET", "/ftp/")
    status_code = response.status_code
    body = read_small_body(response).lower()
    listing = (
        status_code == 200
        and (
            "index of /" in body
            or "directory listing for" in body
            or ("parent directory" in body and "<a " in body)
        )
    )
    results.append(make_result(
        "Directory listing indicator",
        "Potential finding" if listing else "Not confirmed",
        "Medium" if listing else "Info",
        f"HTTP {status_code}; directory-listing signature "
        f"{'detected' if listing else 'not detected'}",
        "Disable unintended directory indexes and review exposed files.",
    ))

    # 20: robots.txt information disclosure review
    response = local_request("GET", "/robots.txt")
    status_code = response.status_code
    body = read_small_body(response)
    robots_paths = [
        line.strip() for line in body.splitlines()
        if line.strip().lower().startswith(("disallow:", "allow:"))
    ]
    results.append(make_result(
        "robots.txt disclosure review",
        "Review recommended" if status_code == 200 and robots_paths
        else "Not confirmed",
        "Info",
        f"HTTP {status_code}; {len(robots_paths)} Allow/Disallow rules",
        "Remember robots.txt is public and does not enforce access control.",
    ))

    # 21: API endpoint response
    response = local_request(
        "GET", "/rest/products/search", params={"q": "test"}
    )
    api_status = response.status_code
    api_type = response.headers.get("Content-Type", "")
    read_small_body(response)
    results.append(make_result(
        "Product search API response",
        "Responding" if 200 <= api_status < 300 else "Needs review",
        "Info" if 200 <= api_status < 300 else "Low",
        f"HTTP {api_status}; Content-Type: {api_type or 'Absent'}",
        "Verify expected status codes and access controls for this API.",
    ))

    # 22: API JSON content-type check
    response = local_request(
        "GET", "/rest/products/search", params={"q": "test"}
    )
    api_status = response.status_code
    api_type = response.headers.get("Content-Type", "")
    response.close()
    json_type = "json" in api_type.lower()
    results.append(make_result(
        "API JSON content type",
        "Present" if json_type else "Needs review",
        "Info" if json_type else "Low",
        f"HTTP {api_status}; Content-Type: {api_type or 'Absent'}",
        "Ensure API responses use the expected media type.",
    ))

    # 23: Generic invalid-route error disclosure
    response = local_request("GET", "/autobugbounty-nonexistent-check")
    status_code = response.status_code
    body = read_small_body(response).lower()
    error_markers = (
        "traceback (most recent call last)",
        " at /app/",
        "node_modules/",
        "stack trace",
    )
    leaked = status_code >= 400 and any(
        marker in body for marker in error_markers
    )
    results.append(make_result(
        "Error-page information disclosure",
        "Potential finding" if leaked else "Not confirmed",
        "Medium" if leaked else "Info",
        f"HTTP {status_code}; stack-trace signature "
        f"{'detected' if leaked else 'not detected'}",
        "Return generic errors to clients and log technical details privately.",
    ))

    # 24: API CORS preflight observation
    response = local_request(
        "OPTIONS",
        "/rest/products/search",
        headers={
            "Origin": "https://example.invalid",
            "Access-Control-Request-Method": "GET",
        },
    )
    preflight_status = response.status_code
    preflight_origin = response.headers.get("Access-Control-Allow-Origin")
    preflight_credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )
    response.close()
    wildcard_credentials = (
        preflight_origin == "*"
        and (preflight_credentials or "").lower() == "true"
    )
    results.append(make_result(
        "API CORS preflight",
        "Needs review" if wildcard_credentials else "Observed",
        "Medium" if wildcard_credentials else "Info",
        f"HTTP {preflight_status}; origin={preflight_origin or 'Absent'}; "
        f"credentials={preflight_credentials or 'Absent'}",
        "Validate allowed origins against application requirements.",
    ))

    # 25: API caching observation
    response = local_request(
        "GET", "/rest/products/search", params={"q": "test"}
    )
    api_cache = response.headers.get("Cache-Control")
    response.close()
    results.append(make_result(
        "API Cache-Control observation",
        "Present" if api_cache else "Needs review",
        "Info" if api_cache else "Low",
        api_cache or "API response did not advertise Cache-Control",
        "Check that authenticated or sensitive API data is not cached publicly.",
    ))

    # 26: Benign input-validation indicator
    response = local_request(
        "GET",
        "/rest/products/search",
        params={"q": "autobugbounty-validation-test"},
    )
    validation_status = response.status_code
    validation_body = read_small_body(response).lower()
    validation_leak = any(
        marker in validation_body
        for marker in (
            "traceback (most recent call last)",
            "sql syntax",
            "unhandled exception",
        )
    )
    results.append(make_result(
        "Basic API input/error handling",
        "Potential finding" if validation_status >= 500 or validation_leak
        else "No obvious error indicator",
        "Medium" if validation_status >= 500 or validation_leak else "Info",
        f"HTTP {validation_status}; obvious error signature "
        f"{'detected' if validation_leak else 'not detected'}",
        "Validate inputs server-side and avoid exposing internal errors.",
    ))

    return results


if __name__ == "__main__":
    try:
        results = run_security_checks()
        for number, item in enumerate(results, start=1):
            print(
                f"{number:02d}. {item['title']}: {item['status']}"
            )
        print(f"\nTotal checks: {len(results)}")
    except requests.RequestException as exc:
        print(f"Connection failed: {exc}")
