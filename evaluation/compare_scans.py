#!/usr/bin/env python3
"""Compare AutoBug security checks with OWASP ZAP JSON alerts.

Matches are candidates for manual review, not proof of equivalent findings.
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

BASE_DIR = Path(__file__).resolve().parents[1]
EVALUATION_DIR = BASE_DIR / "evaluation"


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def normalize_url(value):
    """Normalize host, default port, trailing slash and query string."""
    parsed = urlparse(str(value or ""))

    if not parsed.scheme or not parsed.hostname:
        return normalize_text(value).rstrip("/")

    scheme = parsed.scheme.lower()
    port = parsed.port
    netloc = parsed.hostname.lower()

    if port and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc += f":{port}"

    path = parsed.path.rstrip("/") or "/"
    return urlunparse((scheme, netloc, path, "", "", ""))


def canonical_rule(title):
    """Map common AutoBug/ZAP wording variants to a shared rule family."""
    text = normalize_text(title)
    compact = re.sub(r"[^a-z0-9]+", "", text)

    rules = [
        ("content_security_policy",
         ("contentsecuritypolicy", "cspheader", "csp")),
        ("referrer_policy",
         ("referrerpolicy",)),
        ("content_type_options",
         ("xcontenttypenosniff", "xcontenttypeoptions",
          "contenttypenosniff")),
        ("strict_transport_security",
         ("stricttransportsecurity", "hsts")),
        ("frame_options",
         ("xframeoptions", "clickjacking")),
        ("permissions_policy",
         ("permissionspolicy",)),
        ("cross_origin_opener_policy",
         ("crossoriginopenerpolicy",)),
        ("cross_origin_resource_policy",
         ("crossoriginresourcepolicy",)),
        ("cross_origin_embedder_policy",
         ("crossoriginembedderpolicy",)),
        ("server_header_disclosure",
         ("serverheader", "serverversiondisclosure")),
        ("powered_by_disclosure",
         ("xpoweredby", "poweredbyheader")),
        ("cookie_secure",
         ("cookiesecure", "securecookie")),
        ("cookie_httponly",
         ("cookiehttponly", "httponlycookie")),
        ("cookie_samesite",
         ("cookiesamesite", "samesitecookie")),
        ("directory_listing",
         ("directorylisting", "directorybrowsing")),
        ("sensitive_file_exposure",
         ("sensitivefile", "backupfile", "sourcecodeexposure")),
        ("https_usage",
         ("https", "insecuretransport")),
    ]

    for family, aliases in rules:
        if any(alias in compact for alias in aliases):
            return family

    # Fall back to normalized title when no known alias applies.
    return compact


def load_autobug_findings(data):
    """Load supported AutoBug report formats."""
    if isinstance(data, dict) and isinstance(data.get("checks"), list):
        output = []

        for item in data["checks"]:
            status = normalize_text(item.get("status"))

            if status not in (
                "potential finding",
                "needs review",
                "review recommended",
            ):
                continue

            output.append({
                "source": "AutoBug",
                "name": item.get("title", "Unnamed check"),
                "url": normalize_url(
                    item.get("url") or data.get("target", "")
                ),
                "severity": item.get("severity", "Unknown"),
                "evidence": item.get("evidence", ""),
                "rule": canonical_rule(item.get("title", "")),
                "manual_status": "Unreviewed",
            })

        return output

    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [{
            "source": "AutoBug",
            "name": item.get("title", "Unnamed finding"),
            "url": normalize_url(data.get("target", "")),
            "severity": item.get("severity", "Unknown"),
            "evidence": item.get("evidence", ""),
            "rule": canonical_rule(item.get("title", "")),
            "manual_status": "Unreviewed",
        } for item in data["findings"]]

    raise ValueError(
        "AutoBug JSON must contain a 'checks' or 'findings' list."
    )


def load_zap_alerts(data):
    """Load ZAP's standard JSON report, preserving each alert instance."""
    sites = data.get("site", [])

    if not isinstance(sites, list):
        raise ValueError("ZAP report's 'site' field must be a list.")

    output = []

    for site in sites:
        for alert in site.get("alerts", []):
            instances = alert.get("instances", []) or [{}]

            for instance in instances:
                title = alert.get("name", "Unnamed alert")
                url = instance.get("uri") or site.get("@name", "")

                output.append({
                    "source": "OWASP ZAP",
                    "name": title,
                    "url": normalize_url(url),
                    "severity": alert.get("riskdesc", "Unknown"),
                    "evidence": (
                        instance.get("evidence")
                        or instance.get("method")
                        or ""
                    ),
                    "plugin_id": str(alert.get("pluginid", "")),
                    "rule": canonical_rule(title),
                    "manual_status": "Unreviewed",
                })

    return output


def compare(autobug, zap):
    """Match same-rule candidates at the same normalized URL first."""
    unmatched_zap = set(range(len(zap)))
    matched = []
    autobug_only = []

    # First pass: same rule family and same URL.
    for auto in autobug:
        candidates = [
            i for i in sorted(unmatched_zap)
            if zap[i]["rule"] == auto["rule"]
            and zap[i]["url"] == auto["url"]
        ]

        if candidates:
            index = candidates[0]
            unmatched_zap.remove(index)
            matched.append({
                "autobug": auto,
                "zap": zap[index],
                "match_basis": "Same normalized rule family and URL",
                "manual_status": "Needs manual verification",
            })
        else:
            autobug_only.append(auto)

    # Second pass: report same-rule results on different URLs separately.
    # These are NOT matches; this is useful context for manual review.
    for auto in autobug_only:
        auto["related_zap_urls"] = sorted({
            item["url"] for i, item in enumerate(zap)
            if i in unmatched_zap and item["rule"] == auto["rule"]
        })

    zap_only = [zap[i] for i in sorted(unmatched_zap)]

    return matched, autobug_only, zap_only


def main():
    parser = argparse.ArgumentParser(
        description="Compare AutoBug and OWASP ZAP JSON reports."
    )
    parser.add_argument("--autobug", required=True)
    parser.add_argument("--zap", required=True)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    autobug_data = load_json(args.autobug)
    zap_data = load_json(args.zap)

    autobug = load_autobug_findings(autobug_data)
    zap = load_zap_alerts(zap_data)

    matched, autobug_only, zap_only = compare(autobug, zap)

    output = {
        "project": "AutoBug Bounty IDPS",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "autobug_source": str(Path(args.autobug).resolve()),
        "zap_source": str(Path(args.zap).resolve()),
        "counts": {
            "autobug_candidates": len(autobug),
            "zap_alert_instances": len(zap),
            "candidate_matches": len(matched),
            "autobug_only": len(autobug_only),
            "zap_only": len(zap_only),
        },
        "matched_candidates": matched,
        "autobug_only_candidates": autobug_only,
        "zap_only_candidates": zap_only,
        "manual_review_required": True,
        "interpretation": (
            "Matches use known rule-name aliases and normalized URL paths. "
            "A match is only a candidate for manual verification. Different "
            "URLs, evidence, scope, or detection criteria can explain "
            "unmatched results. Do not calculate accuracy from these counts "
            "until findings have been manually adjudicated."
        ),
    }

    output_path = (
        Path(args.output) if args.output else
        EVALUATION_DIR / (
            "comparison_" + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".json"
        )
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== AutoBug vs OWASP ZAP ===")
    for name, value in output["counts"].items():
        print(f"{name}: {value}")

    print(f"\nSaved comparison: {output_path}")
    print("All candidate matches require manual verification.")


if __name__ == "__main__":
    main()
