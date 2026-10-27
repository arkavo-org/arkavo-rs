#!/usr/bin/env python3
"""Release gate over osv-scanner JSON output (python3 stdlib only).

Usage: osv_gate.py RESULTS.json [--config osv-scanner.toml] [--max-waiver-days N]

Policy (C2PA Generator Product Security Requirements, O.3/O.4 Level 1):
  * Any finding rated CRITICAL (CVSS >= 9.0) or HIGH (CVSS >= 7.0) fails the gate.
    Lower severities are printed but do not fail it.
  * A finding with no usable rating is printed as a warning and does not fail the gate.
  * Waivers live in osv-scanner.toml. osv-scanner drops a waived finding from its
    results until `ignoreUntil` passes, so an expired waiver fails the gate again
    with no extra logic here. This script also lints the waiver file, because
    osv-scanner treats an entry without `ignoreUntil` as permanent.

Exit status: 0 pass, 1 gate failed, 2 bad input (missing results, nothing scanned,
or a waiver that breaks policy).
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import tomllib

CRITICAL_MIN = 9.0
HIGH_MIN = 7.0
LABEL_RANK = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DETECTED_RE = re.compile(r"\bdetected:?\s+(\d{4}-\d{2}-\d{2})\b", re.IGNORECASE)


def level_from_score(score):
    if score >= CRITICAL_MIN:
        return "CRITICAL"
    if score >= HIGH_MIN:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def group_level(group, vulns_by_id):
    """Return (level, score text) for one group of aliased advisories."""
    best = "UNKNOWN"
    shown = ""
    try:
        score = float(group.get("max_severity") or "")
        best, shown = level_from_score(score), f"{score:.1f}"
    except ValueError:
        pass
    # Advisory databases also carry a text rating (GHSA: database_specific.severity).
    # Take the higher of the two so a missing score never lowers a rating.
    for vid in group.get("ids", []):
        label = ((vulns_by_id.get(vid) or {}).get("database_specific") or {}).get("severity")
        label = str(label or "").upper()
        if LABEL_RANK.get(label, 0) > LABEL_RANK[best]:
            best = "MEDIUM" if label == "MODERATE" else label
    return best, shown


def collect(results_path):
    with open(results_path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings, scanned = [], 0
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path", "?")
        for pkg in result.get("packages") or []:
            scanned += 1
            info = pkg.get("package") or {}
            vulns_by_id = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
            for group in pkg.get("groups") or []:
                level, score = group_level(group, vulns_by_id)
                findings.append({
                    "level": level,
                    "score": score,
                    "ids": ", ".join(group.get("ids", [])),
                    "package": f'{info.get("name", "?")}@{info.get("version", "?")}',
                    "source": source,
                })
    return findings, scanned


def lint_waivers(config_path, max_days):
    """Return a list of policy violations in the waiver file."""
    if not config_path or not os.path.exists(config_path):
        return []
    with open(config_path, "rb") as fh:
        config = tomllib.load(fh)
    problems = []
    for entry in config.get("IgnoredVulns", []):
        vid = entry.get("id", "<no id>")
        until = entry.get("ignoreUntil")
        reason = entry.get("reason", "")
        if not entry.get("id"):
            problems.append("a waiver has no id")
        if isinstance(until, dt.datetime):
            until = until.date()
        if not isinstance(until, dt.date):
            problems.append(f"{vid}: ignoreUntil is missing (osv-scanner would waive it forever)")
            continue
        match = DETECTED_RE.search(reason)
        if not match:
            problems.append(f'{vid}: reason must record the detection date as "Detected YYYY-MM-DD"')
            continue
        detected = dt.date.fromisoformat(match.group(1))
        if until > detected + dt.timedelta(days=max_days):
            problems.append(
                f"{vid}: ignoreUntil {until} is more than {max_days} days after detection {detected}"
            )
        if until <= dt.date.today():
            print(f"::notice::Waiver for {vid} expired on {until}; remove it from {config_path}.")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("results")
    parser.add_argument("--config", default="osv-scanner.toml")
    parser.add_argument("--max-waiver-days", type=int, default=90)
    args = parser.parse_args()

    problems = lint_waivers(args.config, args.max_waiver_days)
    for problem in problems:
        print(f"::error file={args.config}::{problem}")
    if problems:
        return 2

    if not os.path.exists(args.results) or os.path.getsize(args.results) == 0:
        print(f"::error::No scan results at {args.results}; the scan itself failed, see the scan step.")
        return 2
    findings, scanned = collect(args.results)
    if scanned == 0:
        print("::error::osv-scanner listed no packages. The lockfile was not parsed, so nothing was checked.")
        return 2

    failing = [f for f in findings if f["level"] in ("CRITICAL", "HIGH")]
    unrated = [f for f in findings if f["level"] == "UNKNOWN"]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    lines = [
        f"Packages scanned: {scanned}. Findings: {len(findings)} "
        f"({len(failing)} CRITICAL/HIGH, {len(unrated)} unrated).",
    ]
    if findings:
        lines += ["", "| Severity | CVSS | Advisories | Package |", "| --- | --- | --- | --- |"]
    for f in sorted(findings, key=lambda f: order[f["level"]]):
        lines.append(f'| {f["level"]} | {f["score"] or "-"} | {f["ids"]} | {f["package"]} |')
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## Vulnerability gate\n\n" + report + "\n")

    for f in unrated:
        print(f'::warning::{f["package"]} {f["ids"]} has no CVSS rating; review it by hand.')
    for f in failing:
        print(f'::error::{f["level"]} {f["ids"]} in {f["package"]}: fix it, or add a dated waiver to {args.config}.')
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
