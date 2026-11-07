"""Validate AI evidence and convert native scanner reports into portable findings."""

import hashlib
import html
import json
import plistlib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NotRequired, TypedDict, cast

import jsonschema


class Location(TypedDict):
    path: str
    line: int
    excerpt: str


class Finding(TypedDict):
    id: str
    title: str
    severity: str
    confidence: str
    cwe: int
    subsystem: str
    summary: str
    prerequisites: str
    impact: str
    remediation: str
    verification: str
    evidence_kind: str
    locations: list[Location]
    tool: NotRequired[str]
    native_evidence: NotRequired[str]
    fingerprint: NotRequired[str]
    run_id: NotRequired[str]
    snapshot_id: NotRequired[str]
    triage_state: NotRequired[str]
    runtime_reproduced: NotRequired[bool]


class FindingBatch(TypedDict):
    snapshot_id: str
    reviewer: str
    reviewed_files: list[str]
    findings: list[Finding]


R = Path(sys.argv[1])
LAB = Path(sys.argv[2])
ACTION = sys.argv[3]
SNAP = R / "snapshot"


def read(p):
    return json.loads(p.read_text())


def save(p, v):
    p.write_text(json.dumps(v, indent=2) + "\n")


M = read(R / "manifest.json")
# Revalidate snapshot contents before accepting any evidence.
inv = read(R / "source-inventory.json")
for rel, digest in inv.items():
    q = (SNAP / rel).resolve()
    if (
        not q.is_relative_to(SNAP.resolve())
        or not q.is_file()
        or hashlib.sha256(q.read_bytes()).hexdigest() != digest
    ):
        raise ValueError("Snapshot integrity failure: " + rel)
if (
    hashlib.sha256(json.dumps(inv, sort_keys=True).encode()).hexdigest()
    != M["snapshot_id"]
):
    raise ValueError("Snapshot manifest mismatch")


def validate(batch) -> FindingBatch:
    jsonschema.validate(batch, read(LAB / "config/finding-batch.schema.json"))
    if batch["snapshot_id"] != M["snapshot_id"]:
        raise ValueError("Review belongs to a different snapshot")
    for rel in batch["reviewed_files"]:
        p = (SNAP / rel).resolve()
        if not p.is_relative_to(SNAP.resolve()) or not p.is_file():
            raise ValueError("Invalid reviewed file: " + rel)
    ids = set()
    for f in batch["findings"]:
        if f["id"] in ids:
            raise ValueError("Duplicate finding ID")
        ids.add(f["id"])
        for loc in f["locations"]:
            p = (SNAP / loc["path"]).resolve()
            if not p.is_relative_to(SNAP.resolve()) or not p.is_file():
                raise ValueError("Invalid source path")
            lines = p.read_text().splitlines()
            if (
                loc["line"] > len(lines)
                or loc["excerpt"].strip() not in lines[loc["line"] - 1]
            ):
                raise ValueError("Source excerpt/line mismatch: " + str(loc))
    return cast(FindingBatch, batch)


if ACTION == "ingest":
    batch = validate(read(Path(sys.argv[4])))
    save(R / "codex-review.json", batch)
    M["ai_review_status"] = "completed-source-review"
    M["ai_reviewer"] = batch["reviewer"]
    save(R / "manifest.json", M)
    print("Validated Codex review:", len(batch["findings"]), "findings")
    ACTION = "normalize"
if ACTION != "normalize":
    raise ValueError("Unsupported action")
findings: list[Finding] = []
if (R / "codex-review.json").exists():
    findings += validate(read(R / "codex-review.json"))["findings"]


def location(path: str, line: str | int) -> Location | None:
    path = path.removeprefix("/workspace/")
    p = (SNAP / path).resolve()
    if not p.is_relative_to(SNAP.resolve()) or not p.is_file():
        return None
    lines = p.read_text().splitlines()
    line = max(1, int(line))
    if line > len(lines):
        return None
    return {
        "path": path,
        "line": line,
        "excerpt": lines[line - 1].strip() or "(blank line)",
    }


# Tool diagnostics stay clearly labeled as candidates; no invented runtime verification.
if (R / "raw/cppcheck.xml").exists():
    for e in ET.parse(R / "raw/cppcheck.xml").findall("./errors/error"):
        if e.get("id") in [
            "missingInclude",
            "missingIncludeSystem",
            "preprocessorErrorDirective",
            "syntaxError",
        ]:
            continue
        locs = [
            x
            for x in [
                location(
                    source_location.get("file", ""), source_location.get("line", 1)
                )
                for source_location in e.findall("location")
            ]
            if x
        ]
        if not locs:
            continue
        key = (
            "cppcheck-"
            + e.get("id", "unknown").lower()
            + "-"
            + hashlib.sha256(
                (locs[0]["path"] + locs[0]["excerpt"]).encode()
            ).hexdigest()[:12]
        )
        findings.append(
            {
                "id": key,
                "title": "Cppcheck: " + e.get("msg", "Diagnostic")[:160],
                "severity": "Medium" if e.get("severity") == "error" else "Low",
                "confidence": "Low" if e.get("inconclusive") == "true" else "Medium",
                "cwe": int(e.get("cwe", "0")),
                "subsystem": "static-scanner",
                "summary": e.get("verbose", e.get("msg", "")),
                "prerequisites": "Determine whether the reported path is reachable from untrusted input.",
                "impact": "Tool diagnostic; security impact requires developer triage.",
                "remediation": "Inspect the native diagnostic and its path before changing code.",
                "verification": "Add a focused regression check if confirmed, then rerun the scanner.",
                "evidence_kind": "tool-diagnostic",
                "locations": locs,
                "tool": "cppcheck",
                "native_evidence": "raw/cppcheck.xml",
            }
        )
for p in sorted((R / "raw/clang").glob("*.plist")):
    data = plistlib.loads(p.read_bytes())
    for d in data.get("diagnostics", []):
        source_location = d["location"]
        loc = location(data["files"][source_location["file"]], source_location["line"])
        if not loc:
            continue
        rule = d.get("check_name", "clang-analyzer")
        key = (
            "clang-"
            + hashlib.sha256(
                (rule + loc["path"] + loc["excerpt"]).encode()
            ).hexdigest()[:20]
        )
        findings.append(
            {
                "id": key,
                "title": "Clang: " + d["description"],
                "severity": "Low",
                "confidence": "Medium",
                "cwe": 0,
                "subsystem": "static-scanner",
                "summary": d["description"] + " Checker: " + rule,
                "prerequisites": "Review the analyzer path for feasible inputs.",
                "impact": "Potential correctness or security defect; impact has not been demonstrated.",
                "remediation": "Inspect the analyzer path and add the missing guard or error handling if confirmed.",
                "verification": "Rerun the analyzer and a focused regression check.",
                "evidence_kind": "tool-diagnostic",
                "locations": [loc],
                "tool": "clang-analyzer",
                "native_evidence": str(p.relative_to(R)),
            }
        )
unique = {}
for f in findings:
    # Stable semantic IDs for AI findings, source anchors for raw detector candidates.
    f["fingerprint"] = hashlib.sha256(("ectf-lab-v1:" + f["id"]).encode()).hexdigest()
    f.setdefault("tool", "codex")
    f.setdefault("native_evidence", "codex-review.json")
    f["run_id"] = M["run_id"]
    f["snapshot_id"] = M["snapshot_id"]
    f["triage_state"] = "needs-triage"
    f["runtime_reproduced"] = False
    unique[f["fingerprint"]] = f
findings = list(unique.values())
save(
    R / "findings.json",
    {
        "schema_version": 1,
        "run_id": M["run_id"],
        "snapshot_id": M["snapshot_id"],
        "findings": findings,
    },
)
reports = R / "reports"
reports.mkdir(exist_ok=True)
generic = []
for f in findings:
    where = "\n".join(
        "- `" + x["path"] + ":" + str(x["line"]) + "`: `" + x["excerpt"] + "`"
        for x in f["locations"]
    )
    body = f"# {f['title']}\n\n{f['severity']} severity (provisional) | {f['confidence']} confidence | Needs triage\n\n## Problem\n\n{f['summary']}\n\n## Where\n\n{where}\n\n## Attacker prerequisites\n\n{f['prerequisites']}\n\n## Impact\n\n{f['impact']}\n\n## Fix direction\n\n{f['remediation']}\n\n## Verification criteria\n\n{f['verification']}\n\n## Evidence\n\n{f['evidence_kind']} by {f['tool']}; runtime reproduction: **not performed**.\nRun: `{M['run_id']}`; source snapshot: `{M['snapshot_id']}`.\nNative evidence: `{f['native_evidence']}`. Stable ID: `{f['id']}`.\n"
    (reports / (f["id"] + ".md")).write_text(body)
    g = {
        "title": f["title"][:250],
        "severity": f["severity"],
        "description": body,
        "mitigation": f["remediation"],
        "impact": f["impact"],
        "steps_to_reproduce": "Source inspection only. " + f["verification"],
        "active": True,
        "verified": False,
        "static_finding": True,
        "dynamic_finding": False,
        "file_path": f["locations"][0]["path"],
        "line": f["locations"][0]["line"],
        "unique_id_from_tool": f["fingerprint"],
        "vuln_id_from_tool": f["id"],
        "date": M["created_utc"][:10],
        "tags": [f["tool"], f["subsystem"], "needs-triage", "no-runtime-reproduction"],
    }
    if f["cwe"]:
        g["cwe"] = f["cwe"]
    generic.append(g)
save(
    R / "dojo-import.json",
    {
        "name": "eCTF full static scan",
        "type": "Generic Findings Import",
        "version": M["snapshot_id"][:12],
        "findings": generic,
    },
)
cov = read(R / "coverage.json")
rows = "".join(
    "<tr><td>"
    + html.escape(f["severity"])
    + "</td><td>"
    + html.escape(f["tool"])
    + "</td><td>"
    + html.escape(f["title"])
    + "</td></tr>"
    for f in findings
)
(R / "summary.html").write_text(
    '<!doctype html><meta charset="utf-8"><title>eCTF analysis run</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}</style><h1>eCTF analysis</h1><p>Run '
    + html.escape(M["run_id"])
    + "</p><p>Scanner coverage: "
    + html.escape(cov["status"])
    + "; Codex review: "
    + html.escape(M["ai_review_status"])
    + ". No runtime reproduction.</p><p>Findings require developer triage. Persistent status lives in DefectDojo.</p><table><tr><th>Severity</th><th>Source</th><th>Finding</th></tr>"
    + rows
    + "</table>"
)
save(
    R / "normalized-artifact-hashes.json",
    {
        name: hashlib.sha256((R / name).read_bytes()).hexdigest()
        for name in [
            "findings.json",
            "dojo-import.json",
            "coverage.json",
            "manifest.json",
        ]
    },
)
print("Normalized", len(findings), "findings; report bundle:", R)
