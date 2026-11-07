"""Short-lived dashboard importer; credentials never enter scanner or agent jobs."""

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

R = Path(sys.argv[1])
LAB = Path(sys.argv[2])
ACTION = sys.argv[3]
TOKEN = (LAB / "state/dashboard.token").read_text().strip()
BASE = "http://nginx:8080/api/v2/"
PUBLIC_URL = os.environ.get("DASHBOARD_URL", "http://localhost:8080")


def api(path, method="GET", data=None, upload=None):
    headers = {"Authorization": "Token " + TOKEN, "Host": "localhost"}
    if upload is not None:
        if data is None:
            raise ValueError("Upload metadata is required")
        boundary = "ectf" + uuid.uuid4().hex
        parts = []
        for key, value in data.items():
            parts.append(
                (
                    "--"
                    + boundary
                    + '\r\nContent-Disposition: form-data; name="'
                    + key
                    + '"\r\n\r\n'
                    + str(value)
                    + "\r\n"
                ).encode()
            )
        parts.append(
            (
                "--"
                + boundary
                + '\r\nContent-Disposition: form-data; name="file"; filename="findings.json"\r\nContent-Type: application/json\r\n\r\n'
            ).encode()
            + upload
            + b"\r\n"
        )
        parts.append(("--" + boundary + "--\r\n").encode())
        body = b"".join(parts)
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    elif data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    else:
        body = None
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                BASE + path, data=body, headers=headers, method=method
            ),
            timeout=120,
        ) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Dashboard API " + str(e.code) + ": " + e.read().decode()[:1500]
        ) from None


m = json.loads((R / "manifest.json").read_text())
stream = m["branch"] + "|1234=RWC|full-static-v1"
key = __import__("hashlib").sha256(stream.encode()).hexdigest()[:16]
state = LAB / "state/publisher" / ("dojo-" + key + ".json")
if ACTION == "publish":
    checks = json.loads((R / "normalized-artifact-hashes.json").read_text())
    for name, digest in checks.items():
        if __import__("hashlib").sha256((R / name).read_bytes()).hexdigest() != digest:
            raise ValueError(
                "Normalized bundle changed; rerun normalize before publishing: " + name
            )

    fields = {
        "scan_type": "Generic Findings Import",
        "active": "true",
        "verified": "false",
        "close_old_findings": "false",
        "do_not_reactivate": "true",
        "minimum_severity": "Info",
        "scan_date": m["created_utc"][:10],
        "version": m["snapshot_id"][:12],
        "build_id": m["run_id"],
        "commit_hash": m["commit"],
        "branch_tag": m["branch"],
        "deduplication_on_engagement": "true",
    }
    if state.exists():
        fields["test"] = json.loads(state.read_text())["test_id"]
    else:
        fields.update(
            {
                "auto_create_context": "true",
                "product_type_name": "Embedded security",
                "product_name": "2026 eCTF lab",
                "engagement_name": "Local " + stream,
                "test_title": "Full static review " + stream,
            }
        )
    result = api(
        "reimport-scan/", "POST", fields, (R / "dojo-import.json").read_bytes()
    )
    (R / "dashboard-import.json").write_text(json.dumps(result, indent=2) + "\n")
    context = {k: result[k] for k in ["test_id", "engagement_id", "product_id"]}
    context["stream"] = stream
    state.write_text(json.dumps(context, indent=2) + "\n")
    print("Dashboard import:", json.dumps(context))
    print("Statistics:", json.dumps(result.get("statistics", {})))
elif ACTION == "verify":
    context = json.loads(state.read_text())
    data = api("findings/?test=" + str(context["test_id"]) + "&limit=1000")
    expected = json.loads((R / "findings.json").read_text())["findings"]
    got = {x["unique_id_from_tool"]: x for x in data["results"]}
    if len(got) != data["count"]:
        raise RuntimeError(
            "Duplicate finding fingerprints or incomplete pagination in dashboard stream"
        )
    missing = [f["id"] for f in expected if f["fingerprint"] not in got]
    if missing:
        raise RuntimeError("Missing dashboard findings: " + str(missing))
    report = {
        "run_id": m["run_id"],
        "expected_findings": len(expected),
        "dashboard_count": data["count"],
        "all_expected_present": not missing,
        "findings": [
            {
                "id": x["id"],
                "title": x["title"],
                "active": x["active"],
                "verified": x["verified"],
                "url": PUBLIC_URL + "/finding/" + str(x["id"]),
            }
            for x in data["results"]
        ],
    }
    (R / "dashboard-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
else:
    raise ValueError("Unknown action")
