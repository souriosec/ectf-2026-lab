"""Model-backed review with Docker as the isolation boundary and fail-closed reporting."""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

R = Path(sys.argv[1]).resolve()
LAB = Path(sys.argv[2]).resolve()
model = sys.argv[3] if len(sys.argv) > 3 else ""
name = "ectf-review-" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d%H%M%S")
out = R / "review-attempts" / name
out.mkdir(parents=True)
prior = R / "prior-findings.json"
if not prior.exists():
    old = (
        json.loads((R / "findings.json").read_text())["findings"]
        if (R / "findings.json").exists()
        else []
    )
    prior.write_text(
        json.dumps(
            [
                {k: f[k] for k in ["id", "title", "summary", "locations", "tool"]}
                for f in old
            ],
            indent=2,
        )
        + "\n"
    )
cmd = [
    "docker",
    "run",
    "--rm",
    "--name",
    name,
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=256",
    "--memory=2g",
    "--user",
    f"{os.getuid()}:{os.getgid()}",
    "--tmpfs",
    "/tmp:rw,size=256m",
    "-e",
    "CODEX_HOME=/state",
    "-e",
    "HOME=/tmp",
    "-v",
    str(LAB / "state/codex") + ":/state:rw",
    "-v",
    str(R / "snapshot") + ":/workspace:ro",
    "-v",
    str(out) + ":/results:rw",
    "-v",
    str(R / "raw") + ":/evidence:ro",
    "-v",
    str(R / "manifest.json") + ":/run/manifest.json:ro",
    "-v",
    str(prior) + ":/run/prior-findings.json:ro",
    "-v",
    str(LAB / "config") + ":/config:ro",
    "-v",
    str(LAB / "prompts") + ":/prompts:ro",
    "-v",
    str(LAB / "context") + ":/context:ro",
    "-w",
    "/workspace",
    "ectf-lab-agent:1",
    "exec",
    "--skip-git-repo-check",
    "--sandbox",
    "danger-full-access",
    "--json",
    "--output-schema",
    "/config/finding-batch.schema.json",
    "--output-last-message",
    "/results/findings.json",
]
if model:
    cmd += ["--model", model]
cmd += [
    "Read /prompts/review.md and /context/project.md. Review the C firmware under /workspace. Run metadata is /run/manifest.json, prior root-cause IDs are /run/prior-findings.json, and scanner evidence is /evidence. This is an isolated container: source and context are read-only. Do not edit source or access hardware. Reuse prior IDs for the same root causes; cite current source. Read the active source files, especially HSM.c, security.c, commands.c, host_messaging.c, filesystem.c, and simple_flash.c. Return only the schema-conforming finding batch. Record honest coverage and limitations."
]
print("Review attempt:", out, flush=True)
with (out / "events.jsonl").open("w") as events, (out / "stderr.log").open("w") as err:
    try:
        code = subprocess.run(cmd, stdout=events, stderr=err, timeout=300).returncode
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "stop", "-t", "2", name], capture_output=True)
        code = 124
fail = []
successful_commands = 0
for line in (out / "events.jsonl").read_text().splitlines():
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        fail.append("Invalid JSONL event")
        continue
    if e.get("type") in ["turn.failed", "error"]:
        fail.append("Model turn failed")
    item = e.get("item", {})
    if item.get("type") == "command_execution" and e.get("type") == "item.completed":
        text = item.get("aggregated_output", "")
        if item.get("exit_code") == 0:
            successful_commands += 1
        if any(
            s in text
            for s in [
                "bwrap: No permissions",
                "No permissions to create new namespace",
                "command not found",
            ]
        ):
            fail.append("Review tool/environment failure")
if code:
    fail.append("CLI exit " + str(code))
if successful_commands == 0:
    fail.append("No successful source-inspection commands")
if not (out / "findings.json").exists():
    fail.append("Missing structured report")
if not fail:
    b = json.loads((out / "findings.json").read_text())
    if not b.get("reviewed_files"):
        fail.append("Empty review scope")
    if (
        b.get("snapshot_id")
        != json.loads((R / "manifest.json").read_text())["snapshot_id"]
    ):
        fail.append("Wrong snapshot")
    if any(
        s in " ".join(b.get("limitations", [])).lower()
        for s in [
            "could not be completed",
            "could not read",
            "unable to read",
            "sandbox could not",
        ]
    ):
        fail.append("Report admits blocked source inspection")
status = {
    "exit_code": code,
    "successful_inspection_commands": successful_commands,
    "failures": fail,
    "status": "failed" if fail else "completed",
    "report": str(out / "findings.json"),
}
(out / "verification.json").write_text(json.dumps(status, indent=2) + "\n")
print(json.dumps(status, indent=2), flush=True)
if fail:
    sys.exit(1)
# Normalizer checks schema, snapshot integrity and exact citations before replacing the accepted report.
subprocess.run(
    [
        "python3",
        str(LAB / "lab.py"),
        "ingest-review",
        str(out / "findings.json"),
        "--run",
        R.name,
    ],
    check=True,
)
