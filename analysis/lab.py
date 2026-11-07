#!/usr/bin/env python3
"""Local lab launcher. Run from Ubuntu/WSL; no host Python packages required."""

import argparse
import datetime
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
IMAGE = "ectf-lab-scanner:1"


def run(
    args: Sequence[str | Path],
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [str(arg) for arg in args]
    print("+ " + shlex.join(command), flush=True)
    return subprocess.run(command, check=True, cwd=cwd, text=True)


def compose_project() -> str:
    return "ectf-lab-" + hashlib.sha256(str(LAB.resolve()).encode()).hexdigest()[:10]


def dashboard_url() -> str:
    values = dict(
        line.split("=", 1)
        for line in (LAB / "state/dashboard.env").read_text().splitlines()
        if "=" in line
    )
    return "http://localhost:" + values["DD_PORT"]


def dojo(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker",
        "compose",
        "--project-name",
        compose_project(),
        "--env-file",
        LAB / "state/dashboard.env",
        "-f",
        LAB / "dashboard/upstream/docker-compose.yml",
        "-f",
        LAB / "dashboard/override.yaml",
        *args,
    ]
    return subprocess.run(
        list(map(str, cmd)), check=True, text=True, capture_output=capture
    )


def selected_run(value: str | None = None) -> Path:
    run_id = (
        value if value is not None else (LAB / "state/latest-run").read_text().strip()
    )
    if not run_id:
        raise ValueError("No run selected; run the scanner first or pass --run")
    destination = (LAB / "runs" / run_id).resolve()
    if destination.parent != (LAB / "runs").resolve() or not destination.is_dir():
        raise ValueError("Unknown run ID")
    return destination


def prepare() -> Path:
    now = datetime.datetime.now(datetime.UTC)
    rid = now.strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(3).hex()
    dest = LAB / "runs" / rid
    dest.mkdir(parents=True)
    snap = dest / "snapshot"
    snap.mkdir()
    inv = {}
    # Include active firmware tree and build inputs, excluding generated secrets, objects and vendored crypto.
    for src in sorted((ROOT / "firmware").rglob("*")):
        rel = src.relative_to(ROOT)
        if (
            not src.is_file()
            or src.is_symlink()
            or "wolfssl" in rel.parts
            or src.name == "secrets.h"
            or src.suffix in [".so", ".o", ".elf", ".bin", ".map", ".pyc"]
            or "__pycache__" in rel.parts
        ):
            continue
        data = src.read_bytes()
        q = snap / rel
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_bytes(data)
        inv[str(rel)] = hashlib.sha256(data).hexdigest()
    # Use the project's generator with explicitly synthetic input; never read existing global.secrets.
    synthetic = dest / "synthetic.secrets"
    synthetic.write_text("{}")
    run(
        [
            "python3",
            snap / "firmware/secrets_to_c_header.py",
            synthetic,
            "123456",
            "1234=RWC",
        ],
        cwd=snap / "firmware",
    )
    inv["firmware/inc/secrets.h"] = hashlib.sha256(
        (snap / "firmware/inc/secrets.h").read_bytes()
    ).hexdigest()
    snapshot_id = hashlib.sha256(json.dumps(inv, sort_keys=True).encode()).hexdigest()

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()

    refs = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/reference"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    manifest = {
        "schema_version": 1,
        "run_id": rid,
        "created_utc": now.isoformat(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "worktree_status": git("status", "--porcelain"),
        "reference_commit": refs.stdout.strip() if refs.returncode == 0 else None,
        "snapshot_id": snapshot_id,
        "synthetic_inputs": True,
        "configuration": {
            "pin": "123456",
            "permissions": "1234=RWC",
            "crypto_example": False,
        },
        "scanner_image": IMAGE,
        "scanner_image_id": subprocess.check_output(
            ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], text=True
        ).strip(),
        "firmware_modified": False,
        "ai_review_status": "pending",
        "analysis_config_hashes": {
            str(p.relative_to(LAB)): hashlib.sha256(p.read_bytes()).hexdigest()
            for d in ["scripts", "config", "prompts", "context"]
            for p in (LAB / d).rglob("*")
            if p.is_file()
        },
    }
    for name, v in [("manifest.json", manifest), ("source-inventory.json", inv)]:
        (dest / name).write_text(json.dumps(v, indent=2) + "\n")
    prior = {}
    for old in sorted((LAB / "runs").iterdir()):
        if old == dest or not (old / "findings.json").exists():
            continue
        meta = json.loads((old / "manifest.json").read_text())
        if meta.get("branch") != manifest["branch"]:
            continue
        for f in json.loads((old / "findings.json").read_text())["findings"]:
            prior[f["id"]] = {
                k: f[k] for k in ["id", "title", "summary", "locations", "tool"]
            }
    (dest / "prior-findings.json").write_text(
        json.dumps(list(prior.values()), indent=2) + "\n"
    )
    (LAB / "state").mkdir(exist_ok=True)
    (LAB / "state/latest-run").write_text(rid + "\n")
    return dest


def build_agent() -> None:
    run(
        [
            "docker",
            "build",
            "-t",
            "ectf-lab-agent:1",
            "-f",
            LAB / "images/Dockerfile.agent",
            LAB,
        ]
    )


def agent_login() -> None:
    (LAB / "state/codex").mkdir(parents=True, exist_ok=True)
    run(
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "HOME=/tmp",
            "-e",
            "CODEX_HOME=/state",
            "-v",
            str(LAB / "state/codex") + ":/state:rw",
            "ectf-lab-agent:1",
            "login",
            "--device-auth",
        ]
    )


def build_scanner() -> None:
    base_id = subprocess.check_output(
        ["docker", "image", "inspect", "build-hsm:latest", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    base = "ectf-lab-ti-base:" + base_id.split(":")[1][:12]
    run(["docker", "tag", base_id, base])
    run(
        [
            "docker",
            "build",
            "--build-arg",
            "TI_BASE=" + base,
            "-t",
            IMAGE,
            "-f",
            LAB / "images/Dockerfile.scanner",
            LAB,
        ]
    )


def backup() -> None:
    dest = (
        LAB / "backups" / datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    dest.mkdir(parents=True, mode=0o700)
    with (dest / "database.dump").open("wb") as stream:
        subprocess.run(
            [
                "docker",
                "exec",
                compose_project() + "-postgres-1",
                "pg_dump",
                "-U",
                "defectdojo",
                "-Fc",
                "defectdojo",
            ],
            stdout=stream,
            check=True,
        )
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            compose_project() + "_defectdojo_media:/media:ro",
            "-v",
            str(dest) + ":/backup:rw",
            "--entrypoint",
            "tar",
            IMAGE,
            "-cf",
            "/backup/media.tar",
            "-C",
            "/media",
            ".",
        ]
    )
    with tarfile.open(dest / "personal-lab.tar.gz", "w:gz") as archive:
        for name in [
            "lab.py",
            "images",
            "scripts",
            "config",
            "prompts",
            "context",
            "runs",
            "state/dashboard.env",
            "state/dashboard.token",
            "state/publisher",
            "dashboard/override.yaml",
        ]:
            archive.add(LAB / name, arcname=name)
    for p in dest.iterdir():
        p.chmod(0o600)
    print(
        "Private backup:",
        dest,
        "(includes dashboard credentials; excludes Codex login state)",
    )


def credentials() -> None:
    env = dict(
        line.split("=", 1)
        for line in (LAB / "state/dashboard.env").read_text().splitlines()
        if "=" in line
    )
    print(
        "Dashboard: "
        + dashboard_url()
        + "\nUsername: "
        + env["DD_ADMIN_USER"]
        + "\nPassword: "
        + env["DD_ADMIN_PASSWORD"]
    )


def scan() -> int:
    dest = prepare()
    print("Run:", dest.name, flush=True)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=3g",
        "--cpus=2",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,nosuid,size=512m",
        "-v",
        str(dest / "snapshot") + ":/workspace:ro",
        "-v",
        str(dest) + ":/results:rw",
        "-v",
        str(dest / "snapshot") + ":/results/snapshot:ro",
        IMAGE,
    ]
    code = subprocess.run(cmd).returncode
    m = json.loads((dest / "manifest.json").read_text())
    m["scanner_exit_code"] = code
    m["analysis_status"] = (
        json.loads((dest / "coverage.json").read_text()).get("status", "failed")
        if (dest / "coverage.json").exists()
        else "failed"
    )
    (dest / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
    print("Run:", dest.name, "scanner exit:", code)
    return code


def process_report(action: str, destination: Path, report: Path | None = None) -> None:
    """Run report processing with dashboard credentials confined to the publisher."""
    publishing = action in {"publish", "verify"}
    script = "publish.py" if publishing else "normalize.py"
    container_run = "/labdata/runs/" + destination.name
    command: list[str | Path] = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,size=64m",
    ]
    if publishing:
        command += [
            "-e",
            "DASHBOARD_URL=" + dashboard_url(),
            "--network",
            compose_project() + "_default",
            "-v",
            str(LAB / "state/publisher") + ":/labdata/state/publisher:rw",
            "-v",
            str(LAB / "state/dashboard.token") + ":/labdata/state/dashboard.token:ro",
        ]
    else:
        command.append("--network=none")
    command += [
        "-v",
        str(destination) + ":" + container_run + ":rw",
        "-v",
        str(destination / "snapshot") + ":" + container_run + "/snapshot:ro",
        "-v",
        str(LAB / "config") + ":/labdata/config:ro",
        "--entrypoint",
        "python3",
        IMAGE,
        "/lab/scripts/" + script,
        container_run,
        "/labdata",
        "ingest" if action == "ingest-review" else action,
    ]
    if action == "ingest-review":
        if report is None:
            raise ValueError("A review report is required")
        report = report.resolve()
        if not report.is_relative_to(destination) or not report.is_file():
            raise ValueError(
                "Place the review report inside the chosen run directory first"
            )
        command.append("/labdata/" + str(report.relative_to(LAB)))
    run(command)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subcommands = result.add_subparsers(dest="action", required=True)
    init = subcommands.add_parser("init")
    init.add_argument("--port", type=int)
    for action in [
        "build",
        "build-agent",
        "agent-login",
        "scan",
        "up",
        "stop",
        "status",
        "credentials",
        "backup",
    ]:
        subcommands.add_parser(action)
    for action in [
        "normalize",
        "publish",
        "verify",
        "review-context",
        "ingest-review",
        "review",
    ]:
        command = subcommands.add_parser(action)
        command.add_argument("--run")
        if action == "ingest-review":
            command.add_argument("report", type=Path)
        elif action == "review":
            command.add_argument("--model")
    return result


def main(argv: Sequence[str] | None = None) -> None:
    options = parser().parse_args(argv)
    action = options.action
    if not (ROOT / "firmware/Makefile").is_file():
        raise ValueError(
            "Install this tooling into a private CTF checkout first; runtime commands run there"
        )
    if action == "init":
        command = ["python3", LAB / "scripts/bootstrap.py", "init", LAB]
        if options.port is not None:
            command += ["--port", str(options.port)]
        run(command)
    elif action == "up":
        run(["python3", LAB / "scripts/bootstrap.py", "up", LAB])
    elif action == "build":
        build_scanner()
    elif action == "build-agent":
        build_agent()
    elif action == "agent-login":
        agent_login()
    elif action in {"stop", "status"}:
        dojo(*{"stop": ["stop"], "status": ["ps"]}[action])
    elif action == "backup":
        backup()
    elif action == "credentials":
        credentials()
    elif action == "scan":
        raise SystemExit(scan())
    else:
        destination = selected_run(options.run)
        if action == "review-context":
            print("Review snapshot:", destination / "snapshot")
            print("Evidence:", destination / "raw")
            print(
                "Snapshot ID:",
                json.loads((destination / "manifest.json").read_text())["snapshot_id"],
            )
            print("Prompt:", LAB / "prompts/review.md")
        elif action == "review":
            run(
                [
                    "python3",
                    LAB / "scripts/review.py",
                    destination,
                    LAB,
                    options.model or "",
                ]
            )
        else:
            process_report(action, destination, getattr(options, "report", None))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
