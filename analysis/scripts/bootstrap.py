"""Initialize fresh local state and a pinned, loopback-only findings dashboard."""

import argparse
import hashlib
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

UPSTREAM = "https://github.com/DefectDojo/django-DefectDojo.git"


def project_name(lab: Path) -> str:
    return "ectf-lab-" + hashlib.sha256(str(lab.resolve()).encode()).hexdigest()[:10]


def compose(lab: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            project_name(lab),
            "--env-file",
            str(lab / "state/dashboard.env"),
            "-f",
            str(lab / "dashboard/upstream/docker-compose.yml"),
            "-f",
            str(lab / "dashboard/override.yaml"),
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def initialize(lab: Path, port: int | None = None) -> None:
    if port is not None and not 1024 <= port <= 65535:
        raise ValueError("Choose an unprivileged port between 1024 and 65535")
    for directory in ["state", "state/codex", "state/publisher", "runs", "backups"]:
        path = lab / directory
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    environment = lab / "state/dashboard.env"
    if environment.exists():
        values = dict(
            line.split("=", 1)
            for line in environment.read_text().splitlines()
            if "=" in line
        )
        if port is not None and values.get("DD_PORT") != str(port):
            raise ValueError(
                "Dashboard already initialized on another port; edit the private state/dashboard.env if needed"
            )
    else:
        database_password = secrets.token_urlsafe(32)
        values = {
            "DD_ADMIN_USER": "admin",
            "DD_ADMIN_PASSWORD": secrets.token_urlsafe(32),
            "DD_ADMIN_MAIL": "admin@example.invalid",
            "DD_ADMIN_FIRST_NAME": "Local",
            "DD_ADMIN_LAST_NAME": "Developer",
            "DD_DATABASE_PASSWORD": database_password,
            "DD_DATABASE_URL": "postgresql://defectdojo:"
            + database_password
            + "@postgres:5432/defectdojo",
            "DD_SECRET_KEY": secrets.token_urlsafe(48),
            "DD_CREDENTIAL_AES_256_KEY": secrets.token_hex(16),
            "DD_ALLOWED_HOSTS": "localhost,127.0.0.1",
            "DD_PORT": str(port or 8080),
            "DD_IMAGE_REGISTRY": "docker.io",
        }
        with environment.open("x", encoding="utf-8") as stream:
            environment.chmod(0o600)
            stream.write(
                "".join(key + "=" + value + "\n" for key, value in values.items())
            )
    lock = json.loads((lab / "config/versions.json").read_text())
    upstream = lab / "dashboard/upstream"
    commit = lock["defectdojo_commit"]
    if not upstream.exists():
        subprocess.run(["git", "init", "-q", str(upstream)], check=True)
        subprocess.run(
            ["git", "-C", str(upstream), "remote", "add", "origin", UPSTREAM],
            check=True,
        )
    head = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    if head.returncode or head.stdout.strip() != commit:
        subprocess.run(
            ["git", "-C", str(upstream), "fetch", "--depth", "1", UPSTREAM, commit],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(upstream), "checkout", "--detach", commit], check=True
        )
    if subprocess.check_output(
        ["git", "-C", str(upstream), "status", "--porcelain"], text=True
    ).strip():
        raise ValueError(
            "The pinned upstream checkout has local changes; inspect them before starting the dashboard"
        )
    print("Initialized private state. Dashboard port:", values["DD_PORT"])


def start(lab: Path) -> None:
    environment = dict(
        line.split("=", 1)
        for line in (lab / "state/dashboard.env").read_text().splitlines()
        if "=" in line
    )
    print(
        "Starting dashboard; initial database migration can take several minutes.",
        flush=True,
    )
    compose(lab, "up", "-d", "--no-build")
    url = "http://localhost:" + environment["DD_PORT"]
    for _ in range(120):
        try:
            with urllib.request.urlopen(url + "/login", timeout=3) as response:
                if response.status == 200:
                    break
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError(
            "Dashboard did not become ready; use lab.py status and Docker Compose logs"
        )
    script = "from django.contrib.auth import get_user_model; from rest_framework.authtoken.models import Token; print(Token.objects.get_or_create(user=get_user_model().objects.get(username='admin'))[0].key)"
    token = (
        compose(
            lab, "exec", "-T", "uwsgi", "python", "manage.py", "shell", "-c", script
        )
        .stdout.strip()
        .splitlines()[-1]
    )
    if len(token) != 40 or any(char not in "0123456789abcdef" for char in token):
        raise RuntimeError("Dashboard returned an invalid API token")
    path = lab / "state/dashboard.token"
    with path.open("w", encoding="utf-8") as stream:
        path.chmod(0o600)
        stream.write(token + "\n")
    print("Dashboard ready:", url, "(use lab.py credentials for the local login)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "up"])
    parser.add_argument("lab", type=Path)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    try:
        if args.action == "init":
            initialize(args.lab.resolve(), args.port)
        else:
            start(args.lab.resolve())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
