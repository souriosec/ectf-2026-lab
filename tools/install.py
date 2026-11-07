#!/usr/bin/env python3
"""Install this tooling overlay into an existing, private 2026 CTF checkout."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parent.parent
EDITOR_FILES = (
    "ctf.py",
    "tasks.json",
    "extensions.json",
    "board.example.json",
    "settings.template.json",
    "launch.template.json",
)
LAB_FILES = (
    "lab.py",
    ".dockerignore",
    "config/versions.json",
    "config/finding-batch.schema.json",
    "images/Dockerfile.scanner",
    "images/Dockerfile.agent",
    "scripts/scan.py",
    "scripts/normalize.py",
    "scripts/publish.py",
    "scripts/review.py",
    "scripts/bootstrap.py",
    "prompts/review.md",
    "context/project.md",
    "dashboard/override.yaml",
)


def install(project: Path, *, update: bool = False, dry_run: bool = False) -> None:
    project = project.resolve()
    if project == TOOLKIT or not (project / "firmware/Makefile").is_file():
        raise ValueError(
            "Choose an existing 2026 CTF checkout containing firmware/Makefile"
        )
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=project, text=True
    ).strip()
    if Path(root).resolve() != project:
        raise ValueError("The project path must be the checkout root")
    for relative in [
        ".vscode/board.local.json",
        "analysis.LOCAL.me/state/dashboard.env",
    ]:
        result = subprocess.run(
            ["git", "check-ignore", "-q", relative], cwd=project, capture_output=True
        )
        if result.returncode:
            raise ValueError(
                "Before installing, ignore .vscode/ and analysis.LOCAL.me/ in the private checkout's .gitignore or local Git excludes"
            )
    pairs = [
        (TOOLKIT / ".vscode" / name, project / ".vscode" / name)
        for name in EDITOR_FILES
    ]
    pairs += [
        (TOOLKIT / "analysis" / name, project / "analysis.LOCAL.me" / name)
        for name in LAB_FILES
    ]
    for source, destination in pairs:
        if not source.is_file() or source.is_symlink():
            raise ValueError(
                "Missing or unsafe toolkit source: " + str(source.relative_to(TOOLKIT))
            )
        if (
            not destination.resolve().is_relative_to(project)
            or destination.is_symlink()
        ):
            raise ValueError("Refusing a symlinked installation path")
        if destination.exists() and not update:
            raise ValueError(
                "Existing tooling found; use --update to replace scripts/templates (local settings and credentials are preserved)"
            )
    for _, destination in pairs:
        print("Install", destination.relative_to(project))
    if dry_run:
        return
    for source, destination in pairs:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    board = project / ".vscode/board.local.json"
    if not board.exists():
        board.write_text((TOOLKIT / ".vscode/board.example.json").read_text())
        board.chmod(0o600)
    # Only generate editor files on initial installation; configure is an explicit refresh.
    if not any(
        (project / ".vscode" / name).exists()
        for name in ["settings.json", "launch.json"]
    ):
        subprocess.run(
            [sys.executable, str(project / ".vscode/ctf.py"), "configure"], check=True
        )
    print(
        "Installed. Edit .vscode/board.local.json, then run ctf.py configure in the private checkout."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        install(args.project, update=args.update, dry_run=args.dry_run)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
