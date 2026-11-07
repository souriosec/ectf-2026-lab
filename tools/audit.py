#!/usr/bin/env python3
"""Check Git-visible files for accidental private data before sharing."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = {
    "home path": re.compile(
        r"(?:/(?:home|Users)/[^/\s]+/|[A-Za-z]:[\\/]Users[\\/][^\\/\s]+)", re.I
    ),
    "private key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]"
    ),
    "API token": re.compile(
        r"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
    ),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}"),
    "probe serial": re.compile(r"\bML[0-9]{6}\b"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}
FORBIDDEN_PARTS = {
    "state",
    "runs",
    "backups",
    "upstream",
    "toolchain",
    "firmware",
    "ectf26_design",
}
FORBIDDEN_NAMES = {
    "auth.json",
    "board.local.json",
    "global.secrets",
    "secrets.h",
    "dashboard.token",
    "dashboard.env",
    "compile_commands.json",
}


def audit() -> list[str]:
    paths = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
        )
        .decode()
        .split("\0")
    )
    problems = []
    for relative in sorted(set(filter(None, paths))):
        path = ROOT / relative
        if (
            set(path.relative_to(ROOT).parts) & FORBIDDEN_PARTS
            or path.name in FORBIDDEN_NAMES
        ):
            problems.append(relative + ": private/runtime path")
            continue
        if path.is_symlink():
            problems.append(relative + ": symlink")
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            problems.append(relative + ": unexpected binary file")
            continue
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                if label == "email" and match.group().endswith("@example.invalid"):
                    continue
                problems.append(
                    relative
                    + ": "
                    + label
                    + " at line "
                    + str(text.count("\n", 0, match.start()) + 1)
                )
    return problems


if __name__ == "__main__":
    findings = audit()
    if findings:
        print("Sharing audit failed:\n" + "\n".join(findings))
        raise SystemExit(1)
    print(
        "Sharing audit passed for all Git-visible files. Review the staged diff before publishing."
    )
