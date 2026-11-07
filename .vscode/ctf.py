"""Local WSL convenience commands; team Makefiles remain authoritative."""

import argparse
import json
import os
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / ".vscode"
ECTF_PACKAGE = "ectf==2026.0.11"
SDK = "/opt/mspm0-sdk-mspm0_sdk_2_06_00_05"
TI_COMPILER = "/opt/ti-cgt-armllvm_4.0.3.LTS"


@dataclass(frozen=True)
class BoardConfig:
    pin: str
    permissions: str
    groups: str
    port: str
    probe: str = ""
    openocd: str = "openocd"

    @classmethod
    def load(cls, path: Path) -> "BoardConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        fields = ("pin", "permissions", "groups", "port")
        if not isinstance(data, dict) or any(
            not isinstance(data.get(field), str) or not data[field].strip()
            for field in fields
        ):
            raise ValueError(
                f"{path.name} requires nonempty strings: {', '.join(fields)}"
            )
        for optional in ["probe", "openocd"]:
            if optional in data and not isinstance(data[optional], str):
                raise ValueError(f"{optional} must be a string")
        return cls(
            *(data[field] for field in fields),
            probe=data.get("probe", ""),
            openocd=data.get("openocd", "openocd"),
        )


def run(
    args: Sequence[str | Path],
    *,
    capture_output: bool = False,
    stdout: int | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [str(arg) for arg in args]
    print("+", display_command(command), flush=True)
    environment = os.environ.copy()
    environment["PATH"] = (
        str(Path.home() / ".local/bin") + os.pathsep + environment.get("PATH", "")
    )
    return subprocess.run(
        command,
        check=True,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=capture_output,
        stdout=stdout,
        timeout=timeout,
    )


def ectf(*args: str | Path, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(["uvx", "--from", ECTF_PACKAGE, "ectf", *args], timeout=timeout)


def output() -> Path:
    destination = ROOT / "build"
    if destination.is_symlink():
        raise ValueError("Refusing symlinked build output directory")
    return destination


def require_docker() -> None:
    socket = Path("/var/run/docker.sock")
    if socket.exists() and not os.access(socket, os.R_OK | os.W_OK):
        raise RuntimeError(
            "This process cannot access /var/run/docker.sock. If terminal builds work, "
            "the VS Code WSL server has stale Linux group membership. Restart the "
            "Ubuntu WSL session and reopen this repo; do not run the task with sudo."
        )


def build(config: BoardConfig) -> None:
    require_docker()
    destination = output()
    if not (ROOT / "global.secrets").exists():
        run(["make", "global.secrets", "GROUPS=" + config.groups])
    destination.mkdir(exist_ok=True)
    # Fresh objects ensure generated PIN/permission header changes take effect.
    objects = destination / "objects"
    if objects.is_symlink():
        raise ValueError("Refusing symlinked build directory")
    if objects.exists():
        shutil.rmtree(objects)
    objects.mkdir()
    for name in ["hsm.elf", "hsm.bin"]:
        (destination / name).unlink(missing_ok=True)
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            str(ROOT / "firmware") + ":/hsm",
            "-v",
            str(ROOT / "global.secrets") + ":/secrets/global.secrets:ro",
            "-v",
            str(destination) + ":/out",
            "-e",
            "HSM_PIN=" + config.pin,
            "-e",
            "PERMISSIONS=" + config.permissions,
            "build-hsm",
            "/out/objects",
        ]
    )
    for name in ["hsm.elf", "hsm.bin", "objects/hsm.map"]:
        artifact = destination / name
        if not artifact.is_file() or artifact.stat().st_size == 0:
            raise RuntimeError("Missing fresh build artifact: " + name)
    shutil.copy2(objects / "hsm.map", destination / "hsm.map")
    print("Build successful: " + str(destination / "hsm.elf"), flush=True)


def index() -> None:
    require_docker()
    cache = LOCAL / "toolchain"
    cache.mkdir(exist_ok=True)
    if not (cache / "sdk").exists() or not (cache / "ti").exists():
        container = run(
            ["docker", "create", "--entrypoint", "true", "build-hsm"],
            capture_output=True,
        ).stdout.strip()
        try:
            for source, name in [(SDK, "sdk"), (TI_COMPILER, "ti")]:
                if not (cache / name).exists():
                    run(["docker", "cp", container + ":" + source, cache / name])
        finally:
            run(["docker", "rm", container], stdout=subprocess.DEVNULL)
    dry_run = run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "make",
            "-v",
            str(ROOT / "firmware") + ":/hsm",
            "build-hsm",
            "-Bn",
            "BUILDDIR=/tmp/build",
        ],
        capture_output=True,
    ).stdout
    commands: list[dict[str, str | list[str]]] = []
    for line in dry_run.splitlines():
        arguments = shlex.split(line)
        if (
            not arguments
            or not arguments[0].endswith("/tiarmclang")
            or "-c" not in arguments
        ):
            continue
        arguments = [
            arg.replace(SDK, str(cache / "sdk")).replace(TI_COMPILER, str(cache / "ti"))
            for arg in arguments
        ]
        source = arguments[arguments.index("-c") + 1]
        commands.append(
            {
                "directory": str(ROOT / "firmware"),
                "file": str((ROOT / "firmware" / source).resolve()),
                "arguments": arguments,
            }
        )
    if not commands:
        raise RuntimeError("No actual compiler invocations captured")
    (LOCAL / "compile_commands.json").write_text(
        json.dumps(commands, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Exported",
        len(commands),
        "compiler commands and matching header/toolchain paths.",
    )


def flash(config: BoardConfig) -> None:
    firmware = output() / "hsm.bin"
    if not firmware.is_file() or firmware.stat().st_size == 0:
        raise RuntimeError("Build first")
    print("Board must be in MITRE update mode (hold S1, tap reset).", flush=True)
    ectf("hw", config.port, "status", timeout=8)
    ectf("hw", config.port, "erase")
    ectf("hw", config.port, "flash", firmware, "-n", "hsm", timeout=120)
    ectf("hw", config.port, "start")


def configure(config: BoardConfig) -> None:
    """Refresh generated editor paths, preserving unrelated settings/configurations."""
    settings = json.loads((LOCAL / "settings.template.json").read_text())
    settings["clangd.arguments"] = [
        argument.replace("@PROJECT@", str(ROOT))
        for argument in settings["clangd.arguments"]
    ]
    settings_path = LOCAL / "settings.json"
    existing = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    existing.update(settings)
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    launch = json.loads((LOCAL / "launch.template.json").read_text())
    attach = launch["configurations"][0]
    attach["serverpath"] = config.openocd
    attach["executable"] = "${workspaceFolder}/build/hsm.elf"
    attach["openOCDLaunchCommands"][0] = "adapter serial " + config.probe
    launch_path = LOCAL / "launch.json"
    if launch_path.exists():
        launch = json.loads(launch_path.read_text())
        launch["configurations"] = [
            item
            for item in launch.get("configurations", [])
            if item.get("name") != attach["name"]
        ] + [attach]
    launch_path.write_text(json.dumps(launch, indent=2) + "\n")
    print("Updated editor paths and debugger configuration from board.local.json.")


def display_command(command: Sequence[str]) -> str:
    """Redact PIN arguments in the wrapper's own command/error messages."""
    safe = [
        "HSM_PIN=<redacted>" if arg.startswith("HSM_PIN=") else arg for arg in command
    ]
    if "ectf" in safe and "list" in safe:
        position = safe.index("list") + 1
        if position < len(safe):
            safe[position] = "<redacted>"
    return shlex.join(safe)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["build", "flash", "list", "index", "status", "start", "configure"],
    )
    action = parser.parse_args(argv).action
    try:
        if not (ROOT / "firmware/Makefile").is_file():
            raise ValueError(
                "Install this tooling into a private CTF checkout first; board commands run there"
            )
        if action == "index":
            index()
            return
        config = BoardConfig.load(LOCAL / "board.local.json")
        if action == "configure":
            configure(config)
        elif action == "build":
            build(config)
        elif action == "flash":
            flash(config)
        elif action == "list":
            ectf("tools", config.port, "list", config.pin, timeout=15)
        else:
            ectf("hw", config.port, action, timeout=8)
    except subprocess.TimeoutExpired:
        parser.exit(
            1,
            "Timed out: check update/application mode, UART ownership, and selected board.\n",
        )
    except subprocess.CalledProcessError as exc:
        parser.exit(
            exc.returncode,
            f"Command failed (exit {exc.returncode}): {display_command(list(map(str, exc.cmd)))}\nSee the command output above for the underlying error.\n",
        )
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
