# eCTF 2026 development lab

A reusable Ubuntu/WSL + VS Code setup for an existing 2026 eCTF firmware checkout: build and board helpers, containerized static analysis, optional Codex review, and a local DefectDojo findings dashboard. This repository contains tooling only. Bring your own authorized CTF checkout; firmware, credentials and scan results stay there.

## Install into your checkout

Use Ubuntu/WSL on x86-64, Python 3.12+, Git, Make, [uv](https://docs.astral.sh/uv/getting-started/installation/), and Docker with WSL integration and Compose 2.24.4+. Open the private checkout through VS Code's WSL extension. For editor support, install `clangd`; optional debugging also needs `gdb-multiarch` and an OpenOCD build supporting XDS110 and `target/ti/mspm0.cfg`.

From this toolkit clone:

```sh
python3 tools/install.py /path/to/private-ctf --dry-run
python3 tools/install.py /path/to/private-ctf
```

The destination must already ignore `.vscode/` and `analysis.LOCAL.me/`. The installer copies an explicit set of files and refuses existing tooling unless you pass `--update`; updates preserve local board settings, credentials and generated editor files. It never copies or edits firmware. Keep this toolkit clone separate for updates.

In the **private checkout**, edit `.vscode/board.local.json`: select your UART device under `/dev/serial/by-id/`, probe serial, practice PIN/permissions, and OpenOCD executable. The supplied `123456`/`1234=RWC` inputs are public practice examples. Then:

```sh
python3 .vscode/ctf.py configure
make docker
python3 .vscode/ctf.py build
python3 .vscode/ctf.py index
```

Firmware outputs are always `build/hsm.bin`, `build/hsm.elf` and `build/hsm.map`; intermediate objects stay in `build/objects/`. The build helper uses the documented `build-hsm` Docker flow directly, while `make docker` still creates the compiler image.

`configure` refreshes clangd paths and debugger settings from your local configuration. `index` extracts matching compiler/SDK files from `build-hsm` and generates the compilation database. VS Code recommends clangd and Cortex-Debug; Ctrl+Shift+B builds, while the task menu exposes flash/start, list and editor refresh. CLI commands also include `status` and `start`.

For hardware, attach USB to WSL and choose the current UART path. Flashing assumes the board already has the matching competition development bootloader. Enter update mode before `ctf.py flash`; this command **erases application flash**, programs the built image and starts it. Application commands such as `list` require running firmware instead. Close other serial clients first. F5 attaches to installed firmware through the optional debugger setup.

## Run static analysis

From the **private checkout**:

```sh
python3 analysis.LOCAL.me/lab.py build
python3 analysis.LOCAL.me/lab.py scan
python3 analysis.LOCAL.me/lab.py normalize
```

The scanner derives from your local `build-hsm` image, builds fresh ARM firmware with the project's TI compiler, then runs Cppcheck, Clang Static Analyzer, selected clang-tidy checks, and LLVM ELF/symbol/disassembly tools. Target assumptions match TI Arm LLVM 4.0.3.LTS / MSPM0 SDK 2.06.00.05; adapt the configuration if your project differs.

Runs contain a hashed source snapshot, synthetic build inputs, coverage, native diagnostics, concise finding reports, an HTML summary and dashboard import JSON. Existing global secrets are not used. Runs stay under the ignored `analysis.LOCAL.me/runs/`; they still contain private source. A run with incomplete tool coverage fails. Select an older run with `--run RUN_ID` on report/review commands. No firmware is executed on hardware or in an emulator.

## Optional AI review and findings dashboard

For Codex review, sign in with **your own account** after building the agent:

```sh
python3 analysis.LOCAL.me/lab.py build-agent
python3 analysis.LOCAL.me/lab.py agent-login
python3 analysis.LOCAL.me/lab.py review
```

`review --model MODEL` selects a model your account can use. Review sends source/evidence to the configured AI service, costs/account limits apply, and requires permission to process that source. Docker is the isolation boundary: source/root are read-only, capabilities are dropped, and the inner Codex sandbox is disabled for container compatibility. It reports candidates rather than changing firmware or opening issues. Schema, snapshot and exact source citations are checked before ingestion.

To track findings locally:

```sh
python3 analysis.LOCAL.me/lab.py init          # optional: --port 18080
python3 analysis.LOCAL.me/lab.py up
python3 analysis.LOCAL.me/lab.py credentials
python3 analysis.LOCAL.me/lab.py publish
python3 analysis.LOCAL.me/lab.py verify
```

`init` fetches a pinned public DefectDojo checkout and generates fresh local credentials; `up` starts it and provisions the importer token. Open the displayed loopback URL, then browse the imported test. `status`, `stop` and `backup` manage the local stack. Each installation has an isolated Compose project. Imports reuse stable finding IDs; candidates remain unverified until developer triage. Backups contain credentials/source and must stay private; restore is not automated. This dashboard configuration is for local use, not hosted production.

## Maintain or share the toolkit

From **this toolkit clone**, install the check tools with `uv tool install ruff==0.17.3` and `uv tool install ty==0.0.97`, then run:

```sh
ruff check .
ruff format --check
ty check .
python3 -m unittest discover -s analysis/tests -v
python3 -m unittest discover -s tests -v
python3 tools/audit.py
```

Project settings include the editor helper and maintained lab/scripts/tests while excluding generated/vendor trees. A partial type stub describes the container-only `jsonschema.validate` call for host-side checks. The audit flags likely credentials, personal paths and runtime files; inspect the staged diff too. Publish only this toolkit's source, never a private checkout, login state, run archive, board readback or dashboard backup.
