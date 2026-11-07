"""Offline scanner, invoked inside the pinned TI-derived image."""

import hashlib
import json
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path
from typing import NotRequired, TypedDict


class CompilerCommand(TypedDict):
    directory: str
    file: str
    arguments: list[str]


class ExecutionResult(TypedDict):
    exit_code: int | None
    duration_seconds: NotRequired[float]
    log: NotRequired[str]
    file: NotRequired[str]
    reason: NotRequired[str]


class CppcheckResult(TypedDict):
    exit_code: int
    log: str
    duration_seconds: NotRequired[float]
    expected: NotRequired[list[str]]
    attempted: NotRequired[list[str]]
    successful: NotRequired[list[str]]
    parse_errors: NotRequired[list[dict[str, str]]]
    status: NotRequired[str]
    diagnostics: NotRequired[int]
    error: NotRequired[str]


R = Path("/results")
W = Path("/workspace")
F = W / "firmware"
for d in ["raw", "build", "raw/clang"]:
    (R / d).mkdir(parents=True, exist_ok=True)


def execute(
    args: Sequence[str], log: str, cwd: Path = F, timeout: int = 180
) -> ExecutionResult:
    started = time.time()
    try:
        p = subprocess.run(
            args,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        code = p.returncode
        output = p.stdout
    except subprocess.TimeoutExpired as exc:
        code = 124
        output = (
            (exc.stdout or b"").decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        output += "\nANALYSIS TIMEOUT\n"
    (R / log).write_text(output)
    return {
        "exit_code": code,
        "duration_seconds": round(time.time() - started, 2),
        "log": log,
    }


def save(name, value):
    (R / name).write_text(json.dumps(value, indent=2) + "\n")


coverage = {
    "schema_version": 1,
    "tools": {},
    "exclusions": {
        "firmware/src/simple_crypto.c": "CRYPTO_EXAMPLE=0; not compiled",
        "vendor_libraries": "precompiled TI libraries; no source analysis coverage",
    },
}
build = execute(["make", "-B", "BUILDDIR=/results/build"], "raw/build.log")
coverage["build"] = build
if build["exit_code"] or not all(
    (R / "build" / n).is_file() for n in ["hsm.elf", "hsm.bin", "hsm.map"]
):
    save("coverage.json", coverage)
    raise SystemExit("Fresh TI build failed; see raw/build.log")
p = subprocess.run(
    ["make", "-Bn", "BUILDDIR=/results/build"],
    cwd=F,
    text=True,
    capture_output=True,
    check=True,
)
commands: list[CompilerCommand] = []
for line in p.stdout.splitlines():
    a = shlex.split(line)
    if a and a[0].endswith("/tiarmclang") and "-c" in a:
        src = a[a.index("-c") + 1]
        commands.append(
            {"directory": str(F), "file": str((F / src).resolve()), "arguments": a}
        )
assert commands, "No compiler commands captured"
save("compile_commands.ti.json", commands)
expected = [str(Path(c["file"]).relative_to(W)) for c in commands]
versions = {}
for tool, args in {
    "ti": ["/opt/ti-cgt-armllvm_4.0.3.LTS/bin/tiarmclang", "--version"],
    "cppcheck": ["cppcheck", "--version"],
    "clang": ["clang-18", "--version"],
    "clang_tidy": ["clang-tidy-18", "--version"],
}.items():
    versions[tool] = subprocess.check_output(args, text=True).strip()
versions["packages"] = subprocess.check_output(
    ["dpkg-query", "-W", "cppcheck", "clang-18", "clang-tidy-18", "llvm-18"], text=True
)
save("tool-versions.json", versions)
# Derive target fundamental type facts from the authoritative compiler.
macros = subprocess.run(
    [
        commands[0]["arguments"][0],
        "-mcpu=cortex-m0plus",
        "-mthumb",
        "-dM",
        "-E",
        "-x",
        "c",
        "-",
    ],
    input="",
    text=True,
    capture_output=True,
    check=True,
).stdout
(R / "raw/ti-predefines.txt").write_text(macros)
md = {
    macro_line.split()[1]: " ".join(macro_line.split()[2:])
    for macro_line in macros.splitlines()
    if macro_line.startswith("#define ")
}
sizes = {
    "short": md["__SIZEOF_SHORT__"],
    "int": md["__SIZEOF_INT__"],
    "long": md["__SIZEOF_LONG__"],
    "long-long": md["__SIZEOF_LONG_LONG__"],
    "float": md["__SIZEOF_FLOAT__"],
    "double": md["__SIZEOF_DOUBLE__"],
    "long-double": md["__SIZEOF_LONG_DOUBLE__"],
    "pointer": md["__SIZEOF_POINTER__"],
    "size_t": md["__SIZEOF_SIZE_T__"],
    "wchar_t": md["__SIZEOF_WCHAR_T__"],
}
platform = (
    "<platform><char_bit>8</char_bit><default-sign>"
    + ("unsigned" if "__CHAR_UNSIGNED__" in md else "signed")
    + "</default-sign><sizeof>"
    + "".join("<" + k + ">" + v + "</" + k + ">" for k, v in sizes.items())
    + "</sizeof></platform>"
)
(R / "target-platform.xml").write_text(platform)
# Use project macros/includes but let cppcheck model the C library rather than parsing compiler internals.
cppargs = [
    "cppcheck",
    "--project=/results/compile_commands.ti.json",
    "--platform=/results/target-platform.xml",
    "--enable=warning,performance,portability",
    "--inconclusive",
    "--xml",
    "--xml-version=2",
    "--check-level=exhaustive",
    "-D__GNUC__=4",
    "-D__GNUC_MINOR__=2",
    "-D__ARM_ARCH_6M__=1",
    "-D__ARM_ARCH=6",
    "--suppress=missingIncludeSystem",
    "--error-exitcode=0",
]
started = time.time()
try:
    cp = subprocess.run(cppargs, cwd=F, text=True, capture_output=True, timeout=240)
    (R / "raw/cppcheck.progress.log").write_text(cp.stdout)
    (R / "raw/cppcheck.log").write_text(cp.stderr)
    cpp: CppcheckResult = {
        "exit_code": cp.returncode,
        "duration_seconds": round(time.time() - started, 2),
        "log": "raw/cppcheck.log",
    }
except subprocess.TimeoutExpired:
    (R / "raw/cppcheck.log").write_text("Cppcheck timed out")
    cpp = {"exit_code": 124, "log": "raw/cppcheck.log"}
# Cppcheck XML is stderr mixed with progress in this log; preserve both and extract XML.
cpptxt = (R / "raw/cppcheck.log").read_text()
start = cpptxt.find("<?xml")
end = cpptxt.rfind("</results>")
cpp["expected"] = expected
cpp["attempted"] = expected
if start >= 0 and end >= 0:
    xml = cpptxt[start : end + 10]
    (R / "raw/cppcheck.xml").write_text(xml)
    try:
        root = ET.fromstring(xml)
        errs = root.findall("./errors/error")
        parseerrors = [
            e.attrib
            for e in errs
            if e.get("id")
            in [
                "syntaxError",
                "internalAstError",
                "preprocessorErrorDirective",
                "internalError",
            ]
        ]
        cpp["parse_errors"] = parseerrors
        cpp["status"] = (
            "complete" if cpp["exit_code"] == 0 and not parseerrors else "partial"
        )
        cpp["successful"] = expected if cpp["status"] == "complete" else []
        cpp["diagnostics"] = len(errs)
    except ET.ParseError as exc:
        cpp.update(status="failed", error=str(exc), successful=[])
else:
    cpp.update(status="failed", error="No complete XML result", successful=[])
coverage["tools"]["cppcheck"] = cpp
# Stock LLVM parses the ARM source using TI C-library headers and its own ARM intrinsics.
clang_db: list[CompilerCommand] = []
syntax: list[ExecutionResult] = []
analyzer: list[ExecutionResult] = []
tidy: list[ExecutionResult] = []
for c in commands:
    args = c["arguments"][1:]
    src = c["file"]
    rel = str(Path(src).relative_to(W))
    base = []
    i = 0
    while i < len(args):
        if args[i] in ["-o", "-c"]:
            i += 2
            continue
        if args[i].startswith("-gdwarf"):
            i += 1
            continue
        base.append(args[i])
        i += 1
    base = [
        "--target=arm-ti-none-eabi",
        "-fshort-enums",
        "-funsigned-char",
        "-Wno-error=implicit-function-declaration",
        "-isystem",
        "/opt/ti-cgt-armllvm_4.0.3.LTS/include/c",
        *base,
    ]
    clang_db.append(
        {
            "directory": str(F),
            "file": src,
            "arguments": ["clang-18", *base, "-c", src],
        }
    )
    name = Path(src).stem
    a = execute(
        ["clang-18", *base, "-fsyntax-only", src], f"raw/clang/{name}.syntax.log"
    )
    a["file"] = rel
    syntax.append(a)
    if a["exit_code"] == 0:
        b = execute(
            [
                "clang-18",
                *base,
                "--analyze",
                "-Xanalyzer",
                "-analyzer-output=plist",
                "-o",
                str(R / f"raw/clang/{name}.plist"),
                src,
            ],
            f"raw/clang/{name}.analyzer.log",
        )
        b["file"] = rel
        analyzer.append(b)
    else:
        analyzer.append(
            {"file": rel, "exit_code": None, "reason": "syntax gate failed"}
        )
save("compile_commands.clang.json", clang_db)
# clang-tidy expects this filename in its build database directory.
(R / "tidy-db").mkdir(exist_ok=True)
save("tidy-db/compile_commands.json", clang_db)
for c in clang_db:
    src = c["file"]
    rel = str(Path(src).relative_to(W))
    name = Path(src).stem
    if next(x for x in syntax if x["file"] == rel)["exit_code"] == 0:
        x = execute(
            [
                "clang-tidy-18",
                "-p=/results/tidy-db",
                "--checks=-*,bugprone-sizeof-expression,bugprone-suspicious-memset-usage,bugprone-argument-comment,cert-err33-c",
                src,
            ],
            f"raw/clang/{name}.tidy.log",
        )
        x["file"] = rel
        tidy.append(x)
    else:
        tidy.append({"file": rel, "exit_code": None, "reason": "syntax gate failed"})
for name, rows in [
    ("clang_syntax", syntax),
    ("clang_analyzer", analyzer),
    ("clang_tidy", tidy),
]:
    ok = [a["file"] for a in rows if a["exit_code"] == 0]
    coverage["tools"][name] = {
        "status": "complete" if len(ok) == len(expected) else "partial",
        "expected": expected,
        "successful": ok,
        "results": rows,
    }
for name, args in {
    "sections": ["llvm-size-18", "-A", str(R / "build/hsm.elf")],
    "symbols": ["llvm-nm-18", "--print-size", "--size-sort", str(R / "build/hsm.elf")],
    "disassembly": ["llvm-objdump-18", "-d", "--source", str(R / "build/hsm.elf")],
    "elf_headers": ["llvm-readelf-18", "-h", "-S", str(R / "build/hsm.elf")],
}.items():
    coverage["tools"][name] = execute(args, "raw/" + name + ".txt")
coverage["status"] = (
    "complete"
    if cpp["status"] == "complete"
    and all(
        coverage["tools"][n]["status"] == "complete"
        for n in ["clang_syntax", "clang_analyzer", "clang_tidy"]
    )
    and all(
        coverage["tools"][n]["exit_code"] == 0
        for n in ["sections", "symbols", "disassembly", "elf_headers"]
    )
    else "partial"
)
save("coverage.json", coverage)
save(
    "artifact-hashes.json",
    {
        str(p.relative_to(R)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (R / "build").glob("hsm.*")
        if p.is_file()
    },
)
print(
    json.dumps(
        {
            "status": coverage["status"],
            "translation_units": len(expected),
            "cppcheck": cpp.get("status"),
            "clang_parsed": len(coverage["tools"]["clang_syntax"]["successful"]),
        },
        indent=2,
    )
)
# Partial coverage remains visible; scanner configuration/execution failures fail the command.
raise SystemExit(0 if coverage["status"] == "complete" else 2)
