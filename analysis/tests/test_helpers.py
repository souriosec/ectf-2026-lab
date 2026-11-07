"""Regression checks for local helpers; no Docker, network, or hardware required."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


lab = load("lab_helpers", ROOT / "analysis/lab.py")
ctf = load("ctf_helpers", ROOT / ".vscode/ctf.py")


class HelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.local = self.root / ".vscode"
        self.local.mkdir()
        self.lab = self.root / "analysis"
        self.lab.mkdir()
        for module, name, value in [
            (ctf, "ROOT", self.root),
            (ctf, "LOCAL", self.local),
            (lab, "ROOT", self.root),
            (lab, "LAB", self.lab),
        ]:
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config = ctf.BoardConfig("123456", "1234=RWC", "0x1234", "/dev/test")

    def test_help_without_board_config(self) -> None:
        with self.assertRaises(SystemExit) as result:
            ctf.main(["--help"])
        self.assertEqual(result.exception.code, 0)

    def test_runtime_requires_private_checkout(self) -> None:
        with patch.object(lab, "scan") as scan, self.assertRaises(ValueError):
            lab.main(["scan"])
        scan.assert_not_called()
        with (
            patch.object(ctf, "index") as index,
            self.assertRaises(SystemExit) as result,
        ):
            ctf.main(["index"])
        self.assertEqual(result.exception.code, 1)
        index.assert_not_called()

    def test_command_display_redacts_pin(self) -> None:
        self.assertNotIn(
            "654321", ctf.display_command(["docker", "-e", "HSM_PIN=654321"])
        )
        self.assertNotIn(
            "654321",
            ctf.display_command(
                ["uvx", "ectf", "tools", "/dev/test", "list", "654321"]
            ),
        )

    def test_board_config_validation(self) -> None:
        path = self.local / "board.local.json"
        for data in [[], {}, {"output": 3}]:
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                ctf.BoardConfig.load(path)
        path.write_text(json.dumps(vars(self.config)))
        self.assertEqual(ctf.BoardConfig.load(path), self.config)

    def test_output_is_fixed_and_rejects_symlink(self) -> None:
        self.assertEqual(ctf.output(), self.root / "build")
        (self.root / "target").mkdir()
        (self.root / "build").symlink_to(self.root / "target", target_is_directory=True)
        with self.assertRaises(ValueError):
            ctf.output()

    def test_build_fresh_objects_and_outputs(self) -> None:
        destination = self.root / "build"
        objects = destination / "objects"
        objects.mkdir(parents=True)
        (objects / "stale.so").write_text("old")
        (destination / "hsm.bin").write_text("old")
        (self.root / "global.secrets").write_text("keep private")

        def make(command, **kwargs):
            self.assertFalse((objects / "stale.so").exists())
            self.assertFalse((destination / "hsm.bin").exists())
            self.assertIn("/out/objects", command)
            self.assertIn(
                str(self.root / "global.secrets") + ":/secrets/global.secrets:ro",
                command,
            )
            self.assertIn(str(destination) + ":/out", command)
            for name in ["hsm.elf", "hsm.bin"]:
                (destination / name).write_text("fresh")
            (objects / "hsm.map").write_text("map")
            return subprocess.CompletedProcess(command, 0)

        with (
            patch.object(ctf, "require_docker"),
            patch.object(ctf, "run", side_effect=make),
        ):
            ctf.build(self.config)
        self.assertEqual((destination / "hsm.map").read_text(), "map")
        self.assertEqual((self.root / "global.secrets").read_text(), "keep private")

    def test_build_rejects_symlinked_objects(self) -> None:
        destination = self.root / "build"
        destination.mkdir()
        external = self.root / "external"
        external.mkdir()
        (destination / "objects").symlink_to(external, target_is_directory=True)
        (self.root / "global.secrets").write_text("{}")
        with patch.object(ctf, "require_docker"), self.assertRaises(ValueError):
            ctf.build(self.config)
        self.assertTrue(external.exists())

    def test_flash_requires_firmware_and_successful_status(self) -> None:
        with patch.object(ctf, "ectf") as hardware, self.assertRaises(RuntimeError):
            ctf.flash(self.config)
        hardware.assert_not_called()
        firmware = self.root / "build" / "hsm.bin"
        firmware.parent.mkdir()
        firmware.write_bytes(b"firmware")
        with (
            patch.object(
                ctf, "ectf", side_effect=subprocess.CalledProcessError(1, ["status"])
            ) as hardware,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            ctf.flash(self.config)
        hardware.assert_called_once_with("hw", "/dev/test", "status", timeout=8)
        with patch.object(ctf, "ectf") as hardware:
            ctf.flash(self.config)
        self.assertEqual(
            [call.args[2] for call in hardware.call_args_list],
            ["status", "erase", "flash", "start"],
        )

        self.assertEqual(
            hardware.call_args_list[2].args,
            ("hw", "/dev/test", "flash", self.root / "build/hsm.bin", "-n", "hsm"),
        )

    def test_index_remaps_compiler_paths(self) -> None:
        for name in ["sdk", "ti"]:
            (self.local / "toolchain" / name).mkdir(parents=True)
        command = f"{ctf.TI_COMPILER}/bin/tiarmclang -I{ctf.SDK}/source -c src/HSM.c -o /tmp/HSM.o"
        with (
            patch.object(ctf, "require_docker"),
            patch.object(
                ctf, "run", return_value=subprocess.CompletedProcess([], 0, command)
            ),
        ):
            ctf.index()
        database = json.loads((self.local / "compile_commands.json").read_text())
        self.assertEqual(len(database), 1)
        self.assertEqual(database[0]["file"], str(self.root / "firmware/src/HSM.c"))
        self.assertTrue(database[0]["arguments"][0].startswith(str(self.local)))

    def test_selected_run_rejects_empty_escape_and_symlink(self) -> None:
        (self.lab / "runs/good").mkdir(parents=True)
        (self.lab / "state").mkdir()
        (self.lab / "state/latest-run").write_text("good\n")
        self.assertEqual(lab.selected_run(), self.lab / "runs/good")
        (self.lab / "runs/escape").symlink_to(self.root, target_is_directory=True)
        for value in ["", "../state", "escape", "missing"]:
            with self.assertRaises(ValueError):
                lab.selected_run(value)

    def test_report_mounts_and_ingest_path(self) -> None:
        (self.lab / "state").mkdir()
        (self.lab / "state/dashboard.env").write_text("DD_PORT=8080\n")
        destination = self.lab / "runs/test"
        destination.mkdir(parents=True)
        for action in ["normalize", "publish", "verify"]:
            with patch.object(lab, "run") as execute:
                lab.process_report(action, destination)
            command = execute.call_args.args[0]
            self.assertIn("--read-only", command)
            self.assertIn(
                str(destination / "snapshot") + ":/labdata/runs/test/snapshot:ro",
                command,
            )
            has_token = any("dashboard.token:" in str(arg) for arg in command)
            self.assertEqual(has_token, action in {"publish", "verify"})
            self.assertEqual("--network=none" in command, action == "normalize")
        for report in [None, self.root / "outside.json", destination / "missing.json"]:
            with patch.object(lab, "run") as execute, self.assertRaises(ValueError):
                lab.process_report("ingest-review", destination, report)
            execute.assert_not_called()
        report = destination / "review.json"
        report.write_text("{}")
        with patch.object(lab, "run") as execute:
            lab.process_report("ingest-review", destination, report)
        self.assertEqual(
            execute.call_args.args[0][-2:], ["ingest", "/labdata/runs/test/review.json"]
        )

    def test_scan_failure_updates_manifest(self) -> None:
        destination = self.lab / "runs/test"
        destination.mkdir(parents=True)
        (destination / "manifest.json").write_text("{}")
        with (
            patch.object(lab, "prepare", return_value=destination),
            patch.object(
                lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 2)
            ),
        ):
            self.assertEqual(lab.scan(), 2)
        manifest = json.loads((destination / "manifest.json").read_text())
        self.assertEqual(manifest["scanner_exit_code"], 2)
        self.assertEqual(manifest["analysis_status"], "failed")


if __name__ == "__main__":
    unittest.main()
