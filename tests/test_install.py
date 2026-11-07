"""Installer and fresh-state tests; hardware, Docker, and network are not used."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load(ROOT / "tools/install.py")
bootstrap = load(ROOT / "analysis/scripts/bootstrap.py")


class InstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name) / "private"
        (self.project / "firmware").mkdir(parents=True)
        (self.project / "firmware/Makefile").write_text("# fixture\n")
        subprocess.run(["git", "init", "-q", str(self.project)], check=True)
        (self.project / ".gitignore").write_text(".vscode/\nanalysis.LOCAL.me/\n")

    def test_dry_run_and_install(self) -> None:
        installer.install(self.project, dry_run=True)
        self.assertFalse((self.project / ".vscode").exists())
        installer.install(self.project)
        for name in installer.LAB_FILES:
            self.assertTrue((self.project / "analysis.LOCAL.me" / name).is_file())
        self.assertFalse((self.project / "analysis.LOCAL.me/state").exists())
        settings = json.loads((self.project / ".vscode/settings.json").read_text())
        self.assertIn(str(self.project), settings["clangd.arguments"][1])
        self.assertEqual(
            (self.project / "firmware/Makefile").read_text(), "# fixture\n"
        )

    def test_refuses_conflict_and_preserves_local_settings_on_update(self) -> None:
        installer.install(self.project)
        board = self.project / ".vscode/board.local.json"
        board.write_text('{"local_setting": true}')
        settings = self.project / ".vscode/settings.json"
        settings.write_text('{"editor.tabSize": 2}')
        state = self.project / "analysis.LOCAL.me/state"
        state.mkdir()
        (state / "dashboard.token").write_text("fixture-token")
        with self.assertRaises(ValueError):
            installer.install(self.project)
        installer.install(self.project, update=True)
        self.assertEqual(json.loads(board.read_text()), {"local_setting": True})
        self.assertEqual(json.loads(settings.read_text()), {"editor.tabSize": 2})
        self.assertEqual((state / "dashboard.token").read_text(), "fixture-token")

    def test_requires_ignored_private_paths(self) -> None:
        (self.project / ".gitignore").write_text("")
        with self.assertRaises(ValueError):
            installer.install(self.project)
        self.assertFalse((self.project / ".vscode").exists())

    def test_refuses_installation_through_symlink(self) -> None:
        outside = self.project.parent / "outside"
        outside.mkdir()
        (self.project / ".vscode").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(self.project)
        self.assertEqual(list(outside.iterdir()), [])

    def test_initialization_is_fresh_private_and_idempotent(self) -> None:
        lab = self.project / "lab"
        (lab / "config").mkdir(parents=True)
        (lab / "config/versions.json").write_text(
            json.dumps({"defectdojo_commit": "fixture-commit"})
        )
        (lab / "dashboard/upstream").mkdir(parents=True)
        with (
            patch.object(
                bootstrap.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "fixture-commit\n"),
            ),
            patch.object(bootstrap.subprocess, "check_output", return_value=""),
        ):
            bootstrap.initialize(lab, 18080)
            environment = lab / "state/dashboard.env"
            first = environment.read_text()
            bootstrap.initialize(lab, 18080)
            self.assertEqual(environment.read_text(), first)
            with self.assertRaises(ValueError):
                bootstrap.initialize(lab, 18081)
        self.assertEqual(environment.stat().st_mode & 0o777, 0o600)
        self.assertIn("DD_PORT=18080", first)
        values = dict(line.split("=", 1) for line in first.splitlines())
        self.assertNotEqual(values["DD_ADMIN_PASSWORD"], values["DD_DATABASE_PASSWORD"])
        self.assertEqual(len(values["DD_CREDENTIAL_AES_256_KEY"]), 32)
        self.assertFalse((lab / "state/dashboard.token").exists())


if __name__ == "__main__":
    unittest.main()
