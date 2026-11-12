"""Submitted projects must never run their own build tooling."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import project_ingest
import red_team_scan
from red_team_scan import (
    UNTRUSTED_ENTRY,
    _safe_remap,
    _untrusted_remappings,
    _untrusted_sources,
    run_slither,
)

_SLITHER_OK = json.dumps({"success": True, "results": {"detectors": []}})


def _hardhat_project(root: Path) -> Path:
    (root / "contracts" / "sub").mkdir(parents=True)
    (root / "contracts" / "Vault.sol").write_text(
        'pragma solidity ^0.8.0;\nimport "@openzeppelin/contracts/a/A.sol";\ncontract Vault {}\n'
    )
    (root / "contracts" / "sub" / "Helper.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Helper {}\n"
    )
    (root / "test").mkdir()
    (root / "test" / "Vault.t.sol").write_text("contract T {}\n")
    oz = root / "node_modules" / "@openzeppelin" / "contracts" / "a"
    oz.mkdir(parents=True)
    (oz / "A.sol").write_text('import "solady/B.sol";\ncontract A {}\n')
    (root / "node_modules" / "solady").mkdir()
    (root / "node_modules" / "solady" / "B.sol").write_text("contract B {}\n")
    (root / "node_modules" / "unused").mkdir()
    (root / "hardhat.config.js").write_text("require('child_process').exec('touch pwned')\n")
    return root


class TestUntrustedSources:
    def test_skips_deps_tests_and_scripts(self, tmp_path: Path) -> None:
        root = _hardhat_project(tmp_path)
        (root / "script").mkdir()
        (root / "script" / "Deploy.s.sol").write_text("contract D {}\n")
        names = sorted(p.relative_to(root).as_posix() for p in _untrusted_sources(root))
        assert names == ["contracts/Vault.sol", "contracts/sub/Helper.sol"]


class TestSafeRemap:
    @pytest.mark.parametrize("remap", [
        "x/=/etc/",
        "x/=../outside/",
        "x/=lib/../../outside/",
        "x/=C:/Windows/",
        "x/=lib/a b/",
        "no-equals-sign",
        "# comment",
    ])
    def test_rejects_escapes_and_junk(self, tmp_path: Path, remap: str) -> None:
        assert _safe_remap(tmp_path, remap) is None

    def test_keeps_relative_target_inside_root(self, tmp_path: Path) -> None:
        assert _safe_remap(tmp_path, " oz/=lib/oz/src/ ") == "oz/=lib/oz/src/"
        assert _safe_remap(tmp_path, "ctx:oz/=lib/oz/") == "ctx:oz/=lib/oz/"


class TestUntrustedRemappings:
    def test_explicit_lib_and_imported_npm_packages(self, tmp_path: Path) -> None:
        root = _hardhat_project(tmp_path)
        (root / "remappings.txt").write_text("oz/=lib/oz/\nevil/=/etc/\n")
        (root / "foundry.toml").write_text(
            '[profile.default]\nremappings = ["ds/=lib/ds/src/", "bad/=../../x/"]\n'
        )
        (root / "lib" / "forge-std" / "src").mkdir(parents=True)
        remaps = _untrusted_remappings(root, _untrusted_sources(root))
        assert remaps[:2] == ["oz/=lib/oz/", "ds/=lib/ds/src/"]
        assert "forge-std/=lib/forge-std/src/" in remaps
        # Imported directly, and imported by an imported package.
        assert "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/" in remaps
        assert "solady/=node_modules/solady/" in remaps
        assert not any(r.startswith(("evil/", "bad/", "unused/")) for r in remaps)


class TestRunSlitherUntrusted:
    def test_forces_plain_solc_and_never_runs_forge(self, tmp_path: Path) -> None:
        root = _hardhat_project(tmp_path)
        (root / "foundry.toml").write_text('[profile.default]\nsolc = "./evil"\n')
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if kwargs.get("cwd"):
                entry = Path(kwargs["cwd"]) / UNTRUSTED_ENTRY
                calls[-1] = (cmd, kwargs, entry.read_text())
            return MagicMock(returncode=0, stdout=_SLITHER_OK, stderr="")

        with patch.object(red_team_scan.subprocess, "run", side_effect=fake_run), \
             patch.object(red_team_scan, "_select_solc_version", return_value=None), \
             patch.object(red_team_scan.shutil, "which", side_effect=lambda t: f"/usr/bin/{t}"):
            result = run_slither(str(root), trust_build=False)

        assert result["success"] is True
        assert len(calls) == 1, "only Slither runs; no forge build"
        cmd, kwargs, entry_text = calls[0]
        assert "forge" not in Path(cmd[0]).name
        assert cmd[1] == UNTRUSTED_ENTRY
        assert cmd[cmd.index("--compile-force-framework") + 1] == "solc"
        assert UNTRUSTED_ENTRY in cmd[cmd.index("--filter-paths") + 1]
        remaps = cmd[cmd.index("--solc-remaps") + 1]
        assert "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/" in remaps
        # Compiled in a staged copy outside the submitted tree, which has
        # only .sol files: crytic-compile finds no framework config to run.
        staging = Path(kwargs["cwd"]).resolve()
        assert root.resolve() not in [staging, *staging.parents]
        assert 'import "./contracts/Vault.sol" as __cs' in entry_text
        assert 'import "./contracts/sub/Helper.sol" as __cs' in entry_text
        assert "Vault.t.sol" not in entry_text
        assert not staging.exists(), "staging copy is removed"
        assert not (root / UNTRUSTED_ENTRY).exists()

    def test_staged_copy_has_only_sol_files(self, tmp_path: Path) -> None:
        root = _hardhat_project(tmp_path)
        (root / "foundry.toml").write_text('[profile.default]\nsolc = "./evil"\n')
        seen = {}

        def fake_run(cmd, **kwargs):
            staging = Path(kwargs["cwd"])
            seen["files"] = sorted(
                p.relative_to(staging).as_posix() for p in staging.rglob("*") if p.is_file()
            )
            return MagicMock(returncode=0, stdout=_SLITHER_OK, stderr="")

        with patch.object(red_team_scan.subprocess, "run", side_effect=fake_run), \
             patch.object(red_team_scan, "_select_solc_version", return_value=None):
            run_slither(str(root), trust_build=False)
        assert all(f.endswith(".sol") for f in seen["files"]), seen["files"]
        assert "contracts/Vault.sol" in seen["files"]
        assert "node_modules/@openzeppelin/contracts/a/A.sol" in seen["files"]

    def test_staging_removed_when_slither_fails(self, tmp_path: Path) -> None:
        root = _hardhat_project(tmp_path)
        made = []
        real_mkdtemp = red_team_scan.tempfile.mkdtemp

        def tracking_mkdtemp(*a, **k):
            made.append(Path(real_mkdtemp(*a, **k)))
            return str(made[-1])

        with patch.object(red_team_scan.subprocess, "run", side_effect=FileNotFoundError), \
             patch.object(red_team_scan.tempfile, "mkdtemp", side_effect=tracking_mkdtemp), \
             patch.object(red_team_scan, "_select_solc_version", return_value=None):
            with pytest.raises(Exception):
                run_slither(str(root), trust_build=False)
        assert made and not made[0].exists()


class TestScanUtilsProjectDir:
    def test_project_dir_uses_untrusted_build(self, tmp_path: Path) -> None:
        from webapp import scan_utils

        _hardhat_project(tmp_path)
        with patch.object(red_team_scan, "run_slither", return_value={"results": {"detectors": []}}) as rs, \
             patch.object(scan_utils, "_invoke_slither") as invoke:
            findings, status = scan_utils.run_slither_analysis(str(tmp_path), tmp_path)
        assert status == "completed" and findings == []
        assert rs.call_args.kwargs["trust_build"] is False
        invoke.assert_not_called()


class TestIngestHardening:
    def test_flags_git_url_and_file_dependencies(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {
                "ok": "^1.2.0",
                "alias": "npm:@scope/pkg@^2.0.0",
                "gitdep": "git+https://github.com/x/y.git",
                "short": "x/y",
                "local": "file:../z",
            },
            "devDependencies": {"tarball": "https://example.com/t.tgz"},
        }))
        (tmp_path / "package-lock.json").write_text(json.dumps({
            "packages": {
                "": {},
                "node_modules/fine": {"resolved": "https://registry.npmjs.org/fine/-/fine-1.0.0.tgz"},
                "node_modules/sneaky": {"resolved": "git+ssh://git@github.com/x/sneaky.git"},
            },
        }))
        assert project_ingest._non_registry_npm_deps(tmp_path) == [
            "gitdep", "local", "short", "sneaky", "tarball",
        ]

    def test_refuses_install_with_git_dependency(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"g": "github:x/y"}}))
        notes: list = []
        with patch.object(project_ingest.shutil, "which", return_value="/usr/bin/tool"), \
             patch.object(project_ingest, "_run") as run:
            assert project_ingest.install_deps("hardhat", tmp_path, notes) is False
        run.assert_not_called()
        assert "can run code" in notes[-1]

    def test_npm_install_drops_project_config_and_pins_git(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "^1.0.0"}}))
        (tmp_path / ".npmrc").write_text("git=./evil.sh\n")
        notes: list = []
        with patch.object(project_ingest.shutil, "which", side_effect=lambda t: f"/usr/bin/{t}"), \
             patch.object(project_ingest, "_run", return_value=True) as run:
            assert project_ingest.install_deps("hardhat", tmp_path, notes) is True
        assert not (tmp_path / ".npmrc").exists()
        cmd = run.call_args.args[0]
        assert "--ignore-scripts" in cmd and "--git=/usr/bin/git" in cmd

    def test_git_env_allows_https_only(self, tmp_path: Path) -> None:
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs["env"])
            (tmp_path / "repo").mkdir(exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(project_ingest.subprocess, "run", side_effect=fake_run):
            project_ingest.ingest_git("https://github.com/x/y", tmp_path)
        assert captured["GIT_ALLOW_PROTOCOL"] == "https"

    def test_remove_symlinks(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "A.sol").write_text("contract A {}\n")
        try:
            (tmp_path / "src" / "leak.sol").symlink_to(tmp_path.parent)
        except OSError:
            pytest.skip("symlinks not permitted on this system")
        project_ingest._remove_symlinks(tmp_path)
        assert sorted(p.name for p in (tmp_path / "src").iterdir()) == ["A.sol"]
