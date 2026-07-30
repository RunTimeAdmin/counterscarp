"""Project ingestion for Counterscarp.

Turn a user submission — a public git URL or an uploaded project archive — into
a *compilable* local tree so the depth analyzers (Slither/Aderyn) can resolve
imports and honour the project's own compiler settings, instead of failing on
bare ``.sol`` files with unresolved ``@openzeppelin`` imports.

Sandboxing (application level, for untrusted input):
  * git: ``https://`` only, host allowlist, no credentials in the URL, no
    interactive credential prompts (``GIT_TERMINAL_PROMPT=0``), shallow clone,
    shallow submodules, wall-clock timeout, post-clone size cap, ``.git`` removed.
  * archive: zip-slip rejection, symlink entries skipped, per-file / total-size /
    entry-count caps (zip-bomb guard).
  * deps: ``npm ci --ignore-scripts`` (blocks arbitrary ``postinstall`` RCE) and
    ``forge`` submodule fetch, each under a wall-clock timeout.

Stronger isolation (containers / user namespaces / seccomp) is a deployment
concern layered on top of this; the caller may wrap install/compile in one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

# ── sandbox limits ──────────────────────────────────────────────────────────
MAX_ARCHIVE_UNCOMPRESSED = 512 * 1024 * 1024   # 512 MB total extracted
MAX_ARCHIVE_FILES = 20_000
MAX_FILE_BYTES = 64 * 1024 * 1024              # 64 MB per entry
MAX_TREE_BYTES = 1024 * 1024 * 1024            # 1 GB after clone/install
CLONE_TIMEOUT = 180                            # seconds
INSTALL_TIMEOUT = 600                          # seconds

# Public git hosts we will clone from. https only; anything else is rejected.
ALLOWED_GIT_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht",
}


class IngestError(Exception):
    """Raised when a submission cannot be safely ingested."""


@dataclass
class IngestResult:
    project_dir: Path            # extracted / cloned root
    compile_root: Path           # dir the analyzers should target
    framework: str               # "foundry" | "hardhat" | "none"
    deps_installed: bool
    notes: List[str] = field(default_factory=list)


# ── git ─────────────────────────────────────────────────────────────────────
def _validate_git_url(url: str) -> str:
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise IngestError("only https:// git URLs are accepted")
    if "@" in (parsed.netloc or "") or parsed.username or parsed.password:
        raise IngestError("credentials in the git URL are not allowed")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_GIT_HOSTS:
        raise IngestError(
            f"git host not allowed: {host or '?'} "
            f"(allowed: {', '.join(sorted(ALLOWED_GIT_HOSTS))})"
        )
    # Reject control chars / spaces that could smuggle extra args.
    if any(c.isspace() for c in url) or "\x00" in url:
        raise IngestError("git URL contains illegal characters")
    return url


def ingest_git(url: str, dest: Path, ref: Optional[str] = None) -> Path:
    """Shallow-clone a public https repo (with shallow submodules for Foundry
    libs) into ``dest/repo`` and return that path. ``.git`` is removed after."""
    url = _validate_git_url(url)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "repo"
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",   # never block on a credential prompt
        "GIT_ASKPASS": "true",
        "GCM_INTERACTIVE": "never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    cmd = [
        "git", "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--recurse-submodules", "--shallow-submodules",
    ]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, str(target)]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT,
            env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        raise IngestError(f"git clone timed out after {CLONE_TIMEOUT}s")
    if res.returncode != 0:
        raise IngestError(
            "git clone failed: "
            + (res.stderr or res.stdout or "unknown error").strip()[:300]
        )
    # Drop VCS metadata (avoids hooks + saves space); lib/ contents remain.
    shutil.rmtree(target / ".git", ignore_errors=True)
    _enforce_tree_size(target)
    return target


# ── archive ─────────────────────────────────────────────────────────────────
def _safe_join(base: Path, name: str) -> Path:
    """Resolve ``base/name`` and reject anything escaping ``base`` (zip-slip)."""
    base_resolved = base.resolve()
    target = (base_resolved / name).resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise IngestError(f"unsafe path in archive: {name!r}")
    return target


def ingest_zip(zip_path: Path, dest: Path) -> Path:
    """Safely extract a project zip into ``dest/project`` and return the project
    root (unwrapping a single top-level directory when present)."""
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "project"
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    total = 0
    count = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise IngestError("not a valid zip archive")
    with zf:
        for info in zf.infolist():
            count += 1
            if count > MAX_ARCHIVE_FILES:
                raise IngestError(f"archive has too many entries (> {MAX_ARCHIVE_FILES})")
            name = info.filename
            # Symlinks (unix mode in the high bits of external_attr): skip.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            if name.endswith("/"):
                _safe_join(out, name).mkdir(parents=True, exist_ok=True)
                continue
            if info.file_size > MAX_FILE_BYTES:
                raise IngestError(f"archive entry too large: {name} ({info.file_size} bytes)")
            total += info.file_size
            if total > MAX_ARCHIVE_UNCOMPRESSED:
                raise IngestError(f"archive expands beyond {MAX_ARCHIVE_UNCOMPRESSED} bytes")
            tpath = _safe_join(out, name)
            tpath.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(tpath, "wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

    entries = [p for p in out.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return out


def _enforce_tree_size(root: Path) -> None:
    total = 0
    for p in root.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                continue
            if total > MAX_TREE_BYTES:
                raise IngestError(f"project exceeds {MAX_TREE_BYTES} bytes")


# ── framework + deps ────────────────────────────────────────────────────────
def _dir_has_files(d: Path) -> bool:
    return d.is_dir() and any(d.iterdir())


def detect_framework(project_dir: Path) -> Tuple[str, Path]:
    """Return (framework, root) where root holds the config. Foundry wins over
    Hardhat if both are present. Searches the project root and one level down."""
    candidates = [project_dir]
    try:
        candidates += sorted(d for d in project_dir.iterdir() if d.is_dir())
    except OSError:
        pass
    for d in candidates:
        if (d / "foundry.toml").exists():
            return "foundry", d
    for d in candidates:
        if (d / "hardhat.config.js").exists() or (d / "hardhat.config.ts").exists():
            return "hardhat", d
    return "none", project_dir


def _run(cmd: List[str], cwd: Path, notes: List[str], tool: str) -> bool:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["npm_config_yes"] = "true"
    try:
        res = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            timeout=INSTALL_TIMEOUT, env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        notes.append(f"{tool} install timed out after {INSTALL_TIMEOUT}s")
        return False
    except OSError as exc:
        notes.append(f"{tool} install could not start: {exc}")
        return False
    if res.returncode != 0:
        notes.append(f"{tool} install failed: {(res.stderr or res.stdout or '').strip()[:200]}")
        return False
    return True


def install_deps(framework: str, root: Path, notes: List[str]) -> bool:
    """Install the framework's dependencies in-place. npm runs with
    ``--ignore-scripts`` so a hostile ``postinstall`` cannot execute."""
    if framework == "hardhat":
        if _dir_has_files(root / "node_modules"):
            notes.append("node_modules already present; skipping npm install")
            return True
        npm = shutil.which("npm")
        if not npm:
            notes.append("npm not found on PATH; cannot install Hardhat deps")
            return False
        has_lock = (root / "package-lock.json").exists()
        cmd = [npm, "ci" if has_lock else "install",
               "--ignore-scripts", "--no-audit", "--no-fund"]
        ok = _run(cmd, root, notes, "npm")
        notes.append("npm deps installed" if ok else "npm deps NOT installed")
        return ok
    if framework == "foundry":
        if _dir_has_files(root / "lib"):
            notes.append("Foundry lib/ already populated; skipping forge install")
            return True
        forge = shutil.which("forge")
        if not forge:
            notes.append("forge not found on PATH; cannot install Foundry deps")
            return False
        ok = _run([forge, "install"], root, notes, "forge")
        notes.append("forge deps installed" if ok else "forge deps NOT installed")
        return ok
    return False


def prepare_project(project_dir: Path) -> IngestResult:
    """Detect the framework, install deps if needed, and return the root the
    analyzers should target."""
    notes: List[str] = []
    framework, root = detect_framework(project_dir)
    deps = False
    if framework == "none":
        notes.append("no Foundry/Hardhat config found; sources scanned as-is "
                     "(external imports may not resolve)")
    else:
        notes.append(f"{framework} project detected at {root.name or '.'}")
        deps = install_deps(framework, root, notes)
    return IngestResult(
        project_dir=project_dir, compile_root=root,
        framework=framework, deps_installed=deps, notes=notes,
    )


def ingest(
    *, git_url: Optional[str] = None, zip_path: Optional[str] = None,
    dest: str, ref: Optional[str] = None,
) -> IngestResult:
    """High-level entry: fetch (git or zip) then prepare. Exactly one source."""
    if bool(git_url) == bool(zip_path):
        raise IngestError("provide exactly one of git_url or zip_path")
    dest_path = Path(dest)
    if git_url:
        project_dir = ingest_git(git_url, dest_path, ref=ref)
    else:
        project_dir = ingest_zip(Path(str(zip_path)), dest_path)
    return prepare_project(project_dir)


def _main() -> None:
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Ingest a git repo or project zip into a compilable tree.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--git", help="public https git URL")
    src.add_argument("--zip", help="path to a project .zip")
    ap.add_argument("--ref", help="branch/tag for git", default=None)
    ap.add_argument("--dest", required=True, help="destination directory")
    args = ap.parse_args()
    try:
        res = ingest(git_url=args.git, zip_path=args.zip, dest=args.dest, ref=args.ref)
    except IngestError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        raise SystemExit(1)
    print(json.dumps({
        "ok": True,
        "project_dir": str(res.project_dir),
        "compile_root": str(res.compile_root),
        "framework": res.framework,
        "deps_installed": res.deps_installed,
        "notes": res.notes,
    }, indent=2))


if __name__ == "__main__":
    _main()
