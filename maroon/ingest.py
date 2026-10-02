"""Target acquisition: local dir, git URL (shallow clone), or uploaded zip.

Security note (dogfooding): zip extraction refuses path-traversal and symlink members
(the exact DSGAI05 / CVE-2024-3584 class this tool flags in others).
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

# Directories we never walk into.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".tox",
    "site-packages", ".next", ".turbo", "vendor", ".idea", ".gradle",
}
# Extensions worth reading as source/config.
TEXT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".java", ".rb",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".txt", ".md",
    ".tf", ".hcl", ".sh", ".dockerfile", ".xml", ".gradle", ".properties",
}
SPECIAL_NAMES = {
    "requirements.txt", "pyproject.toml", "package.json", "package-lock.json",
    "pnpm-lock.yaml", "poetry.lock", "Pipfile", "Pipfile.lock", "Dockerfile",
    "mcp.json", ".mcp.json", "claude_desktop_config.json", "go.mod", "pom.xml",
    "build.gradle", "Cargo.toml",
}
MAX_FILE_BYTES = 2_000_000
MAX_LINE_CHARS = 20_000           # truncate pathologically long lines (ReDoS / DoS defense)
MAX_ZIP_TOTAL_BYTES = 500_000_000  # 500 MB uncompressed cap (zip-bomb defense)
MAX_ZIP_MEMBERS = 50_000
MAX_ZIP_RATIO = 200               # per-member compression-ratio cap


@dataclass
class Target:
    root: str
    files: List[str] = field(default_factory=list)   # repo-relative POSIX paths
    origin: str = "local"
    _tmp: Optional[str] = None                        # temp dir to clean, if any
    name: str = ""

    def abspath(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def read_lines(self, rel: str) -> List[str]:
        try:
            with open(self.abspath(rel), "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except (OSError, ValueError):
            return []
        # Truncate pathologically long lines so a crafted huge single line can't stall regexes.
        return [ln if len(ln) <= MAX_LINE_CHARS else ln[:MAX_LINE_CHARS] for ln in lines]

    def cleanup(self) -> None:
        if self._tmp and os.path.isdir(self._tmp):
            import shutil
            shutil.rmtree(self._tmp, ignore_errors=True)


def _want(name: str) -> bool:
    if name in SPECIAL_NAMES or name.startswith("Dockerfile"):
        return True
    ext = os.path.splitext(name)[1].lower()
    return ext in TEXT_EXT


def _load_ignore(root: str) -> List[str]:
    pats: List[str] = []
    path = os.path.join(root, ".maroonignore")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                s = ln.strip()
                if s and not s.startswith("#"):
                    pats.append(s.rstrip("/"))
    except OSError:
        pass
    return pats


def _ignored(rel: str, patterns: List[str]) -> bool:
    import fnmatch
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or rel.startswith(pat + "/"):
            return True
    return False


def _walk(root: str) -> List[str]:
    out: List[str] = []
    ignore = _load_ignore(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                       or d in {".github", ".vscode", ".cursor", ".claude", ".well-known"}]
        for fn in filenames:
            if not _want(fn):
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.islink(full) or os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if ignore and _ignored(rel, ignore):
                continue
            out.append(rel)
    return sorted(out)


def from_path(path: str) -> Target:
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise ValueError("Not a directory: %s" % path)
    return Target(root=root, files=_walk(root), origin="local", name=os.path.basename(root.rstrip("/")))


_ALLOWED_GIT_SCHEMES = ("http://", "https://", "git://", "ssh://")
# Cloud-metadata / link-local hosts we refuse to clone from (SSRF defense).
_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata",
                  "100.100.100.200", "fd00:ec2::254"}


def _validate_git_url(url: str) -> None:
    if url.startswith("-"):
        raise ValueError("Refusing git URL that looks like a CLI option: %r" % url)
    low = url.lower()
    is_scp = "@" in url and ":" in url.split("@", 1)[1] and "://" not in url  # git@host:path
    if not (low.startswith(_ALLOWED_GIT_SCHEMES) or is_scp):
        raise ValueError("Unsupported git URL scheme (allowed: http/https/git/ssh): %r" % url)
    host = ""
    if "://" in url:
        host = url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
    elif is_scp:
        host = url.split("@", 1)[1].split(":", 1)[0].lower()
    if host in _BLOCKED_HOSTS or host.startswith("169.254."):
        raise ValueError("Refusing to clone from a cloud-metadata/link-local host: %r" % host)


def from_git(url: str, ref: Optional[str] = None) -> Target:
    _validate_git_url(url)
    if ref and ref.startswith("-"):
        raise ValueError("Refusing git ref that looks like a CLI option: %r" % ref)
    tmp = tempfile.mkdtemp(prefix="maroon-clone-")
    # Harden transport: disable ext:: (command exec) and file:: regardless of git version.
    cmd = ["git", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=user",
           "clone", "--depth", "1", "--filter=blob:none", "--quiet"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", url, tmp]   # '--' stops any remaining arg-injection via url/ref
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true", GCM_INTERACTIVE="never")
    try:
        subprocess.run(cmd, check=True, timeout=300, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("git clone failed for %s: %s" % (url, e))
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return Target(root=tmp, files=_walk(tmp), origin="git", _tmp=tmp, name=name)


def _is_within(base: str, target: str) -> bool:
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def from_zip(zip_path: str) -> Target:
    """Extract a zip safely (reject traversal + symlinks), then walk it."""
    tmp = tempfile.mkdtemp(prefix="maroon-zip-")
    try:
        with zipfile.ZipFile(zip_path) as zf:
            total_uncompressed = 0
            members = zf.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError("Zip has too many members (%d > %d)" % (len(members), MAX_ZIP_MEMBERS))
            for info in members:
                # reject absolute paths, traversal, and symlinks
                name = info.filename
                if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    raise ValueError("Unsafe path in zip (traversal): %s" % name)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:  # S_IFLNK
                    raise ValueError("Unsafe symlink in zip: %s" % name)
                dest = os.path.join(tmp, name)
                if not _is_within(tmp, dest):
                    raise ValueError("Zip member escapes extraction dir: %s" % name)
                # zip-bomb defense: cap total uncompressed size and per-member ratio
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                    raise ValueError("Zip uncompressed size exceeds %d bytes (zip bomb?)" % MAX_ZIP_TOTAL_BYTES)
                if info.compress_size > 0 and info.file_size / info.compress_size > MAX_ZIP_RATIO:
                    raise ValueError("Zip member compression ratio too high (zip bomb?): %s" % name)
            zf.extractall(tmp)  # maroon: ignore[ME-DSGAI05-archive-extract] members validated above (no traversal/symlinks, size-capped)
    except Exception:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    # If the zip has a single top-level dir, root into it.
    entries = [e for e in os.listdir(tmp) if not e.startswith("__MACOSX")]
    root = os.path.join(tmp, entries[0]) if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])) else tmp
    name = os.path.splitext(os.path.basename(zip_path))[0]
    return Target(root=root, files=_walk(root), origin="zip", _tmp=tmp, name=name)


def acquire(target: str, ref: Optional[str] = None) -> Target:
    """Dispatch on the target string: git URL, .zip, or local path."""
    if target.startswith(("http://", "https://", "git@")) or target.endswith(".git"):
        return from_git(target, ref)
    if target.endswith(".zip") and os.path.isfile(target):
        return from_zip(target)
    return from_path(target)
