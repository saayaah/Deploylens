"""Project context: file inventory, technology detection, and text helpers.

Detection uses filenames and manifest contents only. No file is executed.
"""
from __future__ import annotations

import fnmatch
import json
import posixpath
from dataclasses import dataclass, field

TECH_PYTHON_FASTAPI = "FastAPI"
TECH_DJANGO = "Django"
TECH_FLASK = "Flask"
TECH_EXPRESS = "Express"
TECH_REACT = "React"
TECH_NODE = "Node.js"
TECH_PYTHON = "Python"
TECH_GENERIC_WEB = "Generic web application"

PYTHON_MANIFESTS = ("requirements.txt", "pyproject.toml", "Pipfile")
NODE_MANIFESTS = ("package.json",)
BINARY_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mp3", ".pyc", ".so",
    ".dll", ".exe", ".bin", ".sqlite3", ".db",
)
TEXT_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml",
    ".cfg", ".ini", ".env", ".txt", ".md", ".html", ".css", ".conf", ".sh",
    ".example", ".sample", ".dockerignore", ".gitignore",
)
IGNORED_DIR_PARTS = ("node_modules", "__pycache__", ".git", "venv", ".venv", "dist", "build")


def is_binary_path(path: str) -> bool:
    return path.lower().endswith(BINARY_EXTENSIONS)


def decode_text(data: bytes) -> str | None:
    """Return decoded text, or None for binary-looking content."""
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


@dataclass
class ProjectContext:
    files: dict[str, bytes]
    technologies: list[str] = field(default_factory=list)
    _text_cache: dict[str, str | None] = field(default_factory=dict, repr=False)

    def paths(self) -> list[str]:
        return sorted(self.files)

    def exists(self, pattern: str) -> bool:
        return bool(self.find(pattern))

    def find(self, pattern: str) -> list[str]:
        """Find paths whose basename or full path matches a glob pattern."""
        hits = []
        for p in self.paths():
            base = posixpath.basename(p)
            if fnmatch.fnmatch(p, pattern) or fnmatch.fnmatch(base, pattern):
                hits.append(p)
        return hits

    def is_ignored_dir(self, path: str) -> bool:
        return any(part in IGNORED_DIR_PARTS for part in path.split("/"))

    def text(self, path: str) -> str | None:
        if path not in self._text_cache:
            data = self.files.get(path, b"")
            self._text_cache[path] = decode_text(data) if data else None
        return self._text_cache[path]

    def text_files(self, suffixes: tuple[str, ...] | None = None) -> list[str]:
        out = []
        for p in self.paths():
            if self.is_ignored_dir(p) or is_binary_path(p):
                continue
            if suffixes is None or p.lower().endswith(suffixes) or posixpath.basename(p) in (
                "Dockerfile", ".gitignore", ".dockerignore", "Procfile",
            ):
                if self.text(p) is not None:
                    out.append(p)
        return out

    def has_tech(self, tech: str) -> bool:
        return tech in self.technologies

    def requirements_text(self) -> str:
        return "\n".join(self.text(p) or "" for p in self.find("requirements*.txt")).lower()

    def package_json(self) -> dict | None:
        for p in self.find("package.json"):
            if p.count("/") <= 1 and not self.is_ignored_dir(p):
                try:
                    return json.loads(self.text(p) or "")
                except json.JSONDecodeError:
                    return None
        return None


def detect_technologies(ctx: ProjectContext) -> list[str]:
    """Infer technologies from manifests and framework markers. Deterministic, sorted."""
    found: set[str] = set()
    py_deps = ctx.requirements_text() + "\n" + "\n".join(
        ctx.text(p) or "" for p in ctx.find("pyproject.toml")
    ).lower()
    pkg = ctx.package_json() or {}
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

    if "fastapi" in py_deps:
        found.add(TECH_PYTHON_FASTAPI)
    if "django" in py_deps or ctx.find("manage.py"):
        found.add(TECH_DJANGO)
    if "flask" in py_deps:
        found.add(TECH_FLASK)
    if ctx.find("*.py") or py_deps.strip():
        found.add(TECH_PYTHON)
    if "express" in deps:
        found.add(TECH_EXPRESS)
    if "react" in deps:
        found.add(TECH_REACT)
    if pkg:
        found.add(TECH_NODE)
    if not found and any(p.lower().endswith((".html", ".css")) for p in ctx.paths()):
        found.add(TECH_GENERIC_WEB)
    return sorted(found)
