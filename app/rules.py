"""Rule definitions. Each rule is a small, pure function of a ProjectContext.

Status meanings:
  PASS            the check was performed and the evidence is good
  FAIL            a confirmed problem in the uploaded files
  WARN            a potential issue that needs human review
  UNVERIFIED      the check could not be performed from the available files
  NOT_APPLICABLE  the rule does not apply to this project
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Callable

from . import context as C
from .context import ProjectContext
from .redaction import scan_text_for_secrets

PASS, WARN, FAIL, UNVERIFIED, NOT_APPLICABLE = "PASS", "WARN", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"

CATEGORIES = [
    "Containerization",
    "Configuration and secrets",
    "Dependencies",
    "Testing",
    "CI/CD",
    "Documentation and repository hygiene",
    "Application readiness",
]

Outcome = tuple[str, list[str], str]  # (status, evidence, explanation)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str  # critical | high | medium | low
    applies: Callable[[ProjectContext], bool]
    check: Callable[[ProjectContext], Outcome]
    remediation: str
    not_applicable_when: str


def _web_project(ctx: ProjectContext) -> bool:
    web = {C.TECH_PYTHON_FASTAPI, C.TECH_DJANGO, C.TECH_FLASK, C.TECH_EXPRESS, C.TECH_REACT, C.TECH_GENERIC_WEB}
    return any(t in web for t in ctx.technologies)


def _backend_project(ctx: ProjectContext) -> bool:
    return any(t in ctx.technologies for t in (C.TECH_PYTHON_FASTAPI, C.TECH_DJANGO, C.TECH_FLASK, C.TECH_EXPRESS))


def _always(_: ProjectContext) -> bool:
    return True


def _has_python(ctx: ProjectContext) -> bool:
    return C.TECH_PYTHON in ctx.technologies or any(
        t in ctx.technologies for t in (C.TECH_PYTHON_FASTAPI, C.TECH_DJANGO, C.TECH_FLASK)
    )


def _has_node(ctx: ProjectContext) -> bool:
    return any(t in ctx.technologies for t in (C.TECH_NODE, C.TECH_EXPRESS, C.TECH_REACT))


# ---------- 1. Containerization ----------

def _dockerfile_present(ctx: ProjectContext) -> Outcome:
    hits = ctx.find("Dockerfile") + ctx.find("Dockerfile.*")
    if hits:
        return PASS, hits[:5], "A Dockerfile is present, so the project can be built into a container image."
    return FAIL, [], "No Dockerfile was found. Containers make deployment environments reproducible."


def _dockerignore_present(ctx: ProjectContext) -> Outcome:
    if not ctx.exists(".dockerignore"):
        return WARN, [], "A Dockerfile exists but no .dockerignore. Build context may include secrets, .git, or node_modules."
    return PASS, [".dockerignore"], "A .dockerignore file limits what is sent to the Docker build context."


def _dockerfile_user(ctx: ProjectContext) -> Outcome:
    df = _first_dockerfile(ctx)
    if df is None:
        return UNVERIFIED, [], "No Dockerfile to inspect."
    text = ctx.text(df) or ""
    if re.search(r"(?m)^\s*USER\s+\S+", text):
        return PASS, [df], "The Dockerfile sets a non-root USER."
    return WARN, [df], "The Dockerfile has no USER instruction, so the container will likely run as root."


def _dockerfile_pinned_base(ctx: ProjectContext) -> Outcome:
    df = _first_dockerfile(ctx)
    if df is None:
        return UNVERIFIED, [], "No Dockerfile to inspect."
    froms = re.findall(r"(?im)^\s*FROM\s+(\S+)", ctx.text(df) or "")
    if not froms:
        return UNVERIFIED, [df], "No FROM instruction could be parsed."
    unpinned = [f for f in froms if f.endswith(":latest") or ":" not in f.split("/")[-1]]
    if unpinned:
        return WARN, [f"{df}: FROM {f}" for f in unpinned[:5]], (
            "Base image is untagged or uses :latest, so builds may change unexpectedly over time.")
    return PASS, [f"{df}: FROM {f}" for f in froms[:3]], "Base images use explicit tags."


def _first_dockerfile(ctx: ProjectContext) -> str | None:
    hits = ctx.find("Dockerfile")
    return hits[0] if hits else None


# ---------- 2. Configuration and secrets ----------

def _env_in_archive(ctx: ProjectContext) -> Outcome:
    envs = [p for p in ctx.find(".env") + ctx.find(".env.*") if not p.endswith((".example", ".sample", ".template"))]
    if envs:
        return FAIL, envs[:5], (
            "A real .env file is included in the upload. Such files usually hold credentials and should not be committed or shipped.")
    return PASS, [], "No real .env file was included in the archive."


def _env_in_gitignore(ctx: ProjectContext) -> Outcome:
    gi = ctx.find(".gitignore")
    if not gi:
        return WARN, [], "An .env file exists but there is no .gitignore to exclude it."
    text = ctx.text(gi[0]) or ""
    if re.search(r"^\s*(\.env|\*\.env|\.env\*)\s*$", text, re.MULTILINE):
        return PASS, [gi[0]], ".gitignore excludes .env files."
    return FAIL, [gi[0]], ".gitignore does not exclude .env, so secrets could be committed to version control."


def _hardcoded_secrets(ctx: ProjectContext) -> Outcome:
    hits = []
    for p in ctx.text_files():
        text = ctx.text(p)
        if text is None:
            continue
        hits.extend(scan_text_for_secrets(p, text))
    if not hits:
        return PASS, [], "No likely hardcoded credentials were found by pattern matching."
    evidence = [f"{h.path}:{h.line} ({h.label}, value redacted)" for h in hits[:8]]
    return FAIL, evidence, (
        "Likely hardcoded credentials were found. Values are redacted here. "
        "Pattern matching can produce false positives, so each finding needs manual review.")


def _django_debug(ctx: ProjectContext) -> Outcome:
    settings = [p for p in ctx.text_files((".py",)) if posixpath.basename(p) == "settings.py"]
    if not settings:
        return UNVERIFIED, [], "No Django settings.py was found to inspect."
    for p in settings:
        for i, line in enumerate((ctx.text(p) or "").splitlines(), 1):
            if re.match(r"\s*DEBUG\s*=\s*True\b", line):
                return FAIL, [f"{p}:{i}"], "DEBUG = True is set in Django settings. Debug mode exposes tracebacks and internals in production."
    return PASS, settings[:3], "Django DEBUG is not hardcoded to True."


def _django_allowed_hosts(ctx: ProjectContext) -> Outcome:
    settings = [p for p in ctx.text_files((".py",)) if posixpath.basename(p) == "settings.py"]
    if not settings:
        return UNVERIFIED, [], "No Django settings.py was found to inspect."
    for p in settings:
        for i, line in enumerate((ctx.text(p) or "").splitlines(), 1):
            if re.match(r"\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", line):
                return WARN, [f"{p}:{i}"], "ALLOWED_HOSTS allows any host ('*'). Restrict it to your real domains."
    return PASS, [], "ALLOWED_HOSTS does not use a wildcard."


def _flask_debug(ctx: ProjectContext) -> Outcome:
    for p in ctx.text_files((".py", ".env", ".cfg", ".toml", ".sh", ".yml", ".yaml", "Dockerfile")):
        for i, line in enumerate((ctx.text(p) or "").splitlines(), 1):
            if re.search(r"\.run\([^)]*debug\s*=\s*True", line) or re.search(r"FLASK_DEBUG\s*=\s*['\"]?1", line):
                return FAIL, [f"{p}:{i}"], "Flask debug mode is enabled. The Werkzeug debugger allows remote code execution if exposed."
    return PASS, [], "Flask debug mode is not enabled in inspected files."





# ---------- 3. Dependencies ----------

def _manifest_present(ctx: ProjectContext) -> Outcome:
    manifests = ctx.find("requirements*.txt") + ctx.find("pyproject.toml") + ctx.find("Pipfile") + ctx.find("package.json")
    manifests = [m for m in manifests if not ctx.is_ignored_dir(m)]
    if manifests:
        return PASS, sorted(manifests)[:5], "A dependency manifest is present."
    return FAIL, [], "No dependency manifest (requirements.txt, pyproject.toml, Pipfile, or package.json) was found."


def _lockfile_present(ctx: ProjectContext) -> Outcome:
    locks = ["poetry.lock", "Pipfile.lock", "uv.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    found = [p for p in ctx.paths() if posixpath.basename(p) in locks and not ctx.is_ignored_dir(p)]
    if _has_node(ctx) and not any(posixpath.basename(p) in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml") for p in found):
        return WARN, [], "No Node lockfile was found. Installs may resolve different dependency versions over time."
    if _has_python(ctx) and not found:
        req_pinned = _requirements_fully_pinned(ctx)
        if req_pinned:
            return PASS, [], "requirements.txt pins every dependency with ==, so it acts as a lock."
        return WARN, [], "No lockfile and requirements are not fully pinned. Builds may not be reproducible."
    return PASS, found[:5], "A lockfile is present."


def _requirements_fully_pinned(ctx: ProjectContext) -> bool:
    lines = []
    for p in ctx.find("requirements*.txt"):
        lines += [l.strip() for l in (ctx.text(p) or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    return bool(lines) and all("==" in l for l in lines if not l.startswith("-"))


def _unpinned_python(ctx: ProjectContext) -> Outcome:
    reqs = ctx.find("requirements*.txt")
    if not reqs:
        return NOT_APPLICABLE_OUTCOME
    loose = []
    for p in reqs:
        for line in (ctx.text(p) or "").splitlines():
            s = line.strip()
            if not s or s.startswith(("#", "-")):
                continue
            if "==" not in s:
                loose.append(f"{p}: {s}")
    if loose:
        return WARN, loose[:6], "Some Python dependencies are not pinned to an exact version."
    return PASS, reqs[:3], "All listed Python dependencies are pinned."


def _unpinned_node(ctx: ProjectContext) -> Outcome:
    pkg = ctx.package_json()
    if pkg is None:
        return NOT_APPLICABLE_OUTCOME
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    loose = [f"{k}: {v}" for k, v in deps.items() if v in ("*", "latest", "") or str(v).startswith(">=")]
    if loose:
        return WARN, loose[:6], "Some Node dependencies use wildcard or unbounded versions, which can pull breaking changes."
    return PASS, ["package.json"], "Node dependency versions are bounded."


# ---------- 4. Testing ----------

def _tests_present(ctx: ProjectContext) -> Outcome:
    hits = [p for p in ctx.paths() if not ctx.is_ignored_dir(p) and (
        re.search(r"(^|/)tests?/", p) or posixpath.basename(p).startswith("test_")
        or re.search(r"\.(test|spec)\.(js|jsx|ts|tsx)$", p))]
    if hits:
        return PASS, hits[:5], "Test files or a test directory are present."
    return FAIL, [], "No test files or test directory were found."


def _test_runner_config(ctx: ProjectContext) -> Outcome:
    has_pytest_cfg = bool(ctx.find("pytest.ini") or ctx.find("setup.cfg") or ctx.find("tox.ini")) or "[tool.pytest" in (
        "\n".join(ctx.text(p) or "" for p in ctx.find("pyproject.toml")))
    pkg = ctx.package_json() or {}
    script = (pkg.get("scripts") or {}).get("test", "")
    has_node_test = bool(script) and "no test specified" not in script
    if has_pytest_cfg or has_node_test:
        return PASS, [], "A test runner is configured."
    py_tests = [p for p in ctx.paths() if posixpath.basename(p).startswith("test_") and p.endswith(".py")]
    if py_tests:
        return PASS, py_tests[:3], "Python test_*.py files follow pytest's default discovery convention."
    return WARN, [], "Tests may exist, but no test runner configuration (pytest config or npm test script) was found."


# ---------- 5. CI/CD ----------

def _workflow_present(ctx: ProjectContext) -> Outcome:
    wf = [p for p in ctx.paths() if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    if wf:
        return PASS, wf[:5], "GitHub Actions workflow files are present."
    return WARN, [], "No GitHub Actions workflow was found. Tests and builds are not automated on push."


def _workflow_runs_checks(ctx: ProjectContext) -> Outcome:
    wf = [p for p in ctx.paths() if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    for p in wf:
        text = (ctx.text(p) or "").lower()
        if re.search(r"\b(pytest|npm (run )?test|npm run build|pnpm (run )?(test|build)|yarn (test|build)|docker build)\b", text):
            return PASS, [p], "A workflow runs tests or a build."
    return WARN, wf[:3], "No workflow step clearly runs tests or a build."


# ---------- 6. Documentation and hygiene ----------

def _readme_present(ctx: ProjectContext) -> Outcome:
    if ctx.exists("README*"):
        return PASS, ctx.find("README*")[:2], "A README is present."
    return WARN, [], "No README was found. Setup and purpose should be documented."


def _gitignore_present(ctx: ProjectContext) -> Outcome:
    if ctx.exists(".gitignore"):
        return PASS, [".gitignore"], ".gitignore is present."
    return WARN, [], "No .gitignore was found. Dependencies, caches, and secrets may be committed."


def _env_example_present(ctx: ProjectContext) -> Outcome:
    if ctx.exists(".env.example") or ctx.exists(".env.sample") or ctx.exists(".env.template"):
        return PASS, [], "An example environment file documents required variables."
    return WARN, [], "No .env.example was found. Required environment variables are undocumented."


def _generated_artifacts(ctx: ProjectContext) -> Outcome:
    bad = sorted({p for p in ctx.paths()
                  if "node_modules" in p.split("/") or "__pycache__" in p.split("/") or p.endswith(".pyc")})
    if bad:
        return WARN, bad[:5], "Generated or dependency files are included in the archive. Remove them before deployment."
    return PASS, [], "No generated dependency or cache files were included."


# ---------- 7. Application readiness ----------

def _health_endpoint(ctx: ProjectContext) -> Outcome:
    for p in ctx.text_files((".py", ".js", ".ts", ".jsx", ".tsx")):
        for i, line in enumerate((ctx.text(p) or "").splitlines(), 1):
            if re.search(r"""['"`]/(api/)?(health|healthz|health-?check|status)['"`/]""", line):
                return PASS, [f"{p}:{i}"], "A health-check route was found."
    return WARN, [], "No health-check endpoint was identified. Load balancers and orchestrators rely on one."


def _startup_config(ctx: ProjectContext) -> Outcome:
    if ctx.exists("Procfile"):
        return PASS, ["Procfile"], "A Procfile defines the startup command."
    df = _first_dockerfile(ctx)
    if df and re.search(r"(?m)^\s*(CMD|ENTRYPOINT)\s", ctx.text(df) or ""):
        return PASS, [df], "The Dockerfile defines a startup command."
    pkg = ctx.package_json() or {}
    if (pkg.get("scripts") or {}).get("start"):
        return PASS, ["package.json"], "package.json defines a start script."
    if re.search(r"uvicorn|gunicorn", ctx.requirements_text()):
        return PASS, [], "A production ASGI/WSGI server (uvicorn or gunicorn) is listed in requirements."
    return WARN, [], "No explicit startup command was found (Procfile, Dockerfile CMD, npm start, or a production server)."


def _production_server(ctx: ProjectContext) -> Outcome:
    if not ctx.has_tech(C.TECH_FLASK):
        return NOT_APPLICABLE_OUTCOME
    if re.search(r"gunicorn|waitress", ctx.requirements_text()):
        return PASS, [], "Flask is served by a production WSGI server."
    return WARN, [], "Flask is used without a production WSGI server (gunicorn or waitress). The built-in dev server is not for production."


NOT_APPLICABLE_OUTCOME: Outcome = (NOT_APPLICABLE, [], "This rule does not apply to the detected technologies.")

RULES: list[Rule] = [
    Rule("CONT-001", "Dockerfile is present", "Containerization", "high", _web_project, _dockerfile_present,
         "Add a Dockerfile that builds and runs the application.", "The project is not a web/application project."),
    Rule("CONT-002", ".dockerignore is present", "Containerization", "medium",
         lambda c: c.exists("Dockerfile*"), _dockerignore_present,
         "Add a .dockerignore excluding .git, node_modules, .env, and caches.", "No Dockerfile exists."),
    Rule("CONT-003", "Dockerfile runs as a non-root user", "Containerization", "medium",
         lambda c: c.exists("Dockerfile"), _dockerfile_user,
         "Add a USER instruction that switches to an unprivileged account before CMD.", "No Dockerfile exists."),
    Rule("CONT-004", "Dockerfile base image is pinned", "Containerization", "low",
         lambda c: c.exists("Dockerfile"), _dockerfile_pinned_base,
         "Pin base images to a specific version tag such as python:3.12-slim.", "No Dockerfile exists."),
    Rule("CFG-001", "No real .env file in the archive", "Configuration and secrets", "critical", _always, _env_in_archive,
         "Remove .env from the project; provide variables at deploy time through the platform's secret store.",
         "Never applies; the archive is always checked."),
    Rule("CFG-002", ".gitignore excludes .env", "Configuration and secrets", "high",
         lambda c: c.exists(".env") or c.exists(".env.*"), _env_in_gitignore,
         "Add a line '.env' to .gitignore.", "No .env file exists in the archive."),
    Rule("CFG-003", "No likely hardcoded credentials", "Configuration and secrets", "critical", _always, _hardcoded_secrets,
         "Move secrets to environment variables or a secret manager and rotate any exposed credentials.",
         "Never applies; all text files are scanned."),
    Rule("CFG-004", "Django DEBUG is not enabled", "Configuration and secrets", "high",
         lambda c: c.has_tech(C.TECH_DJANGO), _django_debug,
         "Read DEBUG from an environment variable defaulting to False.", "Project does not use Django."),
    Rule("CFG-005", "Django ALLOWED_HOSTS is restricted", "Configuration and secrets", "medium",
         lambda c: c.has_tech(C.TECH_DJANGO), _django_allowed_hosts,
         "Set ALLOWED_HOSTS to your real domain names.", "Project does not use Django."),
    Rule("CFG-006", "Flask debug mode is not enabled", "Configuration and secrets", "high",
         lambda c: c.has_tech(C.TECH_FLASK), _flask_debug,
         "Disable debug mode in production and never expose the Werkzeug debugger.", "Project does not use Flask."),
    Rule("DEP-001", "Dependency manifest is present", "Dependencies", "high",
         lambda c: _has_python(c) or _has_node(c), _manifest_present,
         "Declare dependencies in requirements.txt, pyproject.toml, or package.json.",
         "No Python or Node.js technology was detected."),
    Rule("DEP-002", "Lockfile or fully pinned requirements", "Dependencies", "medium",
         lambda c: _has_python(c) or _has_node(c), _lockfile_present,
         "Commit a lockfile (package-lock.json, poetry.lock, uv.lock) or pin every requirement with ==.",
         "No Python or Node.js technology was detected."),
    Rule("DEP-003", "Python dependencies are pinned", "Dependencies", "low",
         lambda c: c.exists("requirements*.txt"), _unpinned_python,
         "Pin each requirement with == to an exact tested version.", "No requirements file exists."),
    Rule("DEP-004", "Node dependencies are version-bounded", "Dependencies", "low",
         lambda c: c.exists("package.json"), _unpinned_node,
         "Replace '*', 'latest', or '>=' ranges with caret or exact versions.", "No package.json exists."),
    Rule("TST-001", "Tests are present", "Testing", "medium", lambda c: _web_project(c) or _has_python(c) or _has_node(c),
         _tests_present, "Add tests under tests/ or alongside source as *.test.js / test_*.py.",
         "No application technology was detected."),
    Rule("TST-002", "A test runner is configured", "Testing", "low", lambda c: _tests_present(c)[0] == PASS,
         _test_runner_config, "Add pytest configuration or an npm test script.",
         "No tests were found, so runner configuration is not evaluated."),
    Rule("CI-001", "CI workflow is present", "CI/CD", "medium", _always, _workflow_present,
         "Add a GitHub Actions workflow that runs tests and builds on each push.", "Never applies."),
    Rule("CI-002", "CI workflow runs tests or a build", "CI/CD", "medium",
         lambda c: any(p.startswith(".github/workflows/") for p in c.paths()), _workflow_runs_checks,
         "Add a step such as 'pytest' or 'npm run build' to the workflow.", "No workflow files exist."),
    Rule("DOC-001", "README is present", "Documentation and repository hygiene", "low", _always, _readme_present,
         "Add a README with setup, run, and test instructions.", "Never applies."),
    Rule("DOC-002", ".gitignore is present", "Documentation and repository hygiene", "medium", _always, _gitignore_present,
         "Add a .gitignore covering dependencies, build output, caches, and secrets.", "Never applies."),
    Rule("DOC-003", ".env.example is present", "Documentation and repository hygiene", "low",
         lambda c: any("os.environ" in (c.text(p) or "") or "process.env" in (c.text(p) or "")
                       for p in c.text_files((".py", ".js", ".ts"))), _env_example_present,
         "Add .env.example listing every required variable with placeholder values.",
         "The code does not read environment variables."),
    Rule("DOC-004", "No generated or dependency directories in archive", "Documentation and repository hygiene", "low",
         _always, _generated_artifacts, "Exclude node_modules, __pycache__, and build output from the upload.",
         "Never applies."),
    Rule("APP-001", "Health-check endpoint is present", "Application readiness", "medium",
         _backend_project, _health_endpoint, "Add a GET /health route returning 200 for orchestrators to probe.",
         "No backend framework was detected."),
    Rule("APP-002", "Startup command is defined", "Application readiness", "medium",
         _web_project, _startup_config, "Define a startup command in the Dockerfile, Procfile, or package.json.",
         "No web application technology was detected."),
    Rule("APP-003", "Flask runs under a production server", "Application readiness", "medium",
         lambda c: c.has_tech(C.TECH_FLASK), _production_server,
         "Serve Flask with gunicorn or waitress in production.", "Project does not use Flask."),
]
