"""Run the project's checks: the same ones CI runs, in the order of seconds.

The fast suite runs its checks in parallel and prints the output of each one that fails::

    uv run tools/check.py                # fast suite: format, lint, layers, types, tests, lock
    uv run tools/check.py types tests    # only the named checks
    uv run tools/check.py --audit        # fast suite plus pip-audit (needs the network)
    uv run tools/check.py --slow         # fast suite, then mutation testing and the formal model

Git hooks (enable once per clone with ``git config core.hooksPath .githooks``)::

    uv run tools/check.py --pre-commit   # staged Python files, as staged: format and lint
    uv run tools/check.py --pre-push     # fast suite, on a working tree that matches the push

``--pre-push`` refuses to verify something other than what is pushed: every pushed ref must be
``HEAD``, and nothing the checks read may differ from ``HEAD``. ``git push --no-verify`` skips the
hook; CI still runs everything the change touches.
"""

import argparse
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAST: dict[str, list[str]] = {
    "format": ["ruff", "format", "--check", "."],
    "lint": ["ruff", "check", "."],
    "layers": ["lint-imports"],
    "types": ["pyright"],
    "tests": ["pytest", "-q"],
    "lock": ["uv", "lock", "--check", "--offline"],
}
AUDIT: dict[str, list[str]] = {"audit": ["pip-audit"]}

# What the checks read: the pre-push hook needs these to match HEAD.
CHECKED_PATHS = ["src", "tests", "tools", "formal", "pyproject.toml", "uv.lock", ".python-version"]

ZERO_SHA = "0" * 40


@dataclass
class Result:
    """The outcome of one check."""

    name: str
    ok: bool
    seconds: float
    output: str


def run(name: str, argv: list[str], stdin: bytes | None = None) -> Result:
    """Run one check from the repository root; a missing tool is a failure, not a skip."""
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=ROOT, input=stdin, capture_output=True, check=False)
    except FileNotFoundError:
        return Result(name, ok=False, seconds=0.0, output=f"{argv[0]}: not found\n")
    output = (proc.stdout + proc.stderr).decode(errors="replace")
    return Result(name, proc.returncode == 0, time.monotonic() - start, output)


def report(results: list[Result]) -> int:
    """Print one line per check, then the output of each failure; return the exit status."""
    for result in results:
        status = "ok" if result.ok else "FAIL"
        print(f"{status:4} {result.name} ({result.seconds:.1f} s)")
    failed = [r for r in results if not r.ok]
    for result in failed:
        print(f"\n----- {result.name}")
        print(result.output.rstrip())
        print("-----")
    if failed:
        print(f"\n{len(failed)} of {len(results)} checks failed")
    return 1 if failed else 0


def run_parallel(checks: dict[str, list[str]]) -> list[Result]:
    """Run the checks concurrently; results keep the order of ``checks``."""
    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        futures = [pool.submit(run, name, argv) for name, argv in checks.items()]
        return [future.result() for future in futures]


def git(*args: str) -> str:
    """Run a git command in the repository and return its standard output."""
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, check=True, text=True
    ).stdout


def staged_python_files() -> list[str]:
    """Python files added, copied, modified or renamed in the index."""
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    return [name for name in names if name.endswith((".py", ".pyi"))]


def pre_commit() -> int:
    """Format and lint each staged Python file as it is in the index, not in the working tree."""
    results: list[Result] = []
    for name in staged_python_files():
        content = subprocess.run(
            ["git", "show", f":{name}"], cwd=ROOT, capture_output=True, check=True
        ).stdout
        stdin_args = ["--force-exclude", "--stdin-filename", name, "-"]
        results.append(run(f"format {name}", ["ruff", "format", "--diff", *stdin_args], content))
        results.append(run(f"lint {name}", ["ruff", "check", *stdin_args], content))
    failed = [r for r in results if not r.ok]
    if not failed:
        return 0
    status = report(failed)
    print("Fix with `uv run ruff format` and `uv run ruff check --fix`, then stage the result.")
    return status


def pre_push(refs: str) -> int:
    """Check that the working tree is what gets pushed, then run the fast suite on it."""
    head = git("rev-parse", "HEAD").strip()
    for line in refs.splitlines():
        local_ref, local_sha, *_ = line.split()
        if local_sha == ZERO_SHA:  # a deletion pushes nothing
            continue
        commit = git("rev-parse", f"{local_sha}^{{commit}}").strip()
        if commit != head:
            print(f"pre-push: {local_ref} is not HEAD; check it out so the hook verifies it.")
            return 1
    dirty = git("status", "--porcelain", "--", *CHECKED_PATHS)
    if dirty:
        print("pre-push: the working tree differs from HEAD in files the checks read:")
        print(dirty.rstrip())
        print("Commit or stash them, so the checks run on exactly what is pushed.")
        return 1
    return report(run_parallel(FAST))


def slow() -> list[Result]:
    """Mutation testing, then the formal model when ProVerif is installed."""
    results = [run("mutation", ["mutmut", "run"])]
    if results[-1].ok:
        results.append(run("mutation gate", [sys.executable, "-m", "tests.mutation_gate"]))
    if shutil.which("proverif"):
        results.append(run("formal", [sys.executable, "formal/verify.py"]))
    else:
        print("skip formal (proverif not on PATH; CI runs it when formal/ changes)")
    return results


def main() -> int:
    """Parse the arguments and run the selected checks."""
    parser = argparse.ArgumentParser(description="Run the project's checks.")
    known = {**FAST, **AUDIT}
    parser.add_argument("checks", nargs="*", metavar="CHECK", help=f"one of: {', '.join(known)}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit", action="store_true", help="also run pip-audit")
    mode.add_argument("--slow", action="store_true", help="also run mutation testing and ProVerif")
    mode.add_argument("--pre-commit", action="store_true", help="the pre-commit hook")
    mode.add_argument("--pre-push", action="store_true", help="the pre-push hook")
    args = parser.parse_args()

    if args.pre_commit:
        return pre_commit()
    if args.pre_push:
        return pre_push(sys.stdin.read())

    unknown = [name for name in args.checks if name not in known]
    if unknown:
        parser.error(f"unknown check: {', '.join(unknown)}")
    checks = known if args.audit else dict(FAST)
    if args.checks:
        checks = {name: known[name] for name in args.checks}
    results = run_parallel(checks)
    if args.slow and all(r.ok for r in results):
        results += slow()
    return report(results)


if __name__ == "__main__":
    sys.exit(main())
