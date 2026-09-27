"""Run every ProVerif model and check each result against the model's EXPECT lines.

Each query in a model is preceded by a line such as::

    (* EXPECT true: inj-event(IAdmitOk *)

meaning: the one ``RESULT`` line whose query starts with ``inj-event(IAdmitOk`` must say
``is true``. ``false`` marks an expected attack in a weakened model. ``reachable`` is for the
sanity checks that a model is not vacuous (``query event(Done)``): it fails only on ``is true``
(the event can never happen). ProVerif answers ``is false`` when it also reconstructs a trace,
and ``cannot be proved`` when it derives the event but cannot rebuild a concrete trace; either
shows that the derivation reaches the event. A result without an EXPECT line, a missing result,
or "cannot be proved" for a true/false expectation fails the run.

Usage::

    python formal/verify.py [--proverif PATH] [--log-dir DIR] [MODEL.pv ...]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

FORMAL = Path(__file__).resolve().parent
LIBRARY = FORMAL / "qrp2p"  # ProVerif adds the .pvl extension
TIMEOUT_S = 3600

EXPECT_RE = re.compile(r"\(\* EXPECT (true|false|reachable): (.+?) \*\)")
RESULT_RE = re.compile(r"^RESULT (.*?) (is true|is false|cannot be proved)\.$")
EXCERPT_LINES = 60


@dataclass
class Outcome:
    """What one model run produced."""

    model: Path
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    results: list[tuple[str, str]] = field(default_factory=list)
    output: str = ""
    unexpected: list[str] = field(default_factory=list)


def expectations(model: Path) -> list[tuple[str, str]]:
    """Return ``(expected verdict, query prefix)`` for each EXPECT line of ``model``."""
    return EXPECT_RE.findall(model.read_text(encoding="utf-8"))


ACCEPTED = {
    "true": {"is true"},
    "false": {"is false"},
    "reachable": {"is false", "cannot be proved"},
}


def check(model: Path, output: str) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Compare ProVerif's RESULT lines with the model's expectations."""
    results = [
        (m.group(1), m.group(2)) for line in output.splitlines() if (m := RESULT_RE.match(line))
    ]
    errors: list[str] = []
    unexpected: list[str] = []
    expected = expectations(model)
    if not expected:
        errors.append("no EXPECT lines")
    used: set[int] = set()
    for want, prefix in expected:
        hits = [i for i, (query, _) in enumerate(results) if query.startswith(prefix)]
        if len(hits) != 1:
            errors.append(f"{len(hits)} results match EXPECT prefix {prefix!r}")
            continue
        used.add(hits[0])
        query, verdict = results[hits[0]]
        if verdict not in ACCEPTED[want]:
            errors.append(f"{query}: {verdict}, expected {want}")
            unexpected.append(query)
    errors.extend(
        f"result without an EXPECT line: {query} {verdict}"
        for i, (query, verdict) in enumerate(results)
        if i not in used
    )
    return results, errors, unexpected


def excerpt(output: str, query: str) -> str:
    """ProVerif's output for one query: the lines just before its RESULT line."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"RESULT {query} "):
            start = i
            while start > 0 and not lines[start - 1].startswith("-- "):
                start -= 1
            return "\n".join(lines[max(start - 1, i - EXCERPT_LINES) : i + 1])
    return "(no output for this query)"


def run(proverif: str, model: Path) -> Outcome:
    """Run ProVerif on one model."""
    outcome = Outcome(model)
    start = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603  # a fixed binary on our own model files
            [proverif, "-lib", str(LIBRARY), str(model)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        outcome.errors.append(f"timed out after {TIMEOUT_S} s")
        return outcome
    outcome.seconds = time.monotonic() - start
    outcome.output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        outcome.errors.append(f"proverif exited with {proc.returncode}")
    outcome.results, errors, outcome.unexpected = check(model, outcome.output)
    outcome.errors.extend(errors)
    return outcome


def main() -> int:
    """Run the models given on the command line, or all of them."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("models", nargs="*", type=Path)
    parser.add_argument("--proverif", default=os.environ.get("PROVERIF", "proverif"))
    parser.add_argument("--log-dir", type=Path, help="write each model's full output here")
    args = parser.parse_args()

    proverif = shutil.which(args.proverif)
    if proverif is None:
        print(f"ProVerif not found: {args.proverif}", file=sys.stderr)
        return 2
    models = args.models or sorted(
        [*FORMAL.glob("*.pv"), *FORMAL.glob("weakened/*.pv"), *FORMAL.glob("redundant/*.pv")]
    )

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 1) as pool:
        outcomes = list(pool.map(lambda m: run(proverif, m), models))

    failed = 0
    for outcome in outcomes:
        name = outcome.model.resolve().relative_to(FORMAL).as_posix()
        status = "FAIL" if outcome.errors else "ok"
        print(f"{status:4} {name} ({outcome.seconds:.1f} s)")
        for query, verdict in outcome.results:
            print(f"       {verdict:17} {query}")
        for error in outcome.errors:
            print(f"     ! {error}")
        for query in outcome.unexpected:
            print(f"\n----- {name}: {query}")
            print(excerpt(outcome.output, query))
            print("-----\n")
        if args.log_dir:
            log = args.log_dir / (name.replace("/", "__") + ".log")
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(outcome.output, encoding="utf-8")
        failed += bool(outcome.errors)
    print(f"\n{len(outcomes) - failed} of {len(outcomes)} models as expected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
