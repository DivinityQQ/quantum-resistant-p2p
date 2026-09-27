"""Run every ProVerif model and check each result against the model's EXPECT lines.

Each query in a model is preceded by a line such as::

    (* EXPECT true: inj-event(IAdmitOk *)

meaning: the one ``RESULT`` line whose query starts with ``inj-event(IAdmitOk`` must say
``is true``. ``false`` marks an expected attack (weakened models) or a reachable event (sanity
checks that the model is not vacuous). A result without an EXPECT line, a missing result, or
"cannot be proved" fails the run.

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

EXPECT_RE = re.compile(r"\(\* EXPECT (true|false): (.+?) \*\)")
RESULT_RE = re.compile(r"^RESULT (.*?) (is true|is false|cannot be proved)\.$")


@dataclass
class Outcome:
    """What one model run produced."""

    model: Path
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    results: list[tuple[str, str]] = field(default_factory=list)
    output: str = ""


def expectations(model: Path) -> list[tuple[bool, str]]:
    """Return ``(expected verdict, query prefix)`` for each EXPECT line of ``model``."""
    text = model.read_text(encoding="utf-8")
    return [(verdict == "true", prefix) for verdict, prefix in EXPECT_RE.findall(text)]


def check(model: Path, output: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Compare ProVerif's RESULT lines with the model's expectations."""
    results = [
        (m.group(1), m.group(2)) for line in output.splitlines() if (m := RESULT_RE.match(line))
    ]
    errors: list[str] = []
    expected = expectations(model)
    if not expected:
        errors.append("no EXPECT lines")
    used: set[int] = set()
    for want_true, prefix in expected:
        hits = [i for i, (query, _) in enumerate(results) if query.startswith(prefix)]
        if len(hits) != 1:
            errors.append(f"{len(hits)} results match EXPECT prefix {prefix!r}")
            continue
        used.add(hits[0])
        query, verdict = results[hits[0]]
        want = "is true" if want_true else "is false"
        if verdict != want:
            errors.append(f"{query}: {verdict}, expected {want}")
    errors.extend(
        f"result without an EXPECT line: {query} {verdict}"
        for i, (query, verdict) in enumerate(results)
        if i not in used
    )
    return results, errors


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
    outcome.results, errors = check(model, outcome.output)
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
    models = args.models or sorted([*FORMAL.glob("*.pv"), *FORMAL.glob("weakened/*.pv")])

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
        if args.log_dir:
            log = args.log_dir / (name.replace("/", "__") + ".log")
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(outcome.output, encoding="utf-8")
        failed += bool(outcome.errors)
    print(f"\n{len(outcomes) - failed} of {len(outcomes)} models as expected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
