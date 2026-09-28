"""Mutation-testing gate for ``qrp2p.core`` (DESIGN §15 row 4; IMPLEMENTATION_PLAN M1).

Run after ``uv run mutmut run``::

    uv run python -m tests.mutation_gate

Every surviving mutant must be one of:

- **message-only**: it changes nothing but the text of an exception message or a string literal
  that no check depends on (error details, trace labels), or
- **allowlisted**: listed in ``tests/mutation_allowlist.txt`` with the reason it is equivalent or
  harmless.

Anything else fails the gate: some check can be removed or inverted without a test noticing.
"""

import ast
import difflib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANTS = ROOT / "mutants" / "src"
ALLOWLIST = Path(__file__).with_name("mutation_allowlist.txt")

_STRING = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
_MESSAGE_ARG = re.compile(r",\s*(?:'(?:[^'\\]|\\.)*'|None)\)")


@dataclass(frozen=True)
class Survivor:
    """One surviving mutant and the lines it changed."""

    key: str
    function: str
    removed: tuple[str, ...]
    added: tuple[str, ...]

    @property
    def signature(self) -> str:
        """``function :: removed => added``, as written in the allowlist."""
        removed, added = " | ".join(self.removed), " | ".join(self.added)
        return f"{self.function} :: {removed} => {added}".rstrip()


def _functions(source: str) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def survivors() -> list[Survivor]:
    """Read mutmut's results and the mutated sources."""
    found: list[Survivor] = []
    for meta in sorted(MUTANTS.rglob("*.py.meta")):
        exit_codes: dict[str, int] = json.loads(meta.read_text())["exit_code_by_key"]
        functions = _functions(meta.with_suffix("").read_text())
        for key, code in exit_codes.items():
            if code != 0:
                continue
            name = key.rsplit(".", 1)[1]
            base = name.rsplit("__mutmut_", 1)[0]
            original, mutant = functions[base + "__mutmut_orig"], functions[name]
            mutant.name = original.name
            diff = [
                line
                for line in difflib.unified_diff(
                    ast.unparse(original).splitlines(), ast.unparse(mutant).splitlines(), n=0
                )
                if line[:1] in "+-" and not line.startswith(("+++", "---"))
            ]
            function = key.rsplit("__mutmut_", 1)[0].replace("xǁ", "").replace("ǁ", ".")
            function = re.sub(r"\.x_", ".", function)
            found.append(
                Survivor(
                    key,
                    function,
                    tuple(line[1:].strip() for line in diff if line[0] == "-"),
                    tuple(line[1:].strip() for line in diff if line[0] == "+"),
                )
            )
    return found


def _normalise(line: str) -> str:
    """Strings (including f-strings) become ``S``; ``'big'`` byte order is Python's default."""
    line = line.replace(", 'big')", ")").replace("'big')", ")")
    line = _STRING.sub("S", line).replace("fS", "S")
    return re.sub(r",\s*name=S\)", ")", line)


def message_only(survivor: Survivor) -> bool:
    """True if the mutant only changes texts: messages, labels, names; or the default byte order.

    A string replaced by ``None`` counts as a text change: every such string in ``qrp2p.core``
    is a message or a label (the gate would show a check whose outcome depends on one).
    """
    removed = [_normalise(line) for line in survivor.removed]
    added = [_normalise(line) for line in survivor.added]
    if removed == added:
        return True
    if len(removed) == len(added) == 1:
        before, after = removed[0], added[0]
        if "S" in before and before.replace("S", "None") == after:
            return True
        if before.startswith("raise ") and before.replace("(msg)", "(None)") == after:
            return True
    if len(survivor.removed) != 1 or len(survivor.added) != 1:
        return False
    before, after = survivor.removed[0], survivor.added[0]
    if "Error(" not in before:
        return False
    strip = lambda line: _MESSAGE_ARG.sub(")", line).replace("(None)", "()")  # noqa: E731
    return strip(before) == strip(after) or strip(before) == strip(after.replace("(None,", "("))


def allowlist() -> dict[str, str]:
    """``signature -> reason`` from the allowlist file."""
    entries: dict[str, str] = {}
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        signature, _, reason = line.partition("  # ")
        entries[signature.strip()] = reason.strip()
    return entries


def main() -> int:
    """Print the survivors that matter; fail if any is not allowlisted."""
    if not MUTANTS.exists():
        print("no mutants/ directory: run `uv run mutmut run` first", file=sys.stderr)
        return 2
    found = survivors()
    allowed = allowlist()
    messages = [s for s in found if message_only(s)]
    code = [s for s in found if not message_only(s)]
    unexplained = [s for s in code if s.signature not in allowed]
    stale = sorted(set(allowed) - {s.signature for s in code})
    total = sum(
        len(json.loads(m.read_text())["exit_code_by_key"]) for m in MUTANTS.rglob("*.py.meta")
    )
    print(f"{total} mutants, {len(found)} survived: {len(messages)} message-only, ", end="")
    print(f"{len(code) - len(unexplained)} allowlisted, {len(unexplained)} unexplained")
    for survivor in unexplained:
        print(f"  UNEXPLAINED {survivor.key}\n    {survivor.signature}")
    for signature in stale:
        print(f"  stale allowlist entry (no longer survives): {signature}")
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
