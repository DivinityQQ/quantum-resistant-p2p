"""Loaders for vendored test vectors; every external file is pinned by SHA-256 (see SOURCES.md)."""

import hashlib
import json
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).parent

XWING_SHA256 = "6290fa1276ce0be3bf7505c058242279faba0d500c0ddefab4cbcb1990d6dc5b"
RFC5869_SHA256 = "faeb61bd8baf571f0f42ba3cea5d075c0c7637b9acdd07831dcfa8295472992a"


def _read_pinned(relative: str, sha256: str) -> str:
    raw = (VECTORS / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        msg = f"{relative}: SHA-256 does not match the pin in tests/vectors/SOURCES.md"
        raise AssertionError(msg)
    return raw.decode("ascii")


def load_xwing() -> list[dict[str, bytes]]:
    """Parse the X-Wing draft's vectors: keys start a line, hex continues on indented lines."""
    vectors: list[dict[str, str]] = []
    current: dict[str, str] = {}
    key = ""
    for line in _read_pinned("xwing/test-vectors.txt", XWING_SHA256).splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            current[key] += line.strip()
            continue
        key, *rest = line.split()
        if key == "seed" and current:
            vectors.append(current)
            current = {}
        current[key] = "".join(rest)
    vectors.append(current)
    return [{k: bytes.fromhex(v) for k, v in vec.items()} for vec in vectors]


def load_rfc5869_sha256() -> list[dict[str, bytes | int]]:
    """Parse pyca's NIST-style ``KEY = value`` blocks for RFC 5869 Appendix A.1-A.3."""
    cases: list[dict[str, bytes | int]] = []
    current: dict[str, bytes | int] = {}
    for raw_line in _read_pinned("rfc5869/rfc-5869-HKDF-SHA256.txt", RFC5869_SHA256).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        if name == "COUNT":
            if current:
                cases.append(current)
            current = {}
        elif name == "L":
            current[name] = int(value)
        elif name != "Hash":
            current[name] = bytes.fromhex(value)
    cases.append(current)
    return cases


def load_json(name: str) -> Any:  # noqa: ANN401  # JSON is untyped by nature
    """Load one of our own KAT files."""
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))
