import ast
import re
from enum import IntEnum
from pathlib import Path

import pytest

from qrp2p.core.errors import AdmitReason, CloseReason, FileCancelReason, ProtocolError
from tests.reason_checklist import ADMIT_REASONS, CLOSE_REASONS, FILE_CANCEL_REASONS

ROOT = Path(__file__).resolve().parents[2]

# DESIGN Appendix B, transcribed independently of src/.
APPENDIX_B_CLOSE = {
    0: "normal",
    1: "decrypt_failed",
    2: "unexpected_message",
    3: "oversize",
    4: "schema_error",
    5: "signature_invalid",
    6: "finished_invalid",
    7: "pin_mismatch",
    8: "policy",
    9: "timeout",
    10: "replaced",
    11: "rate_limited",
    12: "internal",
    13: "locked",
    14: "kem_failure",
    15: "reflection",
    16: "invalid_kem_key",
}
APPENDIX_B_ADMIT = {0: "none", 1: "declined", 2: "profile_policy", 3: "timeout", 4: "busy"}
APPENDIX_B_FILE_CANCEL = {
    0: "user",
    1: "size_mismatch",
    2: "hash_mismatch",
    3: "disk_full",
    4: "limit",
}


@pytest.mark.parametrize(
    ("enum", "expected"),
    [
        (CloseReason, APPENDIX_B_CLOSE),
        (AdmitReason, APPENDIX_B_ADMIT),
        (FileCancelReason, APPENDIX_B_FILE_CANCEL),
    ],
)
def test_codes_match_appendix_b(enum: type[IntEnum], expected: dict[int, str]) -> None:
    actual = {member.value: member.name.lower() for member in enum}
    assert actual == expected
    for member in enum:
        assert getattr(member, "label") == expected[member.value]  # noqa: B009


def test_codes_fit_u8() -> None:
    for enum in (CloseReason, AdmitReason, FileCancelReason):
        assert all(0 <= member <= 0xFF for member in enum)


def test_protocol_error_carries_reason_and_detail() -> None:
    error = ProtocolError(CloseReason.KEM_FAILURE, "X25519 low-order public key")
    assert error.reason is CloseReason.KEM_FAILURE
    assert error.detail == "X25519 low-order public key"
    assert str(error) == "kem_failure: X25519 low-order public key"
    assert str(ProtocolError(CloseReason.TIMEOUT)) == "timeout"


_ENTRY = re.compile(r"^(?:(?P<milestone>M\d) )?(?P<path>tests/[\w/]+\.py)::(?P<name>test_\w+)$")


@pytest.mark.parametrize(
    ("enum", "checklist"),
    [
        (CloseReason, CLOSE_REASONS),
        (AdmitReason, ADMIT_REASONS),
        (FileCancelReason, FILE_CANCEL_REASONS),
    ],
)
def test_every_code_has_a_test_in_the_checklist(
    enum: type[IntEnum], checklist: dict[IntEnum, str]
) -> None:
    assert set(checklist) == set(enum)
    for code, entry in checklist.items():
        match = _ENTRY.match(entry)
        assert match, f"{code!r}: malformed checklist entry {entry!r}"
        if match["milestone"]:
            continue  # reserved name; the milestone that makes the code reachable adds the test
        path = ROOT / match["path"]
        assert path.is_file(), f"{code!r}: {path} does not exist"
        names = {
            node.name
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.FunctionDef)
        }
        assert match["name"] in names, f"{code!r}: {entry} names a missing test"


def test_protocol_error_args_keep_reason_and_detail() -> None:
    error = ProtocolError(CloseReason.OVERSIZE, "too big")
    assert error.args == (CloseReason.OVERSIZE, "too big")
