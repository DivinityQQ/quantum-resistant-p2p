import base64
import copy
import json
import logging
import pickle
import traceback
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from qrp2p.core.crypto.secret import Secret

VALUE = bytes(range(0x41, 0x61))  # printable, so a leak would show up in text


def leak_forms(value: bytes) -> list[str]:
    """Every textual form a leak could take (DESIGN §15, canary leak test)."""
    return [
        value.hex(),
        value.hex().upper(),
        base64.b64encode(value).decode(),
        value.decode("latin-1"),
        repr(value),
        str(list(value)),
    ]


def assert_no_leak(text: str, value: bytes = VALUE) -> None:
    for form in leak_forms(value):
        assert form not in text


def test_reveal_returns_the_value() -> None:
    assert Secret(VALUE, "k").reveal() == VALUE


def test_value_is_copied_from_mutable_input() -> None:
    source = bytearray(VALUE)
    secret = Secret(source, "k")
    source[0] ^= 0xFF
    assert secret.reveal() == VALUE


def test_label_and_size_are_public() -> None:
    secret = Secret(VALUE, "hs_R")
    assert secret.label == "hs_R"
    assert len(secret) == len(VALUE)
    assert "hs_R" in repr(secret)
    assert "32 B" in repr(secret)


@pytest.mark.parametrize(
    "render",
    [
        repr,
        str,
        ascii,
        lambda s: f"{s}",
        lambda s: f"{s!r}",
        lambda s: f"{s!s}",
        lambda s: f"{s:x}",
        lambda s: f"{s:>80}",
        lambda s: "%s %r" % (s, s),  # noqa: UP031  # the old formatting path must be covered too
        "{}".format,
        lambda s: str([s, {"k": s}, (s,)]),
    ],
)
def test_no_textual_form_shows_the_value(render: Callable[[Secret], str]) -> None:
    assert_no_leak(render(Secret(VALUE, "k")))


def test_exception_text_and_traceback_locals_do_not_leak() -> None:
    def fail(secret: Secret) -> None:
        msg = f"failed with {secret}"
        raise ValueError(msg)

    with pytest.raises(ValueError, match="failed with") as info:
        fail(Secret(VALUE, "k"))
    assert_no_leak(str(info.value))
    rendered = "".join(
        traceback.TracebackException.from_exception(info.value, capture_locals=True).format()
    )
    assert "Secret('k'" in rendered
    assert_no_leak(rendered)


def test_logging_does_not_leak(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("qrp2p.test").debug(
            "secret is %s / %r", Secret(VALUE, "k"), [Secret(VALUE, "k")]
        )
    assert caplog.text
    assert_no_leak(caplog.text)


@given(st.binary(min_size=1, max_size=128), st.text(max_size=20))
def test_repr_never_contains_value_for_any_bytes(value: bytes, label: str) -> None:
    text = repr(Secret(value, label))
    if len(value) >= 4:  # shorter values can collide with label or size text by chance
        assert value.hex() not in text.replace(label, "")


def test_equality_is_by_value_and_only_between_secrets() -> None:
    assert Secret(VALUE, "a") == Secret(VALUE, "b")
    assert Secret(VALUE, "a") != Secret(VALUE[:-1] + b"\0", "a")
    assert Secret(VALUE, "a") != Secret(VALUE[:-1], "a")
    assert Secret(VALUE, "a") != VALUE  # never equal to raw bytes


def test_equality_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return a == b

    monkeypatch.setattr("qrp2p.core.crypto.secret.hmac.compare_digest", spy)
    assert Secret(VALUE, "a") == Secret(VALUE, "b")
    assert calls == [(VALUE, VALUE)]


def test_not_hashable() -> None:
    with pytest.raises(TypeError):
        hash(Secret(VALUE, "k"))


@pytest.mark.parametrize(
    "operation",
    [
        pickle.dumps,
        lambda s: pickle.dumps(s, protocol=0),
        copy.copy,
        copy.deepcopy,
        bytes,
        json.dumps,
        vars,
    ],
)
def test_cannot_be_serialised_copied_or_converted(operation: object) -> None:
    assert callable(operation)
    with pytest.raises(TypeError):
        operation(Secret(VALUE, "k"))


def test_immutable() -> None:
    secret = Secret(VALUE, "k")
    with pytest.raises(AttributeError):
        secret._value = b"x"
    with pytest.raises(AttributeError):
        del secret._label


def test_cannot_be_subclassed() -> None:
    with pytest.raises(TypeError):

        class Leaky(Secret):  # pyright: ignore[reportGeneralTypeIssues]
            pass
