"""RowModel: minimal, correct change signals (checked by Qt's model tester and a shadow copy)."""

from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtTest import QAbstractItemModelTester

from qrp2p.ui.viewmodels.listmodel import RowModel, camel


@dataclass(frozen=True, slots=True)
class Row:
    key: str
    short_id: str = ""


class Shadow:
    """Replays the model's change signals on a copy; it equals the model only if they were right."""

    def __init__(self, model: RowModel[Row]) -> None:
        self.model = model
        self.rows = list(model.rows())
        self.signals: list[str] = []
        model.rowsInserted.connect(self._inserted)
        model.rowsRemoved.connect(self._removed)
        model.rowsMoved.connect(self._moved)
        model.dataChanged.connect(self._changed)
        model.modelReset.connect(lambda: self.signals.append("reset"))

    def _inserted(self, _: QModelIndex, first: int, last: int) -> None:
        self.signals.append("insert")
        self.rows[first:first] = self.model.rows()[first : last + 1]

    def _removed(self, _: QModelIndex, first: int, last: int) -> None:
        self.signals.append("remove")
        del self.rows[first : last + 1]

    def _moved(self, _: QModelIndex, first: int, last: int, __: QModelIndex, dest: int) -> None:
        self.signals.append("move")
        moving = self.rows[first : last + 1]
        del self.rows[first : last + 1]
        at = dest if dest < first else dest - len(moving)
        self.rows[at:at] = moving

    def _changed(self, top: QModelIndex, bottom: QModelIndex, _: list[int]) -> None:
        self.signals.append("change")
        for i in range(top.row(), bottom.row() + 1):
            self.rows[i] = self.model.rows()[i]


@pytest.fixture
def model() -> RowModel[Row]:
    rows: RowModel[Row] = RowModel(Row, lambda r: r.key)
    rows.tester = QAbstractItemModelTester(  # type: ignore[attr-defined]  # kept alive with it
        rows, QAbstractItemModelTester.FailureReportingMode.Warning
    )
    return rows


def rows(spec: str) -> list[Row]:
    """``"a b c"`` → rows a, b, c; ``"a=1"`` gives row a the value 1."""
    out: list[Row] = []
    for item in spec.split():
        key, _, value = item.partition("=")
        out.append(Row(key, value))
    return out


def test_roles_are_camel_case_fields(model: RowModel[Row]) -> None:
    assert sorted(bytes(name.data()).decode() for name in model.roleNames().values()) == [
        "key",
        "shortId",
    ]
    assert camel("a_b_c") == "aBC"
    model.sync([Row("x", "X-1")])
    role = next(r for r, n in model.roleNames().items() if n.data() == b"shortId")
    assert model.data(model.index(0, 0), role) == "X-1"
    assert model.data(model.index(0, 0), Qt.ItemDataRole.DisplayRole) is None
    assert model.data(model.index(5, 0), role) is None
    assert model.get(0) == {"key": "x", "shortId": "X-1"}
    assert model.get(1) == {}
    assert model.indexOf("x") == 0
    assert model.indexOf("y") == -1


@pytest.mark.parametrize(
    ("before", "after", "signals"),
    [
        ("", "a b c", ["insert"]),  # one run, one signal
        ("a b c", "a b c d", ["insert"]),
        ("a b c", "a c", ["remove"]),
        ("a b c d", "a d", ["remove"]),  # a contiguous run: one signal
        ("a b c", "a b=1 c", ["change"]),
        ("a b c", "a b c", []),
        ("a b c", "c a b", ["move"]),
        ("a b c", "", ["remove"]),
        ("a b c", "x a y c", ["remove", "insert", "insert"]),
    ],
)
def test_minimal_signals(model: RowModel[Row], before: str, after: str, signals: list[str]) -> None:
    model.sync(rows(before))
    shadow = Shadow(model)
    model.sync(rows(after))
    assert list(model.rows()) == rows(after)
    assert shadow.rows == rows(after)
    assert shadow.signals == signals


def test_count_follows_the_rows(model: RowModel[Row]) -> None:
    counts: list[int] = []
    model.countChanged.connect(lambda: counts.append(model.count))  # type: ignore[attr-defined]
    model.sync(rows("a b"))
    model.sync(rows("a b=1"))  # a change is not a count change
    model.clear()
    assert counts == [2, 0]


def test_duplicate_keys_are_refused(model: RowModel[Row]) -> None:
    with pytest.raises(ValueError, match="unique"):
        model.sync(rows("a a"))


def test_rows_must_be_dataclasses() -> None:
    with pytest.raises(TypeError):
        RowModel(str, str)


specs = st.lists(
    st.tuples(st.sampled_from("abcdefgh"), st.sampled_from(["", "1", "2"])),
    max_size=8,
    unique_by=lambda item: item[0],
).map(lambda items: [Row(k, v) for k, v in items])


@settings(max_examples=300, deadline=None)
@given(steps=st.lists(specs, min_size=1, max_size=6))
def test_any_sequence_of_syncs(steps: list[list[Row]]) -> None:
    model: RowModel[Row] = RowModel(Row, lambda r: r.key)
    tester = QAbstractItemModelTester(model, QAbstractItemModelTester.FailureReportingMode.Warning)
    shadow = Shadow(model)
    for target in steps:
        model.sync(target)
        assert list(model.rows()) == target
        assert shadow.rows == target
        assert model.rowCount() == len(target)
    del tester
