"""The built wheel carries the whole package (v1 regression 7: a non-editable install lost files).

That includes the desktop app's QML, fonts, icons and licences, which are not Python files.
"""

import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def test_wheel_contains_every_module_and_the_cli(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv builds the wheel, as in CI and releases"
    subprocess.run(  # noqa: S603  # fixed arguments
        [uv, "build", "--wheel", "--out-dir", str(tmp_path), str(ROOT)],
        check=True,
        capture_output=True,
    )
    (wheel,) = tmp_path.glob("qrp2p-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        entry_points = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
        scripts = archive.read(entry_points).decode()
    expected = {
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and (
            path.suffix in {".py", ".qml", ".svg", ".ttf", ".txt"}
            or path.name in {"py.typed", "qmldir"}
        )
    }
    assert {n for n in expected if n.endswith(".qml")}, "the desktop app's QML is in the tree"
    assert expected <= names, sorted(expected - names)
    assert "qrp2p-cli = qrp2p.cli.app:main" in scripts
    assert "qrp2p = qrp2p.ui.app:main" in scripts
