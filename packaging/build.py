r"""Build the desktop app as a native, self-contained folder with Nuitka, on the current OS.

Nuitka's PySide6 plugin is what ``pyside6-deploy`` drives; calling it directly keeps the QML,
fonts and icons as package data (where ``qrp2p.ui.app`` looks for them) and every option in one
reviewed place. Run it from a *separate* environment so Nuitka and its caches stay out of the
development one::

    uv venv build-env --python 3.14
    uv pip install --python build-env ".[gui]" "nuitka==4.2.2" patchelf  # patchelf: Linux only
    build-env/bin/python packaging/build.py --prune-build-env   # Windows: build-env\Scripts\python.exe

The result is ``dist/qrp2p_app.dist/`` (Linux, Windows) or ``dist/qrp2p_app.app`` (macOS):
unsigned, for testing on the OS that built it. Installers and signing: packaging/README.md.
"""

import argparse
import os
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Final

HERE: Final = Path(__file__).resolve().parent
ROOT: Final = HERE.parent

# Qt's QML modules the app never imports; the plugin would otherwise ship all of them.
UNUSED_QML: Final = [
    "QtQuick3D", "QtQuick/Controls/FluentWinUI3", "QtQuick/Controls/Fusion",
    "QtQuick/Controls/Imagine", "QtQuick/Controls/Material", "QtQuick/Controls/Universal",
    "QtQuick/VirtualKeyboard", "QtQuick/Scene2D", "QtQuick/Scene3D", "QtQuick/Particles",
    "QtQuick/Pdf", "QtQuick/Timeline", "QtQuick/LocalStorage", "QtQuick/VectorImage",
    "QtQuick/tooling", "QtTest", "QtQuickEffectMaker", "Qt/labs",
    # Shipped as QML plugins by PySide6-Essentials, but their libraries are in the Addons:
    # macOS builds fail to resolve them.
    "QtQml/StateMachine", "QtQml/XmlListModel",
]  # fmt: skip


# Qt libraries pulled in only by those modules or by Qt's own tools (the smoke test proves the
# rest suffice): Linux and Windows name them Qt6<Name>, macOS frameworks Qt<Name>.
UNUSED_LIBRARIES: Final = [
    "Labs", "EglFS", "EglFs", "QuickControls2FluentWinUI3", "QuickControls2Fusion",
    "QuickControls2Imagine", "QuickControls2Material", "QuickControls2Universal",
    "QuickParticles", "QuickTimeline", "QuickTest", "Test", "Sql", "QmlLocalStorage",
    "QmlXmlListModel", "WaylandCompositor", "QuickVectorImage", "QuickShapesDesignHelpers",
]  # fmt: skip


def nuitka_command(out: Path) -> list[str]:
    """The Nuitka invocation for this OS."""
    import qrp2p  # noqa: PLC0415  # the installed package, not the checkout

    resources = Path(qrp2p.__file__).resolve().parent / "ui" / "resources"
    release = version("qrp2p").split(".dev")[0]
    command = [
        sys.executable,
        "-m",
        "nuitka",
        str(HERE / "qrp2p_app.py"),
        "--mode=app" if sys.platform == "darwin" else "--mode=standalone",
        "--enable-plugin=pyside6",
        # QML needs the qml plugin set; platform, image and theme plugins come by default.
        "--include-qt-plugins=qml",
        "--noinclude-qt-translations",
        # Our QML, fonts, icons and licences are package data, read beside qrp2p.ui.app.
        "--include-package-data=qrp2p",
        # keyring finds its OS backends through entry points: keep them and their metadata.
        "--include-package=keyring.backends",
        "--include-distribution-metadata=keyring",
        "--include-distribution-metadata=qrp2p",
        # The terminal front end and the lab's liboqs are not part of the desktop app.
        "--nofollow-import-to=qrp2p.cli",
        "--nofollow-import-to=prompt_toolkit",
        "--nofollow-import-to=oqs",
        f"--output-dir={out}",
        # Not "qrp2p": that is the package's data folder beside it (and macOS ignores case).
        "--output-filename=qrp2p-desktop",
        "--product-name=QRP2P",
        f"--product-version={release}",
        "--file-description=QRP2P: LAN messenger with a hybrid post-quantum channel",
        "--copyright=MIT licence; Inter (SIL OFL 1.1); Lucide icons (ISC)",
        "--assume-yes-for-downloads",
    ]
    for module in UNUSED_QML:
        command += [
            f"--noinclude-data-files=*/qml/{module}/*",
            f"--noinclude-dlls=*/qml/{module}/*",
        ]
    for library in UNUSED_LIBRARIES:
        command += [f"--noinclude-dlls=*Qt6{library}*", f"--noinclude-dlls=*Qt{library}.framework*"]
    if sys.platform == "win32":
        command += [
            "--windows-console-mode=disable",
            f"--windows-icon-from-ico={resources / 'app-icon.ico'}",
        ]
    elif sys.platform == "darwin":
        command += [
            "--macos-app-name=QRP2P",
            f"--macos-app-icon={resources / 'app-icon.icns'}",
            f"--macos-app-version={release}",
        ]
    # Linux: the window icon is set at run time; desktop integration comes with the AppImage.
    return command


def prune_build_env() -> list[Path]:
    """Delete the unused QML modules from *this* environment's PySide6; returns what went.

    Nuitka inspects every QML plugin's libraries before it applies exclusions, and on macOS a
    plugin whose library is in PySide6-Addons (QtQml/StateMachine) stops the build. Only for a
    throwaway build environment: the project's own ``.venv`` is refused.
    """
    if Path(sys.prefix).resolve() == (ROOT / ".venv").resolve():
        msg = "refusing to prune the development environment; use a separate build-env"
        raise SystemExit(msg)
    import PySide6  # noqa: PLC0415  # the build environment's copy

    qml = Path(PySide6.__file__).resolve().parent / "Qt" / "qml"
    removed: list[Path] = []
    for module in UNUSED_QML:
        target = qml / module
        if target.is_dir():
            shutil.rmtree(target)
            removed.append(target)
    return removed


def main() -> int:
    """Run Nuitka; print the command first."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dist", help="output folder")
    parser.add_argument("--dry-run", action="store_true", help="print the command only")
    parser.add_argument(
        "--prune-build-env",
        action="store_true",
        help="first delete unused QML modules from this (throwaway) environment; needed on macOS",
    )
    args = parser.parse_args()
    if args.prune_build_env and not args.dry_run:
        for path in prune_build_env():
            print(f"pruned {path}")
    command = nuitka_command(args.out.resolve())
    print(f"qrp2p {version('qrp2p')}, PySide6 {version('PySide6-Essentials')}")
    print(" ".join(command))
    if args.dry_run:
        return 0
    # Tools installed into the build environment (patchelf on Linux) are found on its PATH.
    tools = str(Path(sys.executable).parent)
    env = os.environ | {"PATH": os.pathsep.join([tools, os.environ.get("PATH", "")])}
    return subprocess.run(command, check=False, env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
