"""Load liboqs-python for the Algorithm Lab without ever letting it build liboqs (DESIGN §13).

liboqs-python 0.16.0.1 has no opt-out from its fallback: when ``import oqs`` finds no loadable
liboqs, it git-clones liboqs and builds it with CMake, and raises ``SystemExit`` if that fails
(docs/v2/research/VERIFIED_FACTS.md). So this module never imports ``oqs`` until it has loaded the
bundled shared library itself. When no bundled library loads, the lab reports "lab algorithms
unavailable" and nothing is built or downloaded.

liboqs is for lab algorithms only: upstream does not recommend it for protecting data.
"""

import ctypes
import importlib
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Final

INSTALL_PATH_ENV: Final = "OQS_INSTALL_PATH"
UNAVAILABLE: Final = "lab algorithms unavailable"

LAB_KEMS: Final = ("HQC-1", "FrodoKEM-640-SHAKE", "Classic-McEliece-348864")
"""One representative per lab-only KEM family (DESIGN §11.9)."""
LAB_SIGNATURES: Final = ("SLH_DSA_PURE_SHA2_128F",)
"""One representative per lab-only signature family (DESIGN §11.9)."""


@dataclass(frozen=True, slots=True)
class OqsStatus:
    """The outcome of :func:`load_oqs`. ``module`` is the ``oqs`` module when available."""

    available: bool
    detail: str
    library: Path | None = None
    module: ModuleType | None = None


def library_candidates(install_dir: Path) -> list[Path]:
    """Where a liboqs install keeps its shared library, in the order liboqs-python looks."""
    if sys.platform == "win32":
        return [install_dir / "bin" / "oqs.dll", install_dir / "bin" / "liboqs.dll"]
    if sys.platform == "darwin":
        return [install_dir / "lib" / "liboqs.dylib"]
    return [install_dir / "lib" / "liboqs.so", install_dir / "lib64" / "liboqs.so"]


def _load_library(install_dir: Path) -> Path | None:
    for candidate in library_candidates(install_dir):
        if not candidate.is_file():
            continue
        try:
            ctypes.CDLL(str(candidate))
        except OSError:
            continue
        return candidate
    return None


def load_oqs(install_dir: Path | None = None) -> OqsStatus:
    """Import liboqs-python against a bundled liboqs, or report why the lab cannot use it.

    Args:
        install_dir: The bundled liboqs install prefix. Defaults to ``$OQS_INSTALL_PATH``.
    """
    if install_dir is None:
        configured = os.environ.get(INSTALL_PATH_ENV)
        if not configured:
            return OqsStatus(available=False, detail=f"{UNAVAILABLE}: no bundled liboqs")
        install_dir = Path(configured)
    library = _load_library(install_dir)
    if library is None:
        return OqsStatus(available=False, detail=f"{UNAVAILABLE}: liboqs did not load")
    # liboqs-python searches $OQS_INSTALL_PATH, so point it at the library we just loaded.
    os.environ[INSTALL_PATH_ENV] = str(install_dir)
    # It attaches a stdout handler to this logger and logs at import; keep the app's stdout clean.
    logging.getLogger("oqs.oqs").disabled = True
    try:
        module = importlib.import_module("oqs")
    except ImportError, OSError, RuntimeError, SystemExit:
        # SystemExit is liboqs-python's own failure signal; it must not end the app.
        return OqsStatus(available=False, detail=f"{UNAVAILABLE}: liboqs-python failed to load")
    return OqsStatus(available=True, detail="liboqs loaded", library=library, module=module)
