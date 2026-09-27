"""The liboqs loader (DESIGN §13; IMPLEMENTATION_PLAN M0.10).

The unavailable paths run in a fresh interpreter, so an ``oqs`` import elsewhere in the test run
cannot hide one here, and the child fails loudly if anything tries to spawn a build.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from qrp2p.lab.oqs_loader import (
    INSTALL_PATH_ENV,
    LAB_KEMS,
    LAB_SIGNATURES,
    library_candidates,
    load_oqs,
)

CHILD = textwrap.dedent(
    """
    import json, subprocess, sys
    from pathlib import Path

    def refuse(*args, **kwargs):
        raise AssertionError("the loader tried to run a subprocess (a liboqs build)")

    subprocess.run = subprocess.Popen = subprocess.check_call = refuse
    from qrp2p.lab.oqs_loader import load_oqs
    arg = sys.argv[1]
    status = load_oqs(Path(arg) if arg else None)
    print(json.dumps({"available": status.available, "detail": status.detail,
                      "imported": "oqs" in sys.modules}))
    """
)


def run_child(tmp_path: Path, install_dir: str, env_value: str | None) -> dict[str, object]:
    env = {k: v for k, v in os.environ.items() if k != INSTALL_PATH_ENV}
    env["HOME"] = env["USERPROFILE"] = str(tmp_path)  # liboqs-python's fallback is ~/_oqs
    if env_value is not None:
        env[INSTALL_PATH_ENV] = env_value
    result = subprocess.run(  # noqa: S603  # our own interpreter with a fixed script
        [sys.executable, "-c", CHILD, install_dir],
        capture_output=True,
        text=True,
        env=env,
        check=True,
        timeout=60,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_no_bundled_library_reports_unavailable(tmp_path: Path) -> None:
    status = run_child(tmp_path, "", None)
    assert status == {
        "available": False,
        "detail": "lab algorithms unavailable: no bundled liboqs",
        "imported": False,
    }


def test_empty_install_dir_reports_unavailable(tmp_path: Path) -> None:
    status = run_child(tmp_path, "", str(tmp_path / "missing"))
    assert status["available"] is False
    assert status["imported"] is False


def test_broken_library_reports_unavailable_without_importing(tmp_path: Path) -> None:
    for candidate in library_candidates(tmp_path / "install"):
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(b"not a shared library")
    status = run_child(tmp_path, str(tmp_path / "install"), None)
    assert status == {
        "available": False,
        "detail": "lab algorithms unavailable: liboqs did not load",
        "imported": False,
    }


def test_candidates_follow_liboqs_python_layout(tmp_path: Path) -> None:
    names = [p.relative_to(tmp_path).as_posix() for p in library_candidates(tmp_path)]
    if sys.platform == "win32":
        assert names == ["bin/oqs.dll", "bin/liboqs.dll"]
    elif sys.platform == "darwin":
        assert names == ["lib/liboqs.dylib"]
    else:
        assert names == ["lib/liboqs.so", "lib64/liboqs.so"]


@pytest.mark.liboqs
def test_lab_algorithms_load_and_work() -> None:
    """Runs where a bundled liboqs exists (the CI liboqs job sets OQS_INSTALL_PATH)."""
    if not os.environ.get(INSTALL_PATH_ENV):
        if os.environ.get("QRP2P_REQUIRE_LIBOQS") == "1":
            pytest.fail("QRP2P_REQUIRE_LIBOQS=1 but OQS_INSTALL_PATH is not set")
        pytest.skip("no bundled liboqs (set OQS_INSTALL_PATH)")
    status = load_oqs()
    assert status.available, status.detail
    oqs = status.module
    assert oqs is not None
    assert oqs.oqs_version().startswith("0.16.")
    for name in LAB_KEMS:
        with oqs.KeyEncapsulation(name) as receiver:
            public = receiver.generate_keypair()
            with oqs.KeyEncapsulation(name) as sender:
                ciphertext, secret = sender.encap_secret(public)
            assert receiver.decap_secret(ciphertext) == secret
    for name in LAB_SIGNATURES:
        with oqs.Signature(name) as signer:
            public = signer.generate_keypair()
            signature = signer.sign(b"lab")
            with oqs.Signature(name) as verifier:
                assert verifier.verify(b"lab", signature, public)
                assert not verifier.verify(b"lab!", signature, public)
