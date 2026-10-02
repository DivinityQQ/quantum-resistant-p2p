# Packaging the desktop app

`pip install "qrp2p[gui]"` (or `uv tool install "qrp2p[gui]"`) always works and is how learners
who want to read the code run it. This folder builds native, self-contained apps that need no
Python: [`build.py`](build.py) runs Nuitka with its PySide6 plugin on the current OS.

```bash
uv venv build-env --python 3.14
uv pip install --python build-env ".[gui]" "nuitka==4.2.2" patchelf   # patchelf: Linux only
build-env/bin/python packaging/build.py                                # Windows: build-env\Scripts\python.exe
```

| OS | Result | Notes |
| --- | --- | --- |
| Linux | `dist/qrp2p_app.dist/qrp2p-desktop` | Needs a C compiler; built on the oldest glibc you support |
| Windows | `dist\qrp2p_app.dist\qrp2p-desktop.exe` | Needs MSVC Build Tools (or lets Nuitka fetch MinGW) |
| macOS | `dist/qrp2p_app.app` | One per architecture (arm64, x86_64) |

A build is about 215 MB unpacked (Python, Qt and ICU dominate; unused Qt styles and modules are
left out). Check one with its smoke test, which renders the first screen and, in a new data
directory, creates a throwaway vault and renders the messenger; it exits 1 on any Qt warning:

```bash
QT_QPA_PLATFORM=offscreen dist/qrp2p_app.dist/qrp2p-desktop --data-dir /tmp/smoke --smoke-test /tmp/smoke.png
```

The CI workflow [`build.yml`](../.github/workflows/build.yml) builds all three on demand
(*Actions → Build desktop apps → Run workflow*), runs the smoke test on each, and keeps the
apps and their screenshots as artifacts for 14 days. They are
**unsigned**: Windows SmartScreen warns, and macOS Gatekeeper refuses them until the user allows
them in *System Settings → Privacy & Security*. That is fine for testing (the M3 gate), not for
release.

## Installers

| OS | Format | Tool | State |
| --- | --- | --- | --- |
| Linux | AppImage (Flatpak later) | [`linux/make_appimage.sh`](linux/make_appimage.sh) with `appimagetool` | Built by `build.yml`, smoke-tested |
| macOS | `.dmg` with the `.app` | `hdiutil` | Built by `build.yml`; notarisation needs signing |
| Windows | zip now; MSIX or MSI later | `makeappx` / WiX from the `.dist` folder | MSIX cannot install unsigned, so it waits for signing |

## Code signing plan

Signing ties a release to its publisher; it does not change the protocol's security. Nothing is
signed until the identities exist (owner decisions, see `docs/v2/OWNER_TODO.md`):

1. **macOS:** an Apple Developer Program membership (USD 99 a year) for a *Developer ID
   Application* certificate. Sign with the hardened runtime, notarise with `notarytool`, staple
   the ticket. Without it, Gatekeeper blocks downloads.
2. **Windows:** Azure Trusted Signing (about USD 10 a month; needs an identity validation) or an OV
   code-signing certificate on a hardware token. Sign `qrp2p-desktop.exe` and the installer with
   `signtool` and a timestamp server.
3. **Linux:** no OS signature; publish SHA-256 sums and a signature of them (minisign or GPG), as
   for the PyPI release, which already carries PEP 740 attestations.
4. **CI:** keys live only in GitHub environments that need the owner's approval, like the `pypi`
   environment; signing runs only for `v2.*` tags.

M6 (release 2.0) completes this: signed installers on all three OSes.
