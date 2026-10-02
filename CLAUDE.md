# CLAUDE.md — QRP2P v2

This repository is a ground-up rewrite (v2) of the quantum-resistant P2P messenger. v1 is kept in
history at the tag `v1-final`; none of its code is in the tree. **Do not build on v1 code.**
`main` accepts changes only through pull requests with green CI (ruleset: `.github/rulesets/main.json`).

## Read first

1. `docs/v2/DESIGN.md` — the normative spec (MUST/SHOULD). It is the source of truth.
2. `docs/v2/IMPLEMENTATION_PLAN.md` — phases M0–M6, task tables and gates, and where work stands.
3. `docs/v2/research/VERIFIED_FACTS.md` — library behaviour the design relies on, with evidence.
4. For desktop or learning-layer work, `docs/v2/UI_DESIGN.md` — the agreed visual language,
   light/dark mockups, interaction contracts and implementation acceptance criteria.

## What this project is

A LAN-only, two-party desktop messenger (Python, PySide6/QML) with a hybrid post-quantum channel:

- X-Wing KEM; Ed25519 + ML-DSA-65 hybrid signatures; ChaCha20-Poly1305;
- a four-message SIGMA-I / TLS 1.3-style handshake with an admission step;
- a signed PQ rekey.

Its differentiator is the **learning layer**: Inspector, glass-box sessions with mutual consent,
solo lab, Attack Lab, weakened engines, Algorithm Lab and lessons.

## Rules

- **Spec first.** If code needs to differ from DESIGN.md, update DESIGN.md in the same change and
  say why in the commit message. Never let them drift.
- **No new cryptography.** Only the constructions in DESIGN §4 and §7–§8. Crypto comes from
  `cryptography` (pyca) and stdlib `hashlib`; lab-only algorithms from liboqs-python.
- **Exact bytes.** Anything hashed, signed or used as AEAD associated data uses the fixed layouts
  in DESIGN §5, §7 and §10. `msgspec` is only for Inner payloads (DESIGN §8.2) and vault row
  plaintexts and `vault.json` (§10), never for bytes that are hashed, signed or associated data.
- **Sans-I/O core.** `qrp2p.core` has no sockets, threads, clocks, Qt or global randomness; time
  and randomness are injected. Respect the import rules in DESIGN §12.2.
- **Fail closed with a named reason** (DESIGN Appendix B). No bare `except`, no silent fallback, no
  retry on the same keys.
- **Secrets:** wrap key material in `Secret`; never log it, format it, or put it in exceptions.
  Only `RevealingProvider` may emit secret values, and only in glass-box or lab sessions.
- **Peer data is untrusted:** size-check before allocating; render peer text as plain text only
  (on a terminal through `services.text.display_text`); the sender is the session, never a payload
  field.
- **Tests come with every change.** Security checks need a test that fails if the check is
  removed (mutation testing enforces this in `core/`).
- **Model first.** A change to the handshake, record layer or rekey changes `formal/` in the same
  PR; every weakened model must still yield its attack.
- **Weakened engines and `LAB-CLASSICAL`** live only under `qrp2p/lab/` and must never be reachable
  from real sessions. Real sessions build their provider with `REAL_PROFILES` only.
- **Never `import oqs` directly.** Use `qrp2p.lab.oqs_loader.load_oqs()`; liboqs-python otherwise
  builds liboqs at import time and can raise `SystemExit`.

## Commands

```bash
uv sync --all-extras --dev          # install
git config core.hooksPath .githooks # once per clone: pre-commit and pre-push hooks
uv run tools/check.py               # the fast suite, about 5 s: run it after every change
uv run tools/check.py types tests   # only some: format, lint, layers, types, tests, lock, audit
uv run tools/check.py --audit       # plus pip-audit (network)
uv run tools/check.py --slow        # plus mutation testing, and ProVerif if installed
uv run pytest tests/core -k record  # iterate on a subset
```

**Where checks run.** The pre-commit hook formats and lints the staged Python files; the pre-push
hook runs the fast suite on exactly what is pushed (a clean tree at `HEAD`). CI is the backstop:
Windows and macOS, liboqs, pip-audit, mutation testing and ProVerif, each job only when its inputs
changed (see the `changes` job in `.github/workflows/ci.yml`), and everything weekly. The `main`
ruleset requires the single check "CI result". Do not push with `--no-verify`.

Lab-algorithm test against a local liboqs build (CI builds it in the `liboqs` job):

```bash
OQS_INSTALL_PATH=/path/to/liboqs-install QRP2P_REQUIRE_LIBOQS=1 uv run pytest -m liboqs
```

Run a node (M2): `uv run qrp2p-cli --data-dir /tmp/a` (a second node needs another data directory
and, on one machine, another `--port`). The desktop app (M3): `uv run qrp2p --data-dir /tmp/b
--port 47471` (`--dev-preview` adds the Inspector layout preview). UI tests run offscreen
(`tests/ui/conftest.py`); any Qt warning fails them. Native builds: `packaging/README.md`. Real-multicast discovery test: `QRP2P_TEST_MDNS=1 uv run
pytest tests/services/test_discovery.py`.

Formal model (ProVerif 2.05; CI runs it when `formal/` or `ci.yml` changes, and weekly):

```bash
python formal/verify.py                 # every model; checks each result against its EXPECT line
```

Mutation testing of `qrp2p.core` (about 6 min; CI runs it when `core/`, `tests/` or dependencies
change). Run it locally before pushing a change to `core/`:

```bash
uv run mutmut run && uv run python -m tests.mutation_gate
```

A surviving mutant that changes code (not just a message) fails the gate unless
`tests/mutation_allowlist.txt` explains why it is equivalent. Prefer a test to an allowlist entry.

Our own known-answer files are regenerated only for a deliberate spec change:
`uv run python -m tests.vectors.generate --force` and `uv run python -m tests.reference.generate
--force` (see `tests/vectors/SOURCES.md`).

Research spikes (frozen; kept runnable as evidence for VERIFIED_FACTS):

```bash
python docs/v2/research/xwing_spike.py
python docs/v2/research/hpke_diff_spike.py
```

## Conventions

- English for code, docs, UI and lessons.
- Small, focused commits; message says what and why.
- Python 3.14+ (use 3.14 features freely); pyright strict on `src/`; ruff formatting.
