# CLAUDE.md — QRP2P v2

This repository is a ground-up rewrite (v2) of the quantum-resistant P2P messenger. v1 is kept in
history at the tag `v1-final`; none of its code is in the tree. **Do not build on v1 code.**
`main` accepts changes only through pull requests with green CI (ruleset: `.github/rulesets/main.json`).

## Read first

1. `docs/v2/DESIGN.md` — the normative spec (MUST/SHOULD). It is the source of truth.
2. `docs/v2/IMPLEMENTATION_PLAN.md` — phases M0–M6, task tables and gates, and where work stands.
3. `docs/v2/research/VERIFIED_FACTS.md` — library behaviour the design relies on, with evidence.

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
  in DESIGN §5, §7 and §10. `msgspec` is only for Inner payloads (DESIGN §8.2).
- **Sans-I/O core.** `qrp2p.core` has no sockets, threads, clocks, Qt or global randomness; time
  and randomness are injected. Respect the import rules in DESIGN §12.2.
- **Fail closed with a named reason** (DESIGN Appendix B). No bare `except`, no silent fallback, no
  retry on the same keys.
- **Secrets:** wrap key material in `Secret`; never log it, format it, or put it in exceptions.
  Only `RevealingProvider` may emit secret values, and only in glass-box or lab sessions.
- **Peer data is untrusted:** size-check before allocating; render peer text as plain text only;
  the sender is the session, never a payload field.
- **Tests come with every change.** Security checks need a test that fails if the check is
  removed (mutation testing enforces this in `core/`).
- **Weakened engines and `LAB-CLASSICAL`** live only under `qrp2p/lab/` and must never be reachable
  from real sessions. Real sessions build their provider with `REAL_PROFILES` only.
- **Never `import oqs` directly.** Use `qrp2p.lab.oqs_loader.load_oqs()`; liboqs-python otherwise
  builds liboqs at import time and can raise `SystemExit`.

## Commands

```bash
uv sync --all-extras --dev          # install
uv run pytest                       # tests
uv run ruff check . && uv run ruff format --check .
uv run pyright                      # strict type check
uv run lint-imports                 # layer rules
uv run pip-audit                    # dependency audit
```

Lab-algorithm test against a local liboqs build (CI builds it in the `liboqs` job):

```bash
OQS_INSTALL_PATH=/path/to/liboqs-install QRP2P_REQUIRE_LIBOQS=1 uv run pytest -m liboqs
```

Our own known-answer files are regenerated only for a deliberate spec change:
`uv run python -m tests.vectors.generate --force` (see `tests/vectors/SOURCES.md`).

Research spikes (frozen; kept runnable as evidence for VERIFIED_FACTS):

```bash
python docs/v2/research/xwing_spike.py
python docs/v2/research/hpke_diff_spike.py
```

## Conventions

- English for code, docs, UI and lessons.
- Small, focused commits; message says what and why.
- Python 3.14+ (use 3.14 features freely); pyright strict on `src/`; ruff formatting.
