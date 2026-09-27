# QRP2P v2 — Implementation plan

This is the working plan for building [DESIGN.md](DESIGN.md). It is written for whoever picks the
work up next, human or a Claude Code session on a local machine. Start with the repository's
`CLAUDE.md`, then this file.

**Status (2026-09-27):** Step 0 done except the PyPI placeholder (needs the owner's account).
**M0 is complete; its gate is met.** CI run 36334481736 is green on Linux, Windows and macOS:
lint, types, layers, audit, the full test suite, and liboqs built, bundled and exercised on all
three OSes (see the M0 status notes). Next: M1, formal model first.

---

## Step 0 — Prepare the branch

1. **Remove v1 from this branch** in one commit: `quantum_resistant_p2p/`, `tests/`, `setup.py`,
   `requirements.txt`, `mkdocs.yml`, and v1 docs (everything in `docs/` except `docs/v2/`). v1
   stays in history; its last commit is tagged `v1-final`, and v2 then replaced it on `main`. `research/VERIFIED_FACTS.md` lists the v1 bugs that
   become regression tests. Keep `LICENSE`.
2. Replace `README.md` with a short v2 README: what it is, status, how to run tests, links to the design.
3. Reserve the `qrp2p` name on PyPI (a placeholder release) before anyone else takes it.

## Target layout

```text
pyproject.toml         # uv-managed; src layout
uv.lock
src/qrp2p/             # package tree as in DESIGN §12.1
tests/
  vectors/             # pinned X-Wing vectors (with source + SHA-256) and our own KATs
formal/                # ProVerif / Tamarin models
docs/v2/               # design, this plan, research
.github/workflows/     # CI: lint, types, layers, audit; tests on windows/macos/ubuntu × 3.14; liboqs build
```

`pyproject.toml` essentials:

- `requires-python = ">=3.14"`
- Runtime dependencies (pinned in the lock file): `cryptography>=50`, `msgspec` today; `zeroconf`,
  `platformdirs`, `keyring`, `filelock` join in M2 and `PySide6` in M3 (UI extra or main — decide
  in M3). Dependencies are added when first imported, not before.
- Extras: `lab = ["liboqs-python"]`.
- Dev group: `pytest`, `hypothesis`, `ruff`, `pyright`, `import-linter`, `pip-audit` today;
  `mutmut` joins in M1 and `pytest-asyncio` in M2.
- Tool config: `ruff` (strict rule set incl. `S` bandit rules), `pyright` strict on `src/`,
  import-linter contracts from DESIGN §12.2.

---

## M0 — Crypto foundations

Everything here lives in `src/qrp2p/core/crypto/` and has no I/O.

| # | Task | Done when |
| --- | --- | --- |
| M0.1 | Project scaffold as above; CI matrix (3 OSes × Python 3.14) running ruff, pyright, pytest, import-linter, pip-audit | CI green on an empty package |
| M0.2 | `secret.py`: `Secret` wrapper for key material — redacted `repr`/`str`, explicit `.reveal()`, constant-time equality, no pickling | Unit tests, including a check that `repr`, f-strings and exception text never show the value |
| M0.3 | `profiles.py`: frozen dataclasses with every constant from DESIGN Appendix A | Tests assert each size against the live primitives (e.g. generate a key and measure) |
| M0.4 | `xwing.py`: port `research/xwing_spike.py`; typed API `keygen() / public_key(sk) / encapsulate(pk) / decapsulate(sk, ct)`; error mapping `invalid_kem_key` and `kem_failure` | Official vectors (vendored in `tests/vectors/` with source URL and SHA-256), the HPKE differential test (port of `research/hpke_diff_spike.py`), an invalid ML-KEM key, low-order and zero X25519 points |
| M0.5 | `mlkem1024.py` wrapper; X25519-KEM for the lab profile (DESIGN §4.3) in `qrp2p/lab/classical.py`, not `core/` (CLAUDE.md: `LAB-CLASSICAL` lives only under `qrp2p/lab/`) | Round trip, sizes, error mapping |
| M0.6 | `hybrid_sig.py`: `HybridSign`/`verify` for all three profiles (the Ed25519-only lab scheme in `lab/classical.py`), roles as an enum, contexts per DESIGN §4.4; `identity.py`: bundle, `peer_id`, short ID and safety number (DESIGN §5), because verification needs the peer's bundle | Tampering with either half fails; cross-role replay fails; wrong profile fails; context ≤ 255 B; identity KATs |
| M0.7 | `kdf.py`: `HkdfLabel`, `Expand-Label`, `Derive-Secret`, `Keys` for SHA-256 and SHA-384 | Known-answer tests frozen in `tests/vectors/kdf.json`, cross-checked by an independent HMAC-only implementation inside the test |
| M0.8 | `provider.py`: `CryptoProvider` protocol (keygen, encapsulate, decapsulate, sign, verify, random bytes, plus KDF and AEAD so a revealing wrapper sees every derived secret), `PlainProvider` gated to the profiles it was built with, and a basic `RevealingProvider`. `RecordingProvider` / `ReplayProvider` move to M4 with the `.qrlab` format | Protocol typed; `PlainProvider` passes the M0.4–M0.6 tests through the interface |
| M0.9 | `core/errors.py`: close, admit and file-cancel codes (DESIGN Appendix B) as enums, plus one exception type that carries a code | Every code has a test name reserved in a checklist |
| M0.10 | **liboqs packaging spike:** a CI job builds liboqs at a pinned tag on all 3 OSes; the app sets `OQS_INSTALL_PATH`; liboqs-python loads HQC, FrodoKEM, Classic McEliece and SLH-DSA; when the library is absent, the lab reports "unavailable" and nothing tries to build | Artefacts on 3 OSes, or a written decision to ship the lab extra on fewer OSes |

**Gate:** vectors and the differential test pass on all 3 OSes; own KATs committed; M0.10 resolved.

**M0 status notes (2026-09-27)**

- Local (Linux, CPython 3.14.7): all tests pass, including the official X-Wing vectors, the HPKE
  differential test, RFC 5869 vectors and our KATs (`tests/vectors/`). Hand mutations of the
  signature, provider-gate, nonce, combiner, bundle-version and PRK checks were each caught; full
  `mutmut` runs start in M1.
- `aead.py` (profile AEADs, `nonce = iv XOR u96(seq)`) was added to M0 because the provider needs
  it; `record.py` in M1 builds on it.
- `tests/reason_checklist.py` reserves a test name for every code in Appendix B; entries without
  a milestone prefix are checked to exist.
- liboqs: 0.16.0 built locally with the CI flags; HQC, FrodoKEM, Classic McEliece and SLH-DSA load
  through `qrp2p.lab.oqs_loader`. The first CI run passed on Linux and macOS. On Windows the build,
  load and KEMs passed but SLH-DSA-SHA2 failed: an MSVC byte-order bug in liboqs
  (VERIFIED_FACTS), now worked around in the CI build and guarded by a cross-platform KAT.
- Windows checkouts converted the vendored vectors to CRLF and broke their SHA-256 pins;
  `.gitattributes` now marks `tests/vectors/` as `-text`.

---

## M1 — Protocol core (sans-I/O)

Order matters: **model first, code second.**

1. **Formal model** (`formal/qrp2p.pv`) of DESIGN §7 and §8.4:
   - Queries: secrecy of `ap_I`/`ap_R`; injective agreement in both directions on
     (`peer_id_I`, `peer_id_R`, profile, `gb_request`, admission decision, `th_final`); forward
     secrecy with identity keys revealed after the session; hybrid secrecy with either KEM
     component revealed; post-compromise recovery after a signed rekey.
   - One weakened model per weakened engine (DESIGN §11.8); each MUST produce an attack.
   - Tamarin cross-check with KEM binding weakened (ML-KEM alone is not MAL-BIND) for `PQ-CNSA-1`.
   - If the model finds a problem, change DESIGN.md **first**, then the code.
2. **`wire.py`:** fixed-layout encoders and decoders for Hello, Reply, Confirm, Admit,
   ProfileUnsupported, frames and transcript entries; msgspec schemas for Inner (DESIGN §8.2) with
   limits. Hypothesis round-trip and garbage-input tests.
3. **`handshake.py`:** `Initiator` and `Responder` state machines. Suggested sans-I/O API:
   - `receive(frame_bytes) -> list[Event]` and `start() -> list[Event]`.
   - Events: `Send(frame)`, `AdmissionRequired(peer_bundle, gb_request, profile)`,
     `Established(session_keys, glass_box, peer)`, `Closed(reason)`, `Trace(event)`.
   - The service answers `AdmissionRequired` by calling `admit(decision, glass_box)`, which yields
     `Send(Admit)` + `Established`.
   - Time is injected (deadlines checked via `tick(now)`); randomness comes from the provider.
4. **`record.py`:** sealing and opening with implicit counters; the writer rule is enforced by
   the service, but the core exposes `seal_next()` so the sequence number is taken at dequeue;
   KeyUpdate; PQ rekey sub-state machine.
5. **`trace.py`:** typed events; the per-session ring buffer lives in services; secrets are only
   possible through `RevealingProvider`.
6. **Tests** (DESIGN §15): table-driven state-machine tests (every message in every state),
   key-schedule KATs as a function of `(ss, transcript)`, full-handshake vectors from a test-only
   derandomised reference (pure-Python ML-KEM/ML-DSA under `tests/reference/`, never imported by
   `src/`), mutation testing with `mutmut` over `core/`, the canary leak test, adversarial tests
   for scenarios 4–6 and 8–9, and v1 regressions 1–4.

**Gate:** model verified (and weakened models attacked); all of the above green in CI.

---

## M2 — Services and headless CLI

- `transport.py`: asyncio TCP server and client; frame reader with a limit; one writer task per
  connection with a priority queue; resource limits (DESIGN §6.4).
- `discovery.py`: AsyncZeroconf registration and browsing, with the TXT record per DESIGN §6.1.
- `session_manager.py`: drives the core machines; admission policy (DESIGN §7.6); simultaneous
  open; replacement; liveness; receipts.
- `files.py`: DESIGN §9 including name sanitising and OS download marks.
- `vault.py`: DESIGN §10 (Argon2id calibration, key hierarchy, schema with `row_uid`, padding,
  per-conversation keys, DEK rotation, lock, keychain opt-in).
- `qrp2p-cli`: unlock, list nearby, connect, chat, send file, verify safety number.
- Tests: two in-process nodes over loopback; the vault's VACUUM and deletion behaviour;
  regressions 5–7.

**Gate:** two real machines on a LAN chat and transfer files via the CLI.

## M3 — Desktop app

- The bridge thread model (DESIGN §12), view models, QML design system (DESIGN §14.3).
- Screens from DESIGN §14.1 except the labs; plain-text rendering of peer data; key-mismatch
  flow; contact requests; verification.
- `pyside6-deploy` builds and installers per OS; code-signing plan.
- Start with clickable QML mock-ups of the main window and prompts; agree the look before
  wiring logic.

**Gate:** daily use on 3 OSes.

## M4 — Learning layer I

Inspector (timeline, dissector, key-schedule explorer, security panel); solo lab nodes;
step-through; `RecordingProvider`, `ReplayProvider` and fork; `RevealingProvider` with the
pre-admission buffer; glass-box prompts, visuals and rate limits; `.qrlab` save, load and
fuzzing.

**Gate:** canary leak test green end to end, including view-model strings and saved files.

## M5 — Learning layer II

Attack Lab scenarios 1–11 (Mallory transport hooks; the simulated quantum oracle clearly
labelled); weakened engines in `lab/weakened/`, with import rules and a runtime check; the
Algorithm Lab (benchmarks and profile comparison); lessons 1–9 as Markdown with step metadata.

**Gate:** every scenario and weakened engine is a green CI test.

## M6 — Release 2.0

Extract §§4–8 into a standalone protocol spec with the formal model; invite outside review;
address findings; signed installers; publish.

---

## Decisions still open (take them when the phase starts)

| Topic | Options | Phase |
| --- | --- | --- |
| ProVerif-only vs ProVerif + Tamarin from day one | Tamarin can follow once ProVerif passes | M1 |
| PySide6 as a core dependency or a `gui` extra | The CLI can run without Qt if it is an extra | M2/M3 |
| Visual identity (palette, icon, name styling) | Mock-ups first | M3 |
| Code-signing identities (Apple, Windows) | Buy when first installer ships | M3/M6 |

### Decisions taken

| Topic | Decision | When |
| --- | --- | --- |
| Vendoring the X-Wing vectors | Vendored with attribution and a SHA-256 pin (`tests/vectors/SOURCES.md`); IETF code components are Simplified-BSD licensed | M0 |
| liboqs tag and OSes | 0.16.0 (commit `5a1a854b`), all 3 OSes, built with `OQS_DIST_BUILD=ON`, `OQS_USE_OPENSSL=OFF`; revisit if the CI job fails on an OS | M0 |
| Minimum Python | 3.14 only (owner's decision: no reason to carry 3.13) | M0 |

## Starting a local session

Suggested first prompt:

> Read `CLAUDE.md`, `docs/v2/DESIGN.md` and `docs/v2/IMPLEMENTATION_PLAN.md`. Continue with the
> first unfinished phase. Run the checks listed in CLAUDE.md before each commit.
