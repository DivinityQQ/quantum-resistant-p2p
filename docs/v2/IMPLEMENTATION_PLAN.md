# QRP2P v2 — Implementation plan

This is the working plan for building [DESIGN.md](DESIGN.md). It is written for whoever picks the
work up next, human or a Claude Code session on a local machine. Start with the repository's
`CLAUDE.md`, then this file.

**Status (2026-09-28):** M0 and M1 are complete and on `main`; their gates are met (see the
status notes under each). M2 (services and headless CLI) is implemented and tested in CI; its gate,
two real machines over a LAN, waits for the owner (see the M2 status notes). v1 is tagged
`v1-final`. CI runs lint, types, layers, audit, the tests on three OSes, liboqs on three OSes, the
ProVerif models and mutation testing, each job only when its inputs changed; the `main` ruleset
requires the gate job "CI result". Local hooks run the fast suite (`tools/check.py`) before every
push. **Next: the M2 gate, then M3** (desktop app). `qrp2p` 2.0.0.dev0 is on PyPI, published by
`.github/workflows/release.yml` (trusted publishing). Steps that need the owner's accounts (the v1
Pages site, the liboqs bug report) are in [OWNER_TODO.md](OWNER_TODO.md).

---

## Step 0 — Prepare the branch

1. **Remove v1 from this branch** in one commit: `quantum_resistant_p2p/`, `tests/`, `setup.py`,
   `requirements.txt`, `mkdocs.yml`, and v1 docs (everything in `docs/` except `docs/v2/`). v1
   stays in history; its last commit is tagged `v1-final`, and v2 then replaced it on `main`. `research/VERIFIED_FACTS.md` lists the v1 bugs that
   become regression tests. Keep `LICENSE`.
2. Replace `README.md` with a short v2 README: what it is, status, how to run tests, links to the design.
3. Reserve the `qrp2p` name on PyPI (a placeholder release) before anyone else takes it. Done: 2.0.0.dev0,
   2026-09-28.

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
- Runtime dependencies (pinned in the lock file): `cryptography`, `msgspec`, `zeroconf`, `ifaddr`,
  `platformdirs`, `keyring`, `filelock`; `PySide6` joins in M3 as the `gui` extra. Dependencies are
  added when first imported, not before.
- Extras: `lab = ["liboqs-python"]`.
- Dev group: `pytest`, `pytest-asyncio`, `hypothesis`, `ruff`, `pyright`, `import-linter`,
  `pip-audit`, `mutmut`, and the test-only references `kyber-py` and `dilithium-py`.
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

**M1 status notes (2026-09-27)** — what was built, and where it differs from the list above:

- **Formal model** (`formal/`, see its README): ProVerif 2.05 runs in CI
  ("Formal model (ProVerif)") when the models change, and weekly; `formal/verify.py` checks every result against an `EXPECT` line.
  All queries hold for the real protocol: secrecy both ways, the three injective agreements
  (the responder's agreement on `th_final` comes from the first record, DESIGN §7.5), forward
  secrecy, hybrid secrecy with either X-Wing component broken, post-compromise recovery after a
  signed rekey, implicit record counters. Each weakened model yields its attack.
- **The model changed the design twice.** (1) Removing Finished MACs, or the signer's identity
  from the signed transcript, is *not* attackable here: the handshake AEAD already binds key and
  identity. Those are now `formal/redundant/`, and DESIGN §11.8 lists two variants that are
  attackable (signatures not bound to the transcript; Hello's profile and flags not in the
  transcript). (2) The rekey's agreement relies on the exporter binding both identities; the
  model now says so explicitly (`expo(pk_I, pk_R, session)`).
- ProVerif cannot rebuild a concrete trace for the honest initiator's completion event (it
  derives it; the derivation in the CI log is an ordinary honest run). Reachability checks
  therefore use `EXPECT reachable`, which fails only if the event is unreachable.
- **Tamarin** moved to M6 (decision below).
- **Code:** `core/wire.py`, `schedule.py`, `handshake.py`, `record.py`, `trace.py`, `events.py`.
  The API follows the suggestion above, with `now` passed to every call; admission is
  `accept(glass_box=…)` / `reject(reason)`; `Established` carries a `Channel`. Everything the
  channel wants to send comes back as `Queue(message, priority)`; the writer calls
  `seal_next()` at dequeue.
- **Tests:** every message in every state; tampering at each check; deadlines; admission and
  glass-box rules; KeyUpdate, rekey, liveness and close; scenarios 4, 5, 6, 8a and the 8b
  substitution against the real engine; v1 regressions 1-4; the canary leak test with its
  glass-box control; Hypothesis fuzzing of codecs, handshake and records; and full-handshake
  plus rekey vectors from `tests/reference/` (an independent derandomised implementation using
  `kyber-py` and `dilithium-py`) that `qrp2p` reproduces byte for byte.
- **Mutation testing:** `mutmut` over `qrp2p.core`, gated by `tests/mutation_gate.py`: every
  survivor must be message-only or explained in `tests/mutation_allowlist.txt`. CI job
  "Mutation testing (core)".
- Scenario 9's "memory graph flat" and the weakened engines themselves are M5 work; the core
  already refuses oversize input before allocating.

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

**M2 status notes (2026-09-28)** — what was built, and what the implementation settled in the
design (DESIGN 1.3):

- **Services** (`src/qrp2p/services/`): `transport` (frame streams, listener with port fallback),
  `session` (one reader, one priority writer that seals at dequeue, flush-then-drop closes, write
  stall and backlog limits), `session_manager` (half-open slots, Hello rate, live-session cap,
  reflection, simultaneous open, replacement, timers), `admission` (the §7.6 table and glass-box
  prompt limits), `vault` + `keychain` + `paths` (§10), `files` (§9), `discovery` (§6.1),
  `trace_bus`, and `node`: the one API front ends use, with the vault on its own thread.
- **CLI** (`src/qrp2p/cli/`, entry point `qrp2p-cli`): every M2 action, plus `/trace` as a first,
  text-only Inspector. It imports only `services` (import-linter).
- **Decisions written into DESIGN 1.3:** what "at once" means for simultaneous open (overlapping
  handshakes); profile policy applies to glass-box requests too; a rate-limited glass-box request is
  a normal session; the receiver's final `file_progress` is the delivery acknowledgement; the exact
  vault header, wrapping, subkey, padding and row layouts; msgspec for vault rows; a crash-safe
  order for password changes; a CLI section.
- **Tests** (`tests/services/`, `tests/cli/`, `tests/test_packaging.py`): nodes and managers over
  loopback TCP; the vault's binding, VACUUM and deletion remnants, interrupted password changes and
  locks; hostile file names and transfers; admission and trust; the canary leak test through the
  services (logs, events, traces, vault files, received files); two real `qrp2p-cli` processes.
  v1 regressions 5 (stale lock), 6 (locking never raises) and 7 (the wheel carries every module) are
  covered. Every Appendix B code now names an existing test. Real multicast is tested only when
  `QRP2P_TEST_MDNS=1` (CI runners do not route it reliably); it passes on the workstation LAN.
- **Hardening pass (2026-09-28)** after review: tests for untested paths, Hypothesis property
  tests for everything the services parse (names, mDNS records, vault files and rows, the
  file-transfer state machine under arbitrary peer sequences, which reaches every end state), and
  a one-off mutmut run over the non-network services (vault, files, admission, text, limits,
  keychain, paths, trace bus, discovery). It found and fixed: both sessions lost when peers connect
  to each other at once without a pin (DESIGN §7.8 now applies the lower-`peer_id` rule at
  establishment too; core `Initiator.peer` lets the services see the responder after Reply);
  `Vault.lock()` failing on a damaged row; CLI crashes on non-ASCII digits and `inf`; mDNS names
  over 63 bytes; file handles leaked by a cancel during a thread's open; a `.part` file left when
  the peer cancelled during `accept`. Mutation results: 2,989 mutants, 2,467 killed; the 160
  behaviour-changing survivors left were reviewed and are equivalent (OS-specific branches,
  cosmetic formatting, caches that fall back to the database, retry bounds, `None` for `False`).
  To repeat it, point `[tool.mutmut]` in a scratch worktree at those modules with
  `pytest_add_cli_args_test_selection` set to the non-network `tests/services` files.
- **Not in M2:** glass-box sessions are admitted, labelled and bound into the transcript, but the
  secrets are shown only by the Inspector (M4); scenario 9's memory graph is M5.
- **LAN test, round 1 (2026-09-28):** a CachyOS desktop (wired, `ufw` on) and a Debian 13
  server with Docker bridges, Tailscale and a VM macvtap, installed there with `uv tool install
  git+…@<branch>`. Passed: discovery both ways, first contact, admission, equal safety numbers,
  chat with receipts (bidi controls neutralised), 1 GiB each way at the same time (about 10 s
  each, hashes equal) with chat still flowing, simultaneous `/connect` (one session), `kill -9`
  of the receiver mid-transfer (the sender reports lost and failed), rekey, lock and unlock (the
  peer sees *locked*; the mDNS entry leaves and returns). Found and fixed: dialling the server's
  Docker bridge addresses first cost 5 s each (15–20 s per connect); a dialler running Docker
  would reach itself at `172.17.0.1` and give up; a contact's last working address was tried last;
  a `/connect` that the peer completed from its side still reported *unreachable*; *unreachable*
  gave no firewall hint; a handshake dropped by the peer showed an empty reason; after a crash,
  transfers stayed *transferring* in history and their `.part` files were never removed (DESIGN
  §6.2, §9, §10.4); zeroconf logged a traceback for IPv6 loopback at every start; `/set` claimed
  every change waits for the next unlock. The desktop's `ufw` dropped incoming TCP, so the server
  could not dial in; that is expected, and the hint now names it.
- **LAN test, round 2 (2026-09-29):** Windows 10 Pro 22H2 (the same desktop, wired, network
  profile *Private*, Czech locale, VMware host-only adapters) against the same server, still on
  the round-1 build; Windows ran the branch from a checkout. Passed: the fast suite; the Windows
  Defender Firewall prompt on the first listen (its defaults allow the uv-managed `python.exe` on
  Private networks only, TCP and UDP); discovery both ways, with the LAN address ranked above the
  VMware ones; connects in 0.8 s out and about 30 ms in; the *unreachable … firewall* hint after
  5 s for a dropped port; equal safety numbers; chat with é, ✓, emoji and U+202E both ways (the
  override shown as U+FFFD); 1 GiB each way at the same time (about 15 s each, hashes equal) with
  chat flowing; Mark of the Web (`ZoneId=3`) on received files; nine names Windows forbids
  (`CON.txt`, `aux`, `nul.tar.gz`, `a:b.txt`, `what?.txt`, `x<y>z|w*.txt`, `trailing.`,
  `" spaced "`, `back\slash.txt`) arriving sanitised; `taskkill /F` mid-receive (no `.part` after
  restart, *failed* in history, the sender reports lost); a second process on the data directory
  refused; `/remember` unlocking from the Credential Locker and `/remember off` removing the entry;
  the real keychain and real multicast tests; a simultaneous `/connect` that really raced (one
  session, both sides agree); rekey (the responder is refused with a reason); lock and unlock. In
  a classic console (conhost, cmd.exe): the password prompt does not echo; é shows, and ✓ and
  emoji show as boxes (the console font lacks them; nothing crashes); Ctrl+C exits with 130
  and no traceback. Found and fixed: piped standard input was read in the ANSI code page, which
  garbled text, broke non-ASCII passwords on `--password-stdin` and reported an emoji as *too
  long* (pipes and files are now UTF-8 on every OS); backslashes in commands were eaten as shell
  escapes, so `/send` of a Windows path failed and `/set downloads` saved a drive-relative path
  (both DESIGN §12); an unusable `--data-dir` ended in a traceback; the real multicast test
  assumed no other node on the LAN; a message arriving while the user typed overwrote the typed
  text, and the console's line editing then deleted into the prompt (Windows and, by the same
  code, POSIX). The prompt is now read with `prompt_toolkit` (DESIGN §12–13); retested in Windows
  PowerShell (conhost): messages print above the prompt, the typed line stays and is sent whole,
  history works, Ctrl+C exits with 130.
- **Gate (owner):** on two machines on one LAN, run `uv run qrp2p-cli` on each (or
  `pipx install qrp2p` once released), `/nearby`, `/connect nearby 1`, `/admit` on the other side,
  chat, `/send` a large file, `/verify` on both and compare. Record the OSes used here. Rounds 1
  (Linux–Linux) and 2 (Windows–Linux) above both passed.

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
| Visual identity (palette, icon, name styling) | Mock-ups first | M3 |
| Code-signing identities (Apple, Windows) | Buy when first installer ships | M3/M6 |

### Decisions taken

| Topic | Decision | When |
| --- | --- | --- |
| Vendoring the X-Wing vectors | Vendored with attribution and a SHA-256 pin (`tests/vectors/SOURCES.md`); IETF code components are Simplified-BSD licensed | M0 |
| liboqs tag and OSes | 0.16.0 (commit `5a1a854b`), all 3 OSes, built with `OQS_DIST_BUILD=ON`, `OQS_USE_OPENSSL=OFF`; revisit if the CI job fails on an OS | M0 |
| Minimum Python | 3.14 only (owner's decision: no reason to carry 3.13) | M0 |
| ProVerif only, or ProVerif + Tamarin in M1 | ProVerif in M1, run in CI on every push; the Tamarin cross-check (weakened KEM binding for `PQ-CNSA-1`) moves to M6, before outside review | M1 |
| PySide6 as a core dependency or a `gui` extra | The `gui` extra (owner's decision): `pip install qrp2p` gives the headless node and `qrp2p-cli`; services and CLI never import Qt (import-linter) | M2 |
| mDNS in CI | Parsing and validation always; real multicast only with `QRP2P_TEST_MDNS=1`, because CI runners do not route multicast reliably | M2 |

## Starting a local session

Suggested first prompt:

> Read `CLAUDE.md`, `docs/v2/DESIGN.md` and `docs/v2/IMPLEMENTATION_PLAN.md`. Continue with the
> first unfinished phase. Run the checks listed in CLAUDE.md before each commit.

Before starting M3 locally:

1. Start M3 on a new branch from `main` and open a PR against it.
2. `uv sync --all-extras --dev`, `git config core.hooksPath .githooks`, then
   `uv run tools/check.py`.
3. Add PySide6 as the `gui` extra when it is first imported. The desktop app drives
   `qrp2p.services.node.Node` from its asyncio thread through the bridge (DESIGN §12); the CLI
   (`src/qrp2p/cli/`) is a working example of a front end on that API, and `tests/cli/` of testing one.
