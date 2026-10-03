# QRP2P v2

A LAN-only, two-party desktop messenger with a hybrid post-quantum channel, built so that learners
can **watch, pause and attack that exact channel**.

- X-Wing KEM (ML-KEM-768 + X25519); Ed25519 + ML-DSA-65 hybrid signatures; ChaCha20-Poly1305.
- A four-message SIGMA-I / TLS 1.3-style handshake with an admission step, and a signed PQ rekey.
- A learning layer: Inspector, glass-box sessions with mutual consent, solo lab, Attack Lab,
  weakened engines, Algorithm Lab and guided lessons.

> **Status:** early development. M0 (crypto foundations), M1 (protocol core), M2 (services and
> the headless `qrp2p-cli`: LAN discovery, sessions, encrypted history, file transfer) and the
> desktop app (M3) are built; the learning layer (M4, M5) is next. `qrp2p` 2.0.0.dev0 on PyPI
> only reserves the name. Nothing here is
> ready for use, and the protocol must not be called secure until every item in DESIGN §15 passes.
> v1 is preserved at the tag
> [`v1-final`](https://github.com/DivinityQQ/quantum-resistant-p2p/tree/v1-final).

## Documentation

- [`docs/v2/DESIGN.md`](docs/v2/DESIGN.md) — the normative specification.
- [`docs/v2/IMPLEMENTATION_PLAN.md`](docs/v2/IMPLEMENTATION_PLAN.md) — phases, tasks and status.
- [`docs/v2/UI_DESIGN.md`](docs/v2/UI_DESIGN.md) — desktop visual language, light/dark mockups,
  interaction contracts and implementation guidance for M3–M5.
- [`docs/v2/research/VERIFIED_FACTS.md`](docs/v2/research/VERIFIED_FACTS.md) — library behaviour
  the design relies on, with evidence.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.14 or newer.

```bash
uv sync --all-extras --dev          # install
git config core.hooksPath .githooks # pre-commit and pre-push hooks
uv run tools/check.py               # format, lint, layers, strict types, tests, lock (~5 s)
uv run tools/check.py --audit       # plus the dependency audit
```

Run the desktop app (light and dark follow the system until you choose in Settings):

```bash
uv run qrp2p
```

Try two nodes on one machine (each needs its own data directory and port); the desktop app and
the terminal one talk to each other:

```bash
uv run qrp2p --data-dir /tmp/alice --port 47470
uv run qrp2p-cli --data-dir /tmp/bob --port 47471      # then: /connect 127.0.0.1:47470 Alice
```

Native builds that need no Python: see [`packaging/README.md`](packaging/README.md).

Between machines, each side's firewall must let in TCP on its port (47470 by default, the next
ones if busy) and mDNS (UDP 5353), e.g. `sudo ufw allow 47470:47485/tcp` with `ufw`. Windows asks
on the first run. A peer that cannot be reached can still connect to you.

CI runs the same checks, plus Windows and macOS, liboqs, mutation testing and the ProVerif models,
each only when its inputs change. Releases go to [PyPI](https://pypi.org/project/qrp2p/) by
trusted publishing.

## Licence

MIT; see [LICENSE](LICENSE).
