# QRP2P v2

A LAN-only, two-party desktop messenger with a hybrid post-quantum channel, built so that learners
can **watch, pause and attack that exact channel**.

- X-Wing KEM (ML-KEM-768 + X25519); Ed25519 + ML-DSA-65 hybrid signatures; ChaCha20-Poly1305.
- A four-message SIGMA-I / TLS 1.3-style handshake with an admission step, and a signed PQ rekey.
- A learning layer: Inspector, glass-box sessions with mutual consent, solo lab, Attack Lab,
  weakened engines, Algorithm Lab and guided lessons.

> **Status:** early development. M0 (crypto foundations) and M1 (protocol core: formal model,
> handshake, record layer, rekey) are done; M2 (services and a headless CLI) is next, so nothing
> talks over a network yet. Nothing here is ready for use, and the protocol must not be called
> secure until every item in DESIGN §15 passes. v1 is preserved at the tag
> [`v1-final`](https://github.com/DivinityQQ/quantum-resistant-p2p/tree/v1-final).

## Documentation

- [`docs/v2/DESIGN.md`](docs/v2/DESIGN.md) — the normative specification.
- [`docs/v2/IMPLEMENTATION_PLAN.md`](docs/v2/IMPLEMENTATION_PLAN.md) — phases, tasks and status.
- [`docs/v2/research/VERIFIED_FACTS.md`](docs/v2/research/VERIFIED_FACTS.md) — library behaviour
  the design relies on, with evidence.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.14 or newer.

```bash
uv sync --all-extras --dev          # install
uv run pytest                       # tests
uv run ruff check . && uv run ruff format --check .
uv run pyright                      # strict type check
uv run lint-imports                 # layer rules
uv run pip-audit                    # dependency audit
```

## Licence

MIT; see [LICENSE](LICENSE).
