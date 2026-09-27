# Test vector sources

Vendored so the tests run offline and cannot drift. Each file's SHA-256 is checked by the test
that loads it (`tests/vectors/__init__.py`); change a pin only together with this table.

| File | Source | SHA-256 | Licence |
| --- | --- | --- | --- |
| `xwing/test-vectors.txt` | [`dconnolly/draft-connolly-cfrg-xwing-kem`](https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem) at commit `984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd`, `spec/test-vectors.txt` (draft dated 2026-09-23) | `6290fa1276ce0be3bf7505c058242279faba0d500c0ddefab4cbcb1990d6dc5b` | IETF code component: Simplified BSD License under the IETF Trust Legal Provisions (see the repository's `CONTRIBUTING.md`) |
| `rfc5869/rfc-5869-HKDF-SHA256.txt` | RFC 5869 Appendix A.1–A.3, as packaged in [`cryptography-vectors`](https://pypi.org/project/cryptography-vectors/) 50.0.1, `cryptography_vectors/KDF/` | `faeb61bd8baf571f0f42ba3cea5d075c0c7637b9acdd07831dcfa8295472992a` | Apache-2.0 OR BSD-3-Clause (pyca); test cases from RFC 5869 |
| `kdf.json` | Own known-answer tests for `HkdfLabel`, `Expand-Label`, `Derive-Secret` and `Keys` (DESIGN §7.4), SHA-256 and SHA-384. Cross-checked in the test by an independent HMAC-only implementation | — | MIT (this project) |
| `identity.json` | Own known-answer tests for the identity bundle, `peer_id`, short ID and safety number (DESIGN §5) from fixed seeds. Cross-checked in the test from first principles | — | MIT (this project) |

The X-Wing file also contains encapsulation vectors (`eseed`). They cannot be replayed because
pyca's ML-KEM `encapsulate()` takes no caller randomness; the encapsulation side is covered by the
HPKE differential test instead (`tests/core/crypto/test_xwing.py`).

Regenerate our own KATs only for a deliberate spec change:
`uv run python -m tests.vectors.generate` (it refuses to overwrite unless `--force` is given).
