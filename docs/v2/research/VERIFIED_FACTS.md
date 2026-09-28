# Verified facts for implementation

Facts the design depends on, each checked by running code on 2026-09-27 with
`cryptography` 50.0.1 (bundled OpenSSL 4.0.2), `msgspec` 0.21.1 and CPython 3.11 (Linux x86-64).
Re-run at M0 on CPython 3.14.7 (same libraries): both spikes pass and every fact below still holds;
most are now regression tests under `tests/`.
Re-check them when a pinned version changes; most should become regression tests in M0.

## pyca/cryptography 50

| Fact | How it was checked | Consequence |
| --- | --- | --- |
| `MLKEM768PublicKey.encapsulate()` takes **no arguments** and returns `(shared_secret, ciphertext)`, in that order (32 B, 1,088 B) | Called with an argument → `TypeError`; inspected return | No derandomised encapsulation; the X-Wing `eseed` vectors can't be replayed. Use the HPKE differential test and provider-boundary recording (DESIGN §11.6) |
| `MLKEM768PrivateKey.from_seed_bytes(seed)` takes the 64-byte FIPS 203 seed `d‖z`; `private_bytes_raw()` returns that seed | X-Wing keygen vectors match | X-Wing expansion maps `e[0:64]` directly |
| ML-KEM public keys with a coefficient ≥ q (3,329) are **rejected at import**. The error text wrongly says "public key is 1184 bytes long" — the *same* message as for a key of the wrong length | Coefficients 4,095 and 3,329 at several positions (including 0 and 767) → rejected; 3,328 accepted; a 1,183-byte key gives the identical message | The FIPS 203 check is present. Check the length first, then map any remaining `ValueError` to `invalid_kem_key` |
| ML-KEM-1024: public key 1,568 B, ciphertext 1,568 B, shared secret 32 B | Measured | Appendix A |
| `MLDSA{44,65,87}PrivateKey.sign(data, context)` accepts a FIPS 204 context string; > 255 bytes → `ValueError` | Called | HybridSign context strings (DESIGN §4.4) |
| ML-DSA signing is **hedged**: two signatures of the same message differ | Compared two signatures | Signatures can't be regenerated for replay or vectors |
| ML-DSA-65: public key 1,952 B, signature 3,309 B. ML-DSA-87: public key 2,592 B, signature 4,627 B. `private_bytes_raw()` = 32-byte seed | Measured | Identity bundle 4,577 B; seeds stored in the vault |
| `X25519PrivateKey.exchange()` with an all-zero or low-order public key raises `ValueError("Error computing shared key.")` | Called with 0, 1, the order-8 point `e0eb7a7c…b800`, p − 1, and the non-canonical p and p + 1 | Map to `kem_failure`; negative vectors in `tests/core/crypto/test_xwing.py` |
| ML-KEM decapsulation of a wrong-length ciphertext raises `ValueError`; a right-length tampered ciphertext returns a different 32-byte secret (implicit rejection) | Called | Wrong length → `kem_failure`; tampering surfaces later as `decrypt_failed` |
| ML-DSA `verify()` raises `InvalidSignature` for a wrong context or a truncated signature; `sign()` with no context uses the empty context | Called | HybridSign maps both to `signature_invalid` |
| `HKDF.extract(algorithm, salt, ikm)` is a static method; `HKDFExpand` has no minimum PRK length (a 1-byte or empty key is accepted) | Called; `extract` matches stdlib HMAC | Our `hkdf_expand` enforces `len(prk) ≥ Hlen` itself |
| `hpke.KEM.MLKEM768_X25519` **is X-Wing** (enc = 1,120 B). RFC 9180 suite id uses KEM id `0x647a` | `research/hpke_diff_spike.py`: 20/20 both directions | Differential test for the encapsulation side |
| `hpke.MLKEM768X25519PrivateKey` / `PublicKey` are opaque wrappers around an ML-KEM and an X25519 key; no raw encapsulate/decapsulate API | Inspected | X-Wing must be built from parts (§4.2) |
| `Argon2id` is available in `cryptography.hazmat.primitives.kdf.argon2` and releases the GIL | Timed alone and with a busy Python thread running alongside (the thread kept running) | Run in a worker thread; t=3, m=256 MiB, p=4 took 0.5–1.4 s on a 4-core container |
| SHA-3 / SHAKE come from `hashlib` (stdlib), not pyca | Used in the spikes | Fine; stdlib hashlib is OpenSSL-backed |

## X-Wing

- The construction in DESIGN §4.2 passes all three official vectors (keygen and decapsulation):
  `research/xwing_spike.py`.
- Vectors are pinned to commit `984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd` of
  `dconnolly/draft-connolly-cfrg-xwing-kem` (draft dated 2026-09-23); SHA-256 of
  `spec/test-vectors.txt` = `6290fa12…6dc5b`.
- The combiner label is hex `5c2e2f2f5e5c`; the combiner order is `ssM ‖ ssX ‖ ctX ‖ pkX ‖ label`.

## msgspec 0.21.1

- **Not canonical.** It accepts a non-minimal MessagePack integer (`cd 00 02` decodes to 2) and
  out-of-order map keys, and re-encoding produces different bytes. So nothing that is hashed or
  signed may use msgspec (DESIGN principle 5); it is used only for Inner payloads.

## SQLite (stdlib `sqlite3`)

- `VACUUM` renumbers implicit rowids: rows 6..10 became 1..5 after deleting 1..5. Any associated
  data bound to rowid breaks after a vacuum. Hence explicit random `row_uid` primary keys
  (DESIGN §10.3).

## liboqs-python 0.16.0.1

- Ships only a `py3-none-any` wheel. When no liboqs shared library is found at import, it
  git-clones liboqs and builds it with CMake at runtime (`oqs/oqs.py`, `_install_liboqs`). We must bundle a CI-built liboqs and set
  `OQS_INSTALL_PATH` (DESIGN §13).
- It has **no opt-out** from that fallback. `_load_liboqs()` first tries `ctypes.util.find_library`
  (system paths), then `$OQS_INSTALL_PATH/lib`, `lib64` (Windows: `bin`, as `oqs.dll` or
  `liboqs.dll`), defaulting to `~/_oqs`. If nothing loads it builds, and if the build fails it
  raises **`SystemExit`**. `qrp2p.lab.oqs_loader` therefore loads the library itself first and
  imports `oqs` only after that succeeded.
- At import it attaches a `StreamHandler(stdout)` to the `oqs.oqs` logger and logs one INFO line;
  the loader disables that logger. It warns if liboqs and liboqs-python differ in major.minor.
- liboqs **0.16.0** (commit `5a1a854b`) builds with CMake + Ninja in about 4 minutes on a 4-core container. Enabled by
  default: `HQC-1/3/5`, `FrodoKEM-*` and `eFrodoKEM-*`, `Classic-McEliece-*`, and
  `SLH_DSA_PURE_*` / `SLH_DSA_*_PREHASH_*` (221 signature names in total). With default flags the
  shared library links the system `libcrypto.so.3`; with `-DOQS_USE_OPENSSL=OFF` it links only
  libc, which is what a bundle needs. `-DOQS_DIST_BUILD=ON` keeps it portable across CPUs.
- **liboqs 0.16.0 SLH-DSA (SHA-2 variants) is broken when built with MSVC.**
  `src/sig/slh_dsa/slh_dsa_c/plat_local.h` selects byte swapping with
  `#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__`. MSVC defines neither macro, so the preprocessor
  compares 0 with 0 and a little-endian x64 build takes the big-endian path in SHA-256/512. Found in
  CI: on Windows, `verify()` rejected a signature it had just made; every KEM and the SHAKE variants
  were fine. Reproduced on Linux by building with `-U__BYTE_ORDER__ -U__ORDER_BIG_ENDIAN__`
  (SHA2-128f verify fails, SHAKE-128f passes) and fixed by defining
  `__ORDER_LITTLE_ENDIAN__=1234 __ORDER_BIG_ENDIAN__=4321 __BYTE_ORDER__=1234`, which the CI
  `liboqs` job now passes on Windows through `CFLAGS`. `tests/vectors/liboqs/` holds a signature
  from a correct GCC build that every OS must verify; the simulated MSVC build fails it. Worth
  reporting upstream.
- liboqs upstream README: *"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A
  PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA."* It is used for lab algorithms only.

## Package versions on PyPI (2026-09-27)

PySide6 6.11.2 · cryptography 50.0.1 · msgspec 0.21.1 · zeroconf 0.151.3 · platformdirs 4.12.0 ·
keyring 25.7.0 · filelock 4.0.4 · liboqs-python 0.16.0.1 · hypothesis 6.168.2 · pytest 9.1.1 ·
pytest-asyncio 1.4.0 · import-linter 2.15 · Nuitka 4.2.2 · pyright 1.1.414 · ruff 0.16.9.
The name `qrp2p` was unclaimed on PyPI. Every runtime dependency ships wheels usable on
CPython 3.14 (cryptography abi3 and cp314t; msgspec and zeroconf cp314; PySide6 abi3).

## v1 bugs reproduced (for the regression suite)

All reproduced against v1 (now the tag `v1-final`) with two real nodes over localhost:

1. A peer can set `sender_id` and `is_system` inside a signed and encrypted message; the receiver
   accepts them, so messages appear in another peer's conversation or as system notices.
2. A replayed `secure_message` is accepted again once its ID leaves the 100-entry dedup set.
3. A file and a text message sent concurrently interleave their chunked frames: both are lost,
   the connection stays "up" and later messages vanish while `send_message` returns `True`.
4. A 25-byte chunked-frame header makes a fresh listener allocate about 1.4 GB before any
   authentication.
5. A stale lock file blocks all key-storage saves for up to an hour
   (`UnboundLocalError: subprocess` inside `SecureFile._acquire_process_lock`).
6. `KeyStorage._secure_zero` raises `TypeError` (Python `bytes` is immutable).
7. A non-editable install omits the liboqs binaries (`setup.py` has no `package_data`).
