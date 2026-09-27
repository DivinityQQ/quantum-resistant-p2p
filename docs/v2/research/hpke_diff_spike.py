"""HPKE differential spike: pyca's HPKE KEM MLKEM768_X25519 is X-Wing.

Research code, not production code. Two directions, 20 trials each:
  1. pyca HPKE encrypt  -> our X-Wing decapsulation + a hand-written RFC 9180 key schedule opens it
  2. our X-Wing encapsulation + RFC 9180 seal -> pyca HPKE decrypt opens it
This covers the encapsulation side that the official vectors cannot (pyca offers no
derandomised encapsulation). It becomes a regression test in M0.

Usage:  python hpke_diff_spike.py        (needs cryptography >= 50)
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from xwing_spike import decapsulate, encapsulate, expand

# RFC 9180 suite: KEM 0x647a (MLKEM768-X25519 per draft-ietf-hpke-pq), KDF 0x0001 HKDF-SHA256, AEAD 0x0003 ChaCha20-Poly1305
SUITE_ID = b"HPKE" + struct.pack(">HHH", 0x647A, 0x0001, 0x0003)
SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + SUITE_ID + label + ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, struct.pack(">H", length) + b"HPKE-v1" + SUITE_ID + label + info, length)


def _base_mode_key_nonce(ss: bytes, info: bytes) -> tuple[bytes, bytes]:
    ctx = b"\x00" + _labeled_extract(b"", b"psk_id_hash", b"") + _labeled_extract(b"", b"info_hash", info)
    secret = _labeled_extract(ss, b"secret", b"")
    return _labeled_expand(secret, b"key", ctx, 32), _labeled_expand(secret, b"base_nonce", ctx, 12)


def main() -> None:
    ok = 0
    for _ in range(20):
        sk = os.urandom(32)
        sk_m, sk_x, _, _ = expand(sk)
        pub = hpke.MLKEM768X25519PublicKey(sk_m.public_key(), sk_x.public_key())
        info, pt = os.urandom(8), os.urandom(40)
        blob = SUITE.encrypt(pt, pub, info=info)
        enc, ct = blob[:1120], blob[1120:]
        key, nonce = _base_mode_key_nonce(decapsulate(sk, enc), info)
        ok += ChaCha20Poly1305(key).decrypt(nonce, ct, b"") == pt
    print(f"{ok}/20 pyca-HPKE ciphertexts opened with our X-Wing decapsulation")
    assert ok == 20

    ok = 0
    for _ in range(20):
        sk = os.urandom(32)
        sk_m, sk_x, pk_m, pk_x = expand(sk)
        ss, enc = encapsulate(pk_m + pk_x)
        info, pt = os.urandom(8), os.urandom(40)
        key, nonce = _base_mode_key_nonce(ss, info)
        blob = enc + ChaCha20Poly1305(key).encrypt(nonce, pt, b"")
        ok += SUITE.decrypt(blob, hpke.MLKEM768X25519PrivateKey(sk_m, sk_x), info=info) == pt
    print(f"{ok}/20 of our X-Wing encapsulations opened by pyca HPKE")
    assert ok == 20


if __name__ == "__main__":
    main()
