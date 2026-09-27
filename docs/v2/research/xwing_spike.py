"""X-Wing spike: X-Wing built from pyca/cryptography primitives, checked against
the official test vectors of draft-connolly-cfrg-xwing-kem.

Research code, not production code. It proves the construction in DESIGN.md §4.2
and is the starting point for qrp2p/core/crypto/xwing.py in M0.

Usage:  python xwing_spike.py            (needs cryptography >= 50 and network access
                                          to fetch the pinned vectors once)
"""

import hashlib
import pathlib
import urllib.request

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

VECTORS_URL = (
    "https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/"
    "984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.txt"
)
VECTORS_SHA256 = "6290fa1276ce0be3bf7505c058242279faba0d500c0ddefab4cbcb1990d6dc5b"
VECTORS_CACHE = pathlib.Path(__file__).with_name("xwing-test-vectors.txt")

XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # "\./" "/^\"


def expand(sk: bytes):
    e = hashlib.shake_256(sk).digest(96)
    sk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(e[0:64])  # 64-byte d||z seed
    sk_x = x25519.X25519PrivateKey.from_private_bytes(e[64:96])
    return sk_m, sk_x, sk_m.public_key().public_bytes_raw(), sk_x.public_key().public_bytes_raw()


def combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def public_key(sk: bytes) -> bytes:
    _, _, pk_m, pk_x = expand(sk)
    return pk_m + pk_x


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    pk_m, pk_x = pk[:1184], pk[1184:1216]
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()  # returns (ss, ct)
    eph = x25519.X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes_raw()
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    return combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decapsulate(sk: bytes, ct: bytes) -> bytes:
    sk_m, sk_x, _, pk_x = expand(sk)
    ss_m = sk_m.decapsulate(ct[:1088])
    ct_x = ct[1088:1120]
    ss_x = sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    return combiner(ss_m, ss_x, ct_x, pk_x)


def load_vectors() -> list[dict[str, bytes]]:
    if not VECTORS_CACHE.exists():
        VECTORS_CACHE.write_bytes(urllib.request.urlopen(VECTORS_URL, timeout=30).read())
    raw = VECTORS_CACHE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != VECTORS_SHA256:
        raise SystemExit("test-vector file hash mismatch")
    vectors, current, key = [], {}, None
    for line in raw.decode().splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            key, *rest = line.split()
            if key == "seed" and current:
                vectors.append(current)
                current = {}
            current[key] = "".join(rest)
        else:
            current[key] += line.strip()
    vectors.append(current)
    return [{k: bytes.fromhex(v) for k, v in vec.items()} for vec in vectors]


def main() -> None:
    for i, v in enumerate(load_vectors()):
        ok_pk = public_key(v["sk"]) == v["pk"]
        ok_ss = decapsulate(v["sk"], v["ct"]) == v["ss"]
        ss, ct = encapsulate(v["pk"])
        ok_rt = decapsulate(v["sk"], ct) == ss
        print(f"vector {i}: keygen {'OK' if ok_pk else 'FAIL'} | decaps {'OK' if ok_ss else 'FAIL'} "
              f"| random round trip {'OK' if ok_rt else 'FAIL'}")
        assert ok_pk and ok_ss and ok_rt
    # Encapsulation vectors (eseed) cannot be replayed: pyca's encapsulate() takes no randomness.
    # The encapsulation side is covered by hpke_diff_spike.py instead.


if __name__ == "__main__":
    main()
