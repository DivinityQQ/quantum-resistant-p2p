"""X-Wing (DESIGN §4.2): official vectors, HPKE differential test and error mapping (M0 gate)."""

import hashlib
import hmac
import os
import struct

import pytest
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from qrp2p.core.crypto import xwing
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from tests.vectors import load_xwing

VECTORS = load_xwing()

# X25519 u-coordinates that yield an all-zero shared secret, including non-canonical encodings
# of 0 and 1 (p and p + 1). OpenSSL refuses them; X-Wing must map that to kem_failure.
LOW_ORDER_POINTS = {
    "zero": bytes(32),
    "one": b"\x01" + bytes(31),
    "order8": bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    "p-1": bytes.fromhex("ec" + "ff" * 30 + "7f"),
    "p": bytes.fromhex("ed" + "ff" * 30 + "7f"),
    "p+1": bytes.fromhex("ee" + "ff" * 30 + "7f"),
}


def expect(reason: CloseReason) -> pytest.RaisesExc[ProtocolError]:
    return pytest.raises(ProtocolError, check=lambda e: e.reason is reason)


# --- official vectors (draft-connolly-cfrg-xwing-kem) --------------------------------------------


def test_vector_file_has_three_complete_vectors() -> None:
    assert len(VECTORS) == 3
    for vector in VECTORS:
        assert set(vector) == {"seed", "sk", "pk", "eseed", "ct", "ss"}


@pytest.mark.parametrize("vector", VECTORS, ids=["v0", "v1", "v2"])
def test_official_keygen(vector: dict[str, bytes]) -> None:
    sk, pk = xwing.keygen(Secret(vector["seed"], "seed"))
    assert sk.reveal() == vector["sk"]
    assert pk == vector["pk"]
    assert xwing.public_key(Secret(vector["sk"], "sk")) == vector["pk"]


@pytest.mark.parametrize("vector", VECTORS, ids=["v0", "v1", "v2"])
def test_official_decapsulation(vector: dict[str, bytes]) -> None:
    shared = xwing.decapsulate(Secret(vector["sk"], "sk"), vector["ct"])
    assert shared.ss.reveal() == vector["ss"]


# --- HPKE differential test: pyca's MLKEM768_X25519 KEM is X-Wing --------------------------------

# RFC 9180 suite: KEM 0x647a (MLKEM768-X25519, draft-ietf-hpke-pq), HKDF-SHA256, ChaCha20-Poly1305.
SUITE_ID = b"HPKE" + struct.pack(">HHH", 0x647A, 0x0001, 0x0003)
SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
TRIALS = 20


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), b"HPKE-v1" + SUITE_ID + label + ikm, "sha256").digest()


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = struct.pack(">H", length) + b"HPKE-v1" + SUITE_ID + label + info
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + labeled + bytes([counter]), "sha256").digest()
        out += block
        counter += 1
    return out[:length]


def _base_mode_key_nonce(ss: bytes, info: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 §5.1 key schedule, base mode, written independently of pyca."""
    context = (
        b"\x00"
        + _labeled_extract(b"", b"psk_id_hash", b"")
        + _labeled_extract(b"", b"info_hash", info)
    )
    secret = _labeled_extract(ss, b"secret", b"")
    return (
        _labeled_expand(secret, b"key", context, 32),
        _labeled_expand(secret, b"base_nonce", context, 12),
    )


def _pyca_keys(sk: Secret) -> tuple[mlkem.MLKEM768PrivateKey, x25519.X25519PrivateKey]:
    expanded = hashlib.shake_256(sk.reveal()).digest(96)
    return (
        mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
        x25519.X25519PrivateKey.from_private_bytes(expanded[64:]),
    )


def test_hpke_differential_pyca_encapsulates_we_decapsulate() -> None:
    for _ in range(TRIALS):
        sk = Secret(os.urandom(32), "sk")
        sk_m, sk_x = _pyca_keys(sk)
        public = hpke.MLKEM768X25519PublicKey(sk_m.public_key(), sk_x.public_key())
        info, plaintext = os.urandom(8), os.urandom(40)
        blob = SUITE.encrypt(plaintext, public, info=info)
        enc, ciphertext = blob[: xwing.CT_LEN], blob[xwing.CT_LEN :]
        key, nonce = _base_mode_key_nonce(xwing.decapsulate(sk, enc).ss.reveal(), info)
        assert ChaCha20Poly1305(key).decrypt(nonce, ciphertext, b"") == plaintext


def test_hpke_differential_we_encapsulate_pyca_decapsulates() -> None:
    for _ in range(TRIALS):
        sk, pk = xwing.keygen(Secret(os.urandom(32), "seed"))
        sk_m, sk_x = _pyca_keys(sk)
        shared, enc = xwing.encapsulate(pk)
        info, plaintext = os.urandom(8), os.urandom(40)
        key, nonce = _base_mode_key_nonce(shared.ss.reveal(), info)
        blob = enc + ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")
        private = hpke.MLKEM768X25519PrivateKey(sk_m, sk_x)
        assert SUITE.decrypt(blob, private, info=info) == plaintext


# --- structure and sizes -------------------------------------------------------------------------


def test_round_trip_sizes_and_components() -> None:
    sk, pk = xwing.keygen(Secret(os.urandom(32), "seed"))
    shared, ct = xwing.encapsulate(pk)
    assert (len(pk), len(ct), len(shared.ss)) == (1216, 1120, 32)
    decapsulated = xwing.decapsulate(sk, ct)
    assert decapsulated == shared
    ss_m, ss_x = (c.reveal() for c in shared.components)
    assert [c.label for c in shared.components] == ["ssM", "ssX"]
    combined = hashlib.sha3_256(
        ss_m + ss_x + ct[1088:] + pk[1184:] + bytes.fromhex("5c2e2f2f5e5c")
    ).digest()
    assert shared.ss.reveal() == combined


def test_scheme_object_matches_module_functions() -> None:
    scheme = xwing.XWING
    assert (scheme.seed_len, scheme.ek_len, scheme.ct_len, scheme.ss_len) == (32, 1216, 1120, 32)
    vector = VECTORS[0]
    _, pk = scheme.keygen(Secret(vector["seed"], "seed"))
    assert pk == vector["pk"]
    assert scheme.decapsulate(Secret(vector["sk"], "sk"), vector["ct"]).ss.reveal() == vector["ss"]
    shared, ct = scheme.encapsulate(pk)
    assert xwing.decapsulate(Secret(vector["sk"], "sk"), ct) == shared


def test_tampered_mlkem_ciphertext_gives_a_different_secret() -> None:
    """ML-KEM implicit rejection: no error, just an unrelated secret (caught later by AEAD)."""
    sk, pk = xwing.keygen(Secret(os.urandom(32), "seed"))
    shared, ct = xwing.encapsulate(pk)
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    assert xwing.decapsulate(sk, tampered).ss != shared.ss


# --- error mapping -------------------------------------------------------------------------------


def _with_coefficient(pk_m: bytes, index: int, value: int) -> bytes:
    """Overwrite 12-bit coefficient ``index`` of an encoded ML-KEM public key."""
    data = bytearray(pk_m)
    base = 3 * (index // 2)
    if index % 2 == 0:
        data[base] = value & 0xFF
        data[base + 1] = (data[base + 1] & 0xF0) | (value >> 8)
    else:
        data[base + 1] = (data[base + 1] & 0x0F) | ((value & 0x0F) << 4)
        data[base + 2] = value >> 4
    return bytes(data)


@pytest.mark.parametrize(("index", "value"), [(0, 3329), (0, 4095), (767, 3329), (511, 3500)])
def test_mlkem_coefficient_not_below_q_is_invalid_kem_key(index: int, value: int) -> None:
    pk = VECTORS[0]["pk"]
    bad = _with_coefficient(pk[:1184], index, value) + pk[1184:]
    with expect(CloseReason.INVALID_KEM_KEY):
        xwing.encapsulate(bad)


def test_coefficient_q_minus_one_is_accepted() -> None:
    pk = VECTORS[0]["pk"]
    edited = _with_coefficient(pk[:1184], 0, 3328) + pk[1184:]
    _, ct = xwing.encapsulate(edited)
    assert len(ct) == 1120


@pytest.mark.parametrize("size", [0, 32, 1184, 1215, 1217])
def test_public_key_of_wrong_size_is_invalid_kem_key(size: int) -> None:
    with expect(CloseReason.INVALID_KEM_KEY):
        xwing.encapsulate(bytes(size))


@pytest.mark.parametrize("point", LOW_ORDER_POINTS.values(), ids=LOW_ORDER_POINTS.keys())
def test_encapsulate_to_low_order_x25519_key_is_kem_failure(point: bytes) -> None:
    with expect(CloseReason.KEM_FAILURE):
        xwing.encapsulate(VECTORS[0]["pk"][:1184] + point)


@pytest.mark.parametrize("point", LOW_ORDER_POINTS.values(), ids=LOW_ORDER_POINTS.keys())
def test_decapsulate_low_order_x25519_ciphertext_is_kem_failure(point: bytes) -> None:
    vector = VECTORS[0]
    with expect(CloseReason.KEM_FAILURE):
        xwing.decapsulate(Secret(vector["sk"], "sk"), vector["ct"][:1088] + point)


@pytest.mark.parametrize("size", [0, 1088, 1119, 1121])
def test_ciphertext_of_wrong_size_is_kem_failure(size: int) -> None:
    with expect(CloseReason.KEM_FAILURE):
        xwing.decapsulate(Secret(VECTORS[0]["sk"], "sk"), bytes(size))


def test_own_key_of_wrong_size_is_internal() -> None:
    with expect(CloseReason.INTERNAL):
        xwing.public_key(Secret(bytes(31), "sk"))
    with expect(CloseReason.INTERNAL):
        xwing.decapsulate(Secret(bytes(33), "sk"), VECTORS[0]["ct"])
