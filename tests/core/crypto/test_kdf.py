"""Key-schedule helpers (DESIGN §7.4) against RFC 5869, frozen KATs and an independent reference."""

import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as pyca_hmac
from hypothesis import given
from hypothesis import strategies as st

from qrp2p.core.crypto import kdf
from qrp2p.core.crypto.kdf import SHA256, SHA384, HashFunction
from qrp2p.core.crypto.secret import Secret
from tests.vectors import load_json, load_rfc5869_sha256

HASHES = {"SHA-256": SHA256, "SHA-384": SHA384}

# --- independent reference: stdlib hmac only, written from RFC 5869 and DESIGN §7.4 ------------


def ref_extract(name: str, salt: bytes, ikm: bytes) -> bytes:
    algo = name.replace("-", "").lower()
    return hmac.new(salt or bytes(hashlib.new(algo).digest_size), ikm, algo).digest()


def ref_expand(name: str, prk: bytes, info: bytes, length: int) -> bytes:
    algo = name.replace("-", "").lower()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), algo).digest()
        out += block
        counter += 1
    return out[:length]


def ref_label(length: int, label: str, context: bytes) -> bytes:
    full = b"qrp2p2 " + label.encode()
    return length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context


def ref_expand_label(name: str, secret: bytes, label: str, context: bytes, length: int) -> bytes:
    return ref_expand(name, secret, ref_label(length, label, context), length)


# --- RFC 5869 ------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", load_rfc5869_sha256(), ids=["A.1", "A.2", "A.3"])
def test_rfc5869_sha256(case: dict[str, bytes | int]) -> None:
    salt, ikm, info = case["salt"], case["IKM"], case["info"]
    length = case["L"]
    assert isinstance(salt, bytes)
    assert isinstance(ikm, bytes)
    assert isinstance(info, bytes)
    assert isinstance(length, int)
    prk = kdf.hkdf_extract(SHA256, salt, Secret(ikm, "ikm"), name="prk")
    assert prk.reveal() == case["PRK"]
    assert kdf.hkdf_expand(SHA256, prk, info, length, name="okm").reveal() == case["OKM"]
    # The reference must agree with the RFC too, or the cross-checks below prove nothing.
    assert ref_extract("SHA-256", salt, ikm) == case["PRK"]
    assert ref_expand("SHA-256", ref_extract("SHA-256", salt, ikm), info, length) == case["OKM"]


# --- layouts -------------------------------------------------------------------------------------


def test_hkdf_label_layout() -> None:
    assert kdf.hkdf_label(32, "key", b"") == b"\x00\x20\x0aqrp2p2 key\x00"
    assert kdf.hkdf_label(12, "iv", b"") == b"\x00\x0c\x09qrp2p2 iv\x00"
    th = bytes(range(32))
    assert kdf.hkdf_label(48, "derived", th) == b"\x00\x30\x0eqrp2p2 derived\x20" + th


def test_hkdf_label_limits() -> None:
    kdf.hkdf_label(0xFFFF, "x" * (255 - 7), bytes(255))  # the largest encodable label
    with pytest.raises(ValueError, match="u8"):
        kdf.hkdf_label(32, "x" * (256 - 7), b"")
    with pytest.raises(ValueError, match="u8"):
        kdf.hkdf_label(32, "key", bytes(256))
    with pytest.raises(ValueError, match="u16"):
        kdf.hkdf_label(0x10000, "key", b"")
    with pytest.raises(UnicodeEncodeError):
        kdf.hkdf_label(32, "clé", b"")


def test_expand_rejects_short_prk_and_bad_lengths() -> None:
    with pytest.raises(ValueError, match="PRK"):
        kdf.hkdf_expand(SHA256, Secret(bytes(31), "prk"), b"", 32, name="x")
    prk = Secret(bytes(32), "prk")
    with pytest.raises(ValueError, match="length"):
        kdf.hkdf_expand(SHA256, prk, b"", 0, name="x")
    with pytest.raises(ValueError, match="length"):
        kdf.hkdf_expand(SHA256, prk, b"", 255 * 32 + 1, name="x")
    assert len(kdf.hkdf_expand(SHA256, prk, b"", 255 * 32, name="x")) == 255 * 32


def test_hash_functions() -> None:
    assert SHA256.digest(b"abc") == hashlib.sha256(b"abc").digest()
    assert SHA384.digest(b"abc") == hashlib.sha384(b"abc").digest()
    assert (SHA256.length, SHA384.length) == (32, 48)
    assert isinstance(SHA256.algorithm(), hashes.SHA256)
    assert isinstance(SHA384.algorithm(), hashes.SHA384)


@pytest.mark.parametrize("h", [SHA256, SHA384])
def test_hmac_matches_pyca(h: HashFunction) -> None:
    key, data = bytes(range(h.length)), b"transcript hash"
    reference = pyca_hmac.HMAC(key, h.algorithm())
    reference.update(data)
    assert kdf.hmac_digest(h, Secret(key, "fk"), data) == reference.finalize()


def test_outputs_are_secrets_with_names() -> None:
    secret = Secret(bytes(32), "hs_R")
    assert kdf.expand_label(SHA256, secret, "finished", b"", 32).label == "finished"
    assert kdf.derive_secret(SHA256, secret, "r hs traffic", bytes(32), name="x").label == "x"
    keys = kdf.traffic_keys(SHA256, secret)
    assert (keys.key.label, keys.iv.label) == ("hs_R.key", "hs_R.iv")
    assert (len(keys.key), len(keys.iv)) == (32, 12)


# --- frozen KATs, cross-checked with the reference -----------------------------------------------


@pytest.mark.parametrize("name", ["SHA-256", "SHA-384"])
def test_kats(name: str) -> None:
    h, kat = HASHES[name], load_json("kdf.json")[name]
    for case in kat["hkdf_label"]:
        ctx = bytes.fromhex(case["context"])
        out = bytes.fromhex(case["out"])
        assert kdf.hkdf_label(case["length"], case["label"], ctx) == out
        assert ref_label(case["length"], case["label"], ctx) == out
    for case in kat["expand_label"]:
        secret, ctx = bytes.fromhex(case["secret"]), bytes.fromhex(case["context"])
        out = bytes.fromhex(case["out"])
        got = kdf.expand_label(h, Secret(secret, "S"), case["label"], ctx, case["length"])
        assert got.reveal() == out
        assert ref_expand_label(name, secret, case["label"], ctx, case["length"]) == out
    case = kat["derive_secret"]
    secret, th = bytes.fromhex(case["secret"]), bytes.fromhex(case["th"])
    got = kdf.derive_secret(h, Secret(secret, "S"), case["label"], th)
    assert got.reveal().hex() == case["out"]
    assert ref_expand_label(name, secret, case["label"], th, h.length).hex() == case["out"]
    case = kat["traffic_keys"]
    keys = kdf.traffic_keys(h, Secret(bytes.fromhex(case["secret"]), "S"))
    assert keys.key.reveal().hex() == case["key"]
    assert keys.iv.reveal().hex() == case["iv"]
    assert ref_expand_label(name, bytes.fromhex(case["secret"]), "iv", b"", 12).hex() == case["iv"]


@pytest.mark.parametrize("name", ["SHA-256", "SHA-384"])
def test_key_schedule_kat_matches_design_7_4(name: str) -> None:
    """A miniature of the handshake schedule, recomputed from the spec with the reference."""
    h, kat = HASHES[name], load_json("kdf.json")[name]["schedule"]
    hlen = h.length
    ss, th_hello, th_final = (bytes.fromhex(kat[k]) for k in ("ss", "th_hello", "th_final"))
    hs = ref_extract(name, bytes(hlen), ss)
    hs_r = ref_expand_label(name, hs, "r hs traffic", th_hello, hlen)
    fk_r = ref_expand_label(name, hs_r, "finished", b"", hlen)
    derived = ref_expand_label(name, hs, "derived", h.digest(b""), hlen)
    cs_0 = ref_extract(name, derived, bytes(hlen))
    ap_i = ref_expand_label(name, cs_0, "i ap traffic", th_final, hlen)
    expected = {"hs": hs, "hs_R": hs_r, "fk_R": fk_r, "cs_0": cs_0, "ap_I": ap_i}
    expected["ap_I_key"] = ref_expand_label(name, ap_i, "key", b"", 32)
    expected["ap_I_iv"] = ref_expand_label(name, ap_i, "iv", b"", 12)
    assert {k: v.hex() for k, v in expected.items()} == {k: kat[k] for k in expected}


@given(
    secret=st.binary(min_size=48, max_size=64),
    label=st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=40),
    context=st.binary(max_size=64),
    length=st.integers(min_value=1, max_value=200),
    use_sha384=st.booleans(),
)
def test_expand_label_matches_reference(
    secret: bytes, label: str, context: bytes, length: int, use_sha384: bool
) -> None:
    name = "SHA-384" if use_sha384 else "SHA-256"
    got = kdf.expand_label(HASHES[name], Secret(secret, "S"), label, context, length)
    assert got.reveal() == ref_expand_label(name, secret, label, context, length)


@given(salt=st.binary(max_size=64), ikm=st.binary(max_size=64))
def test_extract_matches_reference(salt: bytes, ikm: bytes) -> None:
    for name, h in HASHES.items():
        got = kdf.hkdf_extract(h, salt, Secret(ikm, "ikm"), name="prk")
        assert got.reveal() == ref_extract(name, salt, ikm)
