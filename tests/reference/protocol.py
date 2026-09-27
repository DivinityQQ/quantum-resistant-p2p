"""An independent, derandomised implementation of DESIGN §4, §5, §7 and §8.4.

Written from the spec without importing ``qrp2p``. Deterministic because every random value is a
parameter: ML-KEM encapsulation coins, X25519 ephemeral scalars, nonces, and deterministic ML-DSA
signing (a valid FIPS 204 variant that pyca verifies like any other signature).
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Literal

import msgspec
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

PREFIX = b"qrp2p2 "
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # "\.//^\"


@dataclass(frozen=True)
class Profile:
    id: int
    kem: Literal["xwing", "mlkem1024"]
    sig: Literal["ed25519+mldsa65", "mldsa87"]
    aead: Literal["chacha20poly1305", "aes256gcm"]
    hash: Literal["sha256", "sha384"]

    @property
    def hlen(self) -> int:
        return hashlib.new(self.hash).digest_size


HYBRID_1 = Profile(0x01, "xwing", "ed25519+mldsa65", "chacha20poly1305", "sha256")
PQ_CNSA_1 = Profile(0x02, "mlkem1024", "mldsa87", "aes256gcm", "sha384")


# --- hash, HKDF, AEAD ---------------------------------------------------------------------------


def h(p: Profile, data: bytes) -> bytes:
    return hashlib.new(p.hash, data).digest()


def extract(p: Profile, salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, p.hash).digest()


def expand(p: Profile, prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), p.hash).digest()
        out += block
        i += 1
    return out[:length]


def expand_label(p: Profile, secret: bytes, label: str, ctx: bytes, length: int) -> bytes:
    full = PREFIX + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return expand(p, secret, info, length)


def derive_secret(p: Profile, secret: bytes, label: str, th: bytes) -> bytes:
    return expand_label(p, secret, label, th, p.hlen)


def keys(p: Profile, secret: bytes) -> tuple[bytes, bytes]:
    return expand_label(p, secret, "key", b"", 32), expand_label(p, secret, "iv", b"", 12)


def seal(p: Profile, k: tuple[bytes, bytes], seq: int, aad: bytes, pt: bytes) -> bytes:
    key, iv = k
    nonce = (int.from_bytes(iv, "big") ^ seq).to_bytes(12, "big")
    cipher = ChaCha20Poly1305(key) if p.aead == "chacha20poly1305" else AESGCM(key)
    return cipher.encrypt(nonce, pt, aad)


def open_(p: Profile, k: tuple[bytes, bytes], seq: int, aad: bytes, ct: bytes) -> bytes:
    key, iv = k
    nonce = (int.from_bytes(iv, "big") ^ seq).to_bytes(12, "big")
    cipher = ChaCha20Poly1305(key) if p.aead == "chacha20poly1305" else AESGCM(key)
    return cipher.decrypt(nonce, ct, aad)


def entry(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + len(value).to_bytes(4, "big") + value


def header(frame_type: int, length: int) -> bytes:
    return length.to_bytes(4, "big") + bytes([frame_type])


# --- identity (DESIGN §5.1) and signatures (§4.4) -----------------------------------------------


class Identity:
    def __init__(self, ed_seed: bytes, mldsa65_seed: bytes, mldsa87_seed: bytes) -> None:
        self.seeds = (ed_seed, mldsa65_seed, mldsa87_seed)
        self._ed = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
        self._pk65, self._sk65 = ML_DSA_65.key_derive(mldsa65_seed)
        self._pk87, self._sk87 = ML_DSA_87.key_derive(mldsa87_seed)
        self.bundle = b"\x01" + self._ed.public_key().public_bytes_raw() + self._pk65 + self._pk87

    def sign(self, p: Profile, role: str, th: bytes) -> bytes:
        ctx = PREFIX + role.encode()
        if p.sig == "mldsa87":
            return ML_DSA_87.sign(self._sk87, th, ctx=ctx, deterministic=True)
        ed_sig = self._ed.sign(ctx + b"\x00" + th)
        return ed_sig + ML_DSA_65.sign(self._sk65, th, ctx=ctx, deterministic=True)


def verify(p: Profile, bundle: bytes, role: str, th: bytes, sig: bytes) -> bool:
    ctx = PREFIX + role.encode()
    ed_pk, pk65, pk87 = bundle[1:33], bundle[33 : 33 + 1952], bundle[33 + 1952 :]
    if p.sig == "mldsa87":
        return ML_DSA_87.verify(pk87, th, sig, ctx=ctx)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(sig[:64], ctx + b"\x00" + th)
    except Exception:  # noqa: BLE001  # the reference only needs a yes or no
        return False
    return ML_DSA_65.verify(pk65, th, sig[64:], ctx=ctx)


# --- KEMs (DESIGN §4.2) ------------------------------------------------------------------------


@dataclass
class KemKey:
    ek: bytes
    dk: Any


def kem_keygen(p: Profile, seed: bytes) -> KemKey:
    if p.kem == "mlkem1024":
        ek, dk = ML_KEM_1024.key_derive(seed)
        return KemKey(ek, dk)
    e = hashlib.shake_256(seed).digest(96)
    ek_m, dk_m = ML_KEM_768.key_derive(e[:64])
    sk_x = x25519.X25519PrivateKey.from_private_bytes(e[64:])
    pk_x = sk_x.public_key().public_bytes_raw()
    return KemKey(ek_m + pk_x, (dk_m, sk_x, pk_x))


@dataclass
class Encapsulation:
    ss: bytes
    ct: bytes
    components: tuple[bytes, ...] = ()


def kem_encaps(p: Profile, ek: bytes, coins: bytes) -> Encapsulation:
    if p.kem == "mlkem1024":
        ss, ct = ML_KEM_1024._encaps_internal(ek, coins[:32])
        return Encapsulation(ss, ct)
    ek_m, pk_x = ek[:1184], ek[1184:]
    ss_m, ct_m = ML_KEM_768._encaps_internal(ek_m, coins[:32])
    e_x = x25519.X25519PrivateKey.from_private_bytes(coins[32:64])
    ct_x = e_x.public_key().public_bytes_raw()
    ss_x = e_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    ss = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()
    return Encapsulation(ss, ct_m + ct_x, (ss_m, ss_x))


def kem_decaps(p: Profile, key: KemKey, ct: bytes) -> bytes:
    if p.kem == "mlkem1024":
        return ML_KEM_1024.decaps(key.dk, ct)
    dk_m, sk_x, pk_x = key.dk
    ss_m = ML_KEM_768.decaps(dk_m, ct[:1088])
    ss_x = sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(ct[1088:]))
    return hashlib.sha3_256(ss_m + ss_x + ct[1088:] + pk_x + XWING_LABEL).digest()


# --- the handshake (DESIGN §7) -------------------------------------------------------------------


@dataclass
class Inputs:
    """Every random value of one handshake and one rekey."""

    initiator: Identity
    responder: Identity
    kem_seed: bytes
    nonce_i: bytes
    nonce_r: bytes
    coins: bytes
    gb_request: bool
    glass_box: bool
    rekey_seed: bytes
    rekey_coins: bytes


@dataclass
class Result:
    values: dict[str, bytes] = field(default_factory=dict)

    def __setitem__(self, name: str, value: bytes) -> None:
        self.values[name] = value

    def __getitem__(self, name: str) -> bytes:
        return self.values[name]


def handshake(p: Profile, x: Inputs) -> Result:  # one straight-line script
    out = Result()
    # 1. Hello
    eph = kem_keygen(p, x.kem_seed)
    hello = bytes([0x02, p.id, 0x01 if x.gb_request else 0x00]) + x.nonce_i + eph.ek
    out["hello"] = header(0x10, len(hello)) + hello
    # 2. Reply
    enc = kem_encaps(p, eph.ek, x.coins)
    assert kem_decaps(p, eph, enc.ct) == enc.ss
    out["ss"] = enc.ss
    for name, value in zip(("ssM", "ssX"), enc.components, strict=False):
        out[name] = value
    out["ct"] = enc.ct
    tr = entry(0x10, hello) + entry(0x11, x.nonce_r + enc.ct)
    th_hello = h(p, tr)
    hs = extract(p, bytes(p.hlen), enc.ss)
    hs_r, hs_i = (
        derive_secret(p, hs, "r hs traffic", th_hello),
        derive_secret(p, hs, "i hs traffic", th_hello),
    )
    fk_r = expand_label(p, hs_r, "finished", b"", p.hlen)
    fk_i = expand_label(p, hs_i, "finished", b"", p.hlen)
    out.values |= {"th_hello": th_hello, "hs": hs, "hs_R": hs_r, "hs_I": hs_i}
    tr += entry(0x21, x.responder.bundle)
    sig_r = x.responder.sign(p, "responder", h(p, tr))
    tr += entry(0x22, sig_r)
    fin_r = hmac.new(fk_r, h(p, tr), p.hash).digest()
    tr += entry(0x23, fin_r)
    out["sig_R"] = sig_r
    sig_len = len(sig_r)
    reply_len = 32 + len(enc.ct) + 4577 + sig_len + p.hlen + 16
    sealed = seal(p, keys(p, hs_r), 0, header(0x11, reply_len), x.responder.bundle + sig_r + fin_r)
    reply = x.nonce_r + enc.ct + sealed
    out["reply"] = header(0x11, len(reply)) + reply
    # 3. Confirm
    tr += entry(0x31, x.initiator.bundle)
    sig_i = x.initiator.sign(p, "initiator", h(p, tr))
    tr += entry(0x32, sig_i)
    fin_i = hmac.new(fk_i, h(p, tr), p.hash).digest()
    tr += entry(0x33, fin_i)
    out["sig_I"] = sig_i
    confirm_len = 4577 + sig_len + p.hlen + 16
    confirm = seal(
        p, keys(p, hs_i), 0, header(0x12, confirm_len), x.initiator.bundle + sig_i + fin_i
    )
    out["confirm"] = header(0x12, len(confirm)) + confirm
    # 4. Admit
    admit_body = bytes([0x00, 0x01 if x.glass_box else 0x00, 0x00])
    tr += entry(0x41, admit_body)
    fin_a = hmac.new(fk_r, h(p, tr), p.hash).digest()
    tr += entry(0x42, fin_a)
    admit = seal(p, keys(p, hs_r), 1, header(0x13, 3 + p.hlen + 16), admit_body + fin_a)
    out["admit"] = header(0x13, len(admit)) + admit
    th_final = h(p, tr)
    out["th_final"] = th_final
    # Traffic secrets
    cs_0 = extract(p, derive_secret(p, hs, "derived", h(p, b"")), bytes(p.hlen))
    out.values |= {
        "cs_0": cs_0,
        "ap_I_0": derive_secret(p, cs_0, "i ap traffic", th_final),
        "ap_R_0": derive_secret(p, cs_0, "r ap traffic", th_final),
        "exporter_0": derive_secret(p, cs_0, "exporter", th_final),
    }
    # The initiator's first record: chat "hello" (Inner is MessagePack, DESIGN §8.2).
    chat = msgspec.msgpack.encode({"kind": "chat", "id": bytes(16), "text": "hello"})
    record = seal(p, keys(p, out["ap_I_0"]), 0, header(0x20, len(chat) + 16), chat)
    out["record_I_0"] = header(0x20, len(record)) + record
    rekey(p, x, out)
    return out


def rekey(p: Profile, x: Inputs, out: Result) -> None:
    """The signed PQ rekey from epoch 0 to 1 (DESIGN §8.4)."""
    exporter = out["exporter_0"]
    eph = kem_keygen(p, x.rekey_seed)
    enc = kem_encaps(p, eph.ek, x.rekey_coins)
    assert kem_decaps(p, eph, enc.ct) == enc.ss
    rt = entry(0x51, eph.ek) + entry(0x52, enc.ct)
    sig_r = x.responder.sign(p, "rekey-answer", h(p, rt + exporter))
    assert verify(p, x.responder.bundle, "rekey-answer", h(p, rt + exporter), sig_r)
    with_sig_r = rt + entry(0x53, sig_r)
    sig_i = x.initiator.sign(p, "rekey-finish", h(p, with_sig_r + exporter))
    th_rekey = h(p, with_sig_r + entry(0x54, sig_i))
    cs_1 = extract(p, derive_secret(p, out["cs_0"], "derived", h(p, b"")), enc.ss)
    out.values |= {
        "rekey_ek": eph.ek,
        "rekey_ct": enc.ct,
        "rekey_ss": enc.ss,
        "rekey_sig_R": sig_r,
        "rekey_sig_I": sig_i,
        "th_rekey": th_rekey,
        "cs_1": cs_1,
        "ap_I_1": derive_secret(p, cs_1, "i ap traffic", th_rekey),
        "ap_R_1": derive_secret(p, cs_1, "r ap traffic", th_rekey),
        "exporter_1": derive_secret(p, cs_1, "exporter", th_rekey),
    }
    for name, value in zip(("rekey_ssM", "rekey_ssX"), enc.components, strict=False):
        out[name] = value
