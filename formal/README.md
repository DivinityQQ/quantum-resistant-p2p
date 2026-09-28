# Formal models (ProVerif)

Symbolic models of the QRP2P v2 handshake (DESIGN §7), record layer (§8.1) and signed PQ rekey
(§8.4), written before the protocol code (IMPLEMENTATION_PLAN M1). CI runs them in the job
"Formal model (ProVerif)" whenever `formal/` or the CI workflow changes, and weekly; the job
uploads ProVerif's full output, attack traces included.

```bash
python formal/verify.py                      # all models; needs proverif on PATH
python formal/verify.py formal/rekey.pv      # one model
proverif -lib formal/qrp2p formal/handshake.pv   # by hand
```

ProVerif 2.05: `opam install proverif`, or build the source tarball with OCaml (see the CI job).

## Layout

| File | What it shows |
| --- | --- |
| `qrp2p.pvl` | Shared library: primitives, events and the honest handshake and rekey processes. Its header lists the modelling simplifications |
| `handshake.pv` | Secrecy of both directions' first records; injective agreement: responder on the initiator at Confirm, initiator on everything including the admission decision at Admit, responder on `th_final` at the first record |
| `handshake_fs.pv` | Forward secrecy: identity keys revealed after the sessions |
| `hybrid_m.pv`, `hybrid_x.pv` | Hybrid secrecy with ML-KEM-768 or X25519 broken |
| `hybrid_both.pv` | Sanity check: both broken, secrecy MUST fail |
| `rekey.pv` | Post-compromise recovery: after one signed rekey, an active attacker that read the whole session state is locked out |
| `record.pv` | Implicit sequence numbers: confidentiality with a known plaintext, and every record accepted once, in order |
| `weakened/*.pv` | One model per weakened engine (DESIGN §11.8), each with one defence removed; each MUST yield an attack |
| `redundant/*.pv` | Defences whose removal alone yields no attack (defence in depth) |

Every query carries an `EXPECT` line: `true` (the property holds), `false` (an expected attack,
in `weakened/` and `hybrid_both.pv`) or `reachable` (a sanity check that the model is not
vacuous; see below).

## Results (ProVerif 2.05, CI)

| Model | Result |
| --- | --- |
| `handshake.pv` | Secrecy of `ap_I` and `ap_R` holds. Injective agreement holds in all three directions, including the admission decision, the glass-box flag and `th_final` |
| `handshake_fs.pv` | Forward secrecy holds (identity keys revealed after the sessions); about 9 minutes |
| `hybrid_m.pv`, `hybrid_x.pv` | Secrecy holds with either X-Wing component broken |
| `hybrid_both.pv` | Secrecy fails, as it must (checked on the responder's record) |
| `rekey.pv` | After a signed rekey, the new traffic secrets stay secret from an attacker that read the whole session state; agreement on the rekey holds both ways |
| `record.pv` | A known plaintext reveals nothing about other records; every record is accepted once, in order |
| `weakened/no_pin_check.pv` | Attack: MITM on a pinned contact (secrecy and all agreements fail) |
| `weakened/unbound_signature.pv` | Attack: impersonation of either side with a replayed signature |
| `weakened/unbound_hello.pv` | Attack: downgrade; agreement on profile and `gb_request` fails (secrecy holds) |
| `weakened/unsigned_rekey.pv` | Attack: an active A5 attacker keeps reading after the rekey |
| `weakened/nonce_reuse.pv` | Attack: keystream recovery reveals the secret record |
| `weakened/replay_dedup.pv` | Attack: a record is accepted twice |
| `redundant/no_finished.pv`, `redundant/unsigned_identity.pv` | **No attack.** The handshake AEAD under keys from `ss` already binds possession of the key and the identity. DESIGN §11.8 was changed accordingly |

### What the model found

1. **Two weakened engines of the original DESIGN §11.8 were not attackable** (the `redundant/`
   rows). DESIGN 1.2 replaced them with the `unbound_signature` and `unbound_hello` variants.
2. **The rekey's agreement relies on the exporter binding the identities.** A first model that let
   the attacker hand an honest party any exporter value found an identity misbinding on the
   rekey. In the protocol, `exporter_n` is derived from `th_final`, which covers both identity
   bundles, so the model now makes the exporter a function of both identities. Whoever changes
   the exporter derivation must keep that property.

### Reachability checks

Each model has `query event(Done)` checks with `EXPECT reachable`, so a model that silently
never completes cannot pass. For the initiator's completion ProVerif prints a derivation (an
ordinary honest run) but "could not find a trace corresponding to this derivation", so its
verdict is "cannot be proved" rather than "is false". The weakened models show the same code
path completing in reconstructed attack traces.

### Not modelled (see the header of `qrp2p.pvl`)

The two halves of the hybrid signature separately; ML-KEM's binding properties for `PQ-CNSA-1`
(the Tamarin cross-check, now planned for M6); KeyUpdate; sizes, encodings and timing; the
reflection checks, which are local policy.
