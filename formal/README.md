# Formal models (ProVerif)

Symbolic models of the QRP2P v2 handshake (DESIGN §7), record layer (§8.1) and signed PQ rekey
(§8.4), written before the protocol code (IMPLEMENTATION_PLAN M1). CI runs them in the job
"Formal model (ProVerif)"; the job uploads ProVerif's full output, attack traces included.

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
| `weakened/*.pv` | One model per weakened engine (DESIGN §11.8), each with one defence removed |

Every query carries an `EXPECT` line. `false` on a `not event(...)` query means the event is
reachable, which shows the model is not vacuous; `false` on a secrecy or agreement query in
`weakened/` is the expected attack.

## Results

Filled in from the CI run that first verified the models.
