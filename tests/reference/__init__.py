"""Test-only derandomised reference of the protocol (IMPLEMENTATION_PLAN M1.6, DESIGN §15 row 2).

Never imported by ``src/``. It shares no code with ``qrp2p``: it is written again from the spec,
with pure-Python ML-KEM (``kyber-py``) and ML-DSA (``dilithium-py``) so that every random input
can be fixed. pyca/cryptography then verifies what it produces, byte for byte.
"""
