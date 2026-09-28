"""Sans-I/O protocol core (DESIGN §12).

No sockets, threads, clocks, Qt or global randomness: time and randomness are injected. Imports
only the standard library, ``cryptography`` and ``msgspec`` (enforced by import-linter).
"""
