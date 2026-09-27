"""QRP2P v2: a LAN messenger with a hybrid post-quantum channel and a learning layer.

The normative specification is docs/v2/DESIGN.md. Layers (DESIGN §12):

- ``qrp2p.core``: the sans-I/O protocol core and crypto providers.
- ``qrp2p.services``: asyncio networking, discovery, sessions and the vault.
- ``qrp2p.lab``: the solo lab, LAB-CLASSICAL, weakened engines and lab-only algorithms.
- ``qrp2p.ui``: the PySide6/QML desktop app.
"""
