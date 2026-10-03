"""Entry script for frozen builds (pyside6-deploy / Nuitka): the installed ``qrp2p`` command."""

import sys

from qrp2p.ui.app import main

if __name__ == "__main__":
    sys.exit(main())
