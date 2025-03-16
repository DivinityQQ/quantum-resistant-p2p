"""
Widget to display OQS implementation status.
"""

import logging
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel, QPushButton
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

from ..crypto import LIBOQS_AVAILABLE, LIBOQS_VERSION

logger = logging.getLogger(__name__)


class OQSStatusWidget(QWidget):
    """Widget to display OQS implementation status."""
    
    # Signal to open OQS setup window
    setup_clicked = pyqtSignal()
    
    def __init__(self, parent=None):
        """Initialize the OQS status widget."""
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)
        
        # Status label
        if LIBOQS_AVAILABLE:
            self.status_label = QLabel(f"OQS: ✓ v{LIBOQS_VERSION}")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            self.setToolTip(f"Real OQS implementation is active (version {LIBOQS_VERSION})")
        else:
            self.status_label = QLabel("OQS: ⚠ Mock")
            self.status_label.setStyleSheet("color: orange; font-weight: bold;")
            self.setToolTip("Using mock implementations. Click the Setup button to install OQS.")
        
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        self.setFixedHeight(30)
