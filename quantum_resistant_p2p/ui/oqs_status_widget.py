"""
Widget to display OQS implementation status.
"""

import logging
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from ..crypto import LIBOQS_VERSION

logger = logging.getLogger(__name__)


class OQSStatusWidget(QWidget):
    """Widget to display OQS implementation status."""
    
    def __init__(self, parent=None):
        """Initialize the OQS status widget."""
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 2, 5, 2)
        
        # Status label - now always shows as available since we vendor the library
        self.status_label = QLabel(f"OQS: ✓ v{LIBOQS_VERSION}")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")
        self.setToolTip(f"Using Open Quantum Safe library version {LIBOQS_VERSION}")
        
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        self.setFixedHeight(30)