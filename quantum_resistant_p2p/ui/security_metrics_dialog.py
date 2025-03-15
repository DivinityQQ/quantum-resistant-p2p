"""
Dialog for displaying security metrics.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QFormLayout, QTextEdit, QTabWidget, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from ..app import SecureLogger

logger = logging.getLogger(__name__)


class SecurityMetricsDialog(QDialog):
    """Dialog for displaying security metrics."""
    
    def __init__(self, secure_messaging, secure_logger, parent=None):
        """Initialize the security metrics dialog.
        
        Args:
            secure_messaging: The secure messaging service
            secure_logger: The secure logger instance
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.secure_messaging = secure_messaging
        self.secure_logger = secure_logger
        
        self.setWindowTitle("Security Metrics")
        self.setMinimumSize(600, 450)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Create tabs
        tabs = QTabWidget()
        
        # Algorithms info tab
        algo_tab = QWidget()
        algo_layout = QVBoxLayout(algo_tab)
        
        # Current security settings
        security_group = QGroupBox("Current Security Settings")
        security_layout = QFormLayout()
        
        # Get security info from the messaging service
        security_info = self.secure_messaging.get_security_info()
        
        # Key Exchange
        key_exchange_info = security_info["key_exchange"]
        key_exchange_text = QLabel(f"{key_exchange_info['algorithm']} (Level {key_exchange_info['security_level']})")
        key_exchange_text.setToolTip(key_exchange_info["description"])
        security_layout.addRow("Key Exchange:", key_exchange_text)
        
        # Symmetric encryption
        symmetric_info = security_info["symmetric"]
        symmetric_text = QLabel(f"{symmetric_info['algorithm']} ({symmetric_info['key_size']*8} bits)")
        symmetric_text.setToolTip(symmetric_info["description"])
        security_layout.addRow("Symmetric Encryption:", symmetric_text)
        
        # Digital signature
        signature_info = security_info["signature"]
        signature_text = QLabel(f"{signature_info['algorithm']} (Level {signature_info['security_level']})")
        signature_text.setToolTip(signature_info["description"])
        security_layout.addRow("Digital Signature:", signature_text)
        
        # Peers with shared keys
        peers_text = QLabel(f"{security_info['peers_with_shared_keys']}")
        security_layout.addRow("Peers with Shared Keys:", peers_text)
        
        security_group.setLayout(security_layout)
        algo_layout.addWidget(security_group)
        
        # Algorithm details
        details_group = QGroupBox("Algorithm Details")
        details_layout = QVBoxLayout()
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        # Compile detailed algorithm information
        details = (
            "### Key Exchange Algorithm\n"
            f"**Algorithm**: {key_exchange_info['algorithm']}\n"
            f"**Security Level**: {key_exchange_info['security_level']}\n"
            f"**Description**: {key_exchange_info['description']}\n\n"
            
            "### Symmetric Encryption Algorithm\n"
            f"**Algorithm**: {symmetric_info['algorithm']}\n"
            f"**Key Size**: {symmetric_info['key_size']*8} bits\n"
            f"**Description**: {symmetric_info['description']}\n\n"
            
            "### Digital Signature Algorithm\n"
            f"**Algorithm**: {signature_info['algorithm']}\n"
            f"**Security Level**: {signature_info['security_level']}\n"
            f"**Description**: {signature_info['description']}\n"
        )
        
        details_text.setPlainText(details)
        details_layout.addWidget(details_text)
        details_group.setLayout(details_layout)
        algo_layout.addWidget(details_group)
        
        tabs.addTab(algo_tab, "Algorithms")
        
        # Usage metrics tab
        metrics_tab = QWidget()
        metrics_layout = QVBoxLayout(metrics_tab)
        
        # Get metrics from the secure logger
        metrics = self.secure_logger.get_security_metrics()
        
        # Basic metrics
        metrics_group = QGroupBox("Usage Metrics")
        form_layout = QFormLayout()
        
        # Display metrics
        form_layout.addRow("Total Events:", QLabel(str(metrics.get('total_events', 0))))
        form_layout.addRow("Key Exchanges:", QLabel(str(metrics.get('key_exchanges', 0))))
        form_layout.addRow("Messages Sent:", QLabel(str(metrics.get('messages_sent', 0))))
        form_layout.addRow("Messages Received:", QLabel(str(metrics.get('messages_received', 0))))
        form_layout.addRow("Files Transferred:", QLabel(str(metrics.get('files_transferred', 0))))
        form_layout.addRow("Total Bytes Transferred:", QLabel(f"{metrics.get('total_bytes_transferred', 0):,} bytes"))
        
        # Add timestamps if available
        if metrics.get('first_event_time'):
            import datetime
            first_time = datetime.datetime.fromtimestamp(metrics['first_event_time']).strftime('%Y-%m-%d %H:%M:%S')
            form_layout.addRow("First Activity:", QLabel(first_time))
            
        if metrics.get('last_event_time'):
            import datetime
            last_time = datetime.datetime.fromtimestamp(metrics['last_event_time']).strftime('%Y-%m-%d %H:%M:%S')
            form_layout.addRow("Latest Activity:", QLabel(last_time))
        
        metrics_group.setLayout(form_layout)
        metrics_layout.addWidget(metrics_group)
        
        # Algorithms used
        if metrics.get('algorithms_used'):
            algos_group = QGroupBox("Algorithms Used")
            algos_layout = QVBoxLayout()
            
            algos_table = QTableWidget()
            algos_table.setColumnCount(2)
            algos_table.setHorizontalHeaderLabels(["Algorithm", "Usage Count"])
            algos_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            
            # Add rows for each algorithm
            algos_table.setRowCount(len(metrics['algorithms_used']))
            row = 0
            for algo, count in metrics['algorithms_used'].items():
                algos_table.setItem(row, 0, QTableWidgetItem(algo))
                algos_table.setItem(row, 1, QTableWidgetItem(str(count)))
                row += 1
            
            algos_layout.addWidget(algos_table)
            algos_group.setLayout(algos_layout)
            metrics_layout.addWidget(algos_group)
        
        tabs.addTab(metrics_tab, "Usage Metrics")
        
        # Event summary tab
        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        
        # Get event summary
        summary = self.secure_logger.get_event_summary()
        
        summary_table = QTableWidget()
        summary_table.setColumnCount(2)
        summary_table.setHorizontalHeaderLabels(["Event Type", "Count"])
        summary_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        # Add rows for each event type
        summary_table.setRowCount(len(summary))
        row = 0
        for event_type, count in summary.items():
            summary_table.setItem(row, 0, QTableWidgetItem(event_type))
            summary_table.setItem(row, 1, QTableWidgetItem(str(count)))
            row += 1
        
        summary_layout.addWidget(summary_table)
        tabs.addTab(summary_tab, "Event Summary")
        
        layout.addWidget(tabs)
        
        # Close button
        button_layout = QHBoxLayout()
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
