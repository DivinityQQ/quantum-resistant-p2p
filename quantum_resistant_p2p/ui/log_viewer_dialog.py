"""
Dialog for viewing secure logs.
"""

import logging
import datetime
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QDateTimeEdit, QGroupBox, QFormLayout, QCheckBox, QSplitter,
    QApplication
)
from PyQt5.QtCore import Qt, QDateTime
from PyQt5.QtGui import QColor, QFont, QPalette

from ..app import SecureLogger

logger = logging.getLogger(__name__)


class LogViewerDialog(QDialog):
    """Dialog for viewing secure logs."""
    
    def __init__(self, secure_logger, parent=None):
        """Initialize the log viewer dialog.
        
        Args:
            secure_logger: The secure logger instance
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.secure_logger = secure_logger
        
        self.setWindowTitle("Secure Logs")
        self.setMinimumSize(800, 600)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Filter controls
        filter_group = QGroupBox("Filter Options")
        filter_layout = QFormLayout()
        
        # Event type filter
        self.event_type_combo = QComboBox()
        self.event_type_combo.addItem("All Events", None)
        
        # Add all event types - get a unique list from the logs
        summary = self.secure_logger.get_event_summary()
        for event_type in summary.keys():
            self.event_type_combo.addItem(event_type, event_type)
        
        filter_layout.addRow("Event Type:", self.event_type_combo)
        
        # Time range filter
        time_layout = QHBoxLayout()
        
        self.start_time_check = QCheckBox("Start Time:")
        self.start_time_edit = QDateTimeEdit()
        self.start_time_edit.setCalendarPopup(True)
        self.start_time_edit.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.start_time_edit.setEnabled(False)
        self.start_time_check.toggled.connect(self.start_time_edit.setEnabled)
        
        time_layout.addWidget(self.start_time_check)
        time_layout.addWidget(self.start_time_edit)
        
        self.end_time_check = QCheckBox("End Time:")
        self.end_time_edit = QDateTimeEdit()
        self.end_time_edit.setCalendarPopup(True)
        self.end_time_edit.setDateTime(QDateTime.currentDateTime())
        self.end_time_edit.setEnabled(False)
        self.end_time_check.toggled.connect(self.end_time_edit.setEnabled)
        
        time_layout.addWidget(self.end_time_check)
        time_layout.addWidget(self.end_time_edit)
        
        filter_layout.addRow(time_layout)
        
        # Filter and refresh buttons
        button_layout = QHBoxLayout()
        
        self.apply_filter_button = QPushButton("Apply Filter")
        self.apply_filter_button.clicked.connect(self._apply_filter)
        button_layout.addWidget(self.apply_filter_button)
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh_logs)
        button_layout.addWidget(self.refresh_button)
        
        filter_layout.addRow(button_layout)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Logs table
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Event Type", "Peer", "Details", "Size"])
        self.logs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)  # Stretch Details column
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logs_table.setSelectionMode(QTableWidget.SingleSelection)
        
        # Set minimum column widths
        self.logs_table.setColumnWidth(0, 150)  # Timestamp
        self.logs_table.setColumnWidth(1, 120)  # Event Type
        self.logs_table.setColumnWidth(2, 150)  # Peer
        self.logs_table.setColumnWidth(4, 80)   # Size
        
        layout.addWidget(self.logs_table, 1)  # Give it a stretch factor of 1
        
        # Close button
        button_layout = QHBoxLayout()
        
        self.clear_logs_button = QPushButton("Clear All Logs")
        self.clear_logs_button.setStyleSheet("color: red;")
        self.clear_logs_button.clicked.connect(self._confirm_clear_logs)
        button_layout.addWidget(self.clear_logs_button)
        
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Initial load of logs
        self._refresh_logs()
    
    def _refresh_logs(self):
        """Refresh the logs display."""
        # Get filter settings
        event_type = self.event_type_combo.currentData()
        
        start_time = None
        if self.start_time_check.isChecked():
            start_time = self.start_time_edit.dateTime().toSecsSinceEpoch()
            
        end_time = None
        if self.end_time_check.isChecked():
            end_time = self.end_time_edit.dateTime().toSecsSinceEpoch()
        
        # Get logs with the current filter
        events = self.secure_logger.get_events(start_time, end_time, event_type)
        
        # Update the table
        self.logs_table.setRowCount(len(events))
        
        for row, event in enumerate(events):
            # Timestamp
            timestamp = datetime.datetime.fromtimestamp(event["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            timestamp_item = QTableWidgetItem(timestamp)
            self.logs_table.setItem(row, 0, timestamp_item)
            
            # Event type
            event_type_item = QTableWidgetItem(event["type"])
            self.logs_table.setItem(row, 1, event_type_item)
            
            # Peer ID
            peer_id = event.get("peer_id", "")
            if peer_id:
                peer_item = QTableWidgetItem(f"{peer_id[:8]}...")
                peer_item.setToolTip(peer_id)
            else:
                peer_item = QTableWidgetItem("")
            self.logs_table.setItem(row, 2, peer_item)
            
            # Details - compile relevant fields
            details = []
            
            # Algorithm info
            if "algorithm" in event:
                details.append(f"Algorithm: {event['algorithm']}")
            if "encryption_algorithm" in event:
                details.append(f"Encryption: {event['encryption_algorithm']}")
            if "signature_algorithm" in event:
                details.append(f"Signature: {event['signature_algorithm']}")
                
            # Direction
            if "direction" in event:
                details.append(f"Direction: {event['direction']}")
                
            # State
            if "state" in event:
                details.append(f"State: {event['state']}")
                
            # Is file
            if event.get("is_file", False):
                details.append(f"File: {event.get('filename', 'unknown')}")
                
            # Message ID
            if "message_id" in event:
                details.append(f"Message ID: {event['message_id']}")
            
            # Component (for settings changes)
            if "component" in event:
                details.append(f"Component: {event['component']}")
                if "old_algorithm" in event and "new_algorithm" in event:
                    details.append(f"Changed: {event['old_algorithm']} → {event['new_algorithm']}")
            
            details_item = QTableWidgetItem(", ".join(details))
            details_item.setToolTip("\n".join(details))
            self.logs_table.setItem(row, 3, details_item)
            
            # Size
            size = event.get("size", 0)
            size_item = QTableWidgetItem(f"{size:,}" if size > 0 else "")
            self.logs_table.setItem(row, 4, size_item)
            
            # Detect if we're using a dark theme by checking palette
            app = QApplication.instance()
            palette = app.palette()
            text_color = palette.color(QPalette.Text)
            base_color = palette.color(QPalette.Base)
            
            # Determine if dark theme based on text vs background contrast
            text_luminance = (0.299 * text_color.red() + 0.587 * text_color.green() + 0.114 * text_color.blue()) / 255
            base_luminance = (0.299 * base_color.red() + 0.587 * base_color.green() + 0.114 * base_color.blue()) / 255
            is_dark_theme = text_luminance > base_luminance
            
            # Choose colors based on theme
            if is_dark_theme:
                # Dark theme color scheme
                color_schemes = {
                    "default": QColor(40, 40, 40),  # Dark gray
                    "key_exchange": QColor(0, 60, 0),  # Dark green
                    "message_sent": QColor(0, 0, 60),  # Dark blue
                    "message_received": QColor(0, 0, 60),  # Dark blue
                    "crypto_settings_changed": QColor(60, 50, 0),  # Dark amber
                    "initialization": QColor(50, 50, 50)  # Darker gray
                }
                text_colors = {
                    "default": QColor(220, 220, 220),  # Light gray text
                    "key_exchange": QColor(200, 255, 200),  # Light green text
                    "message_sent": QColor(200, 200, 255),  # Light blue text
                    "message_received": QColor(200, 200, 255),  # Light blue text
                    "crypto_settings_changed": QColor(255, 240, 200),  # Light amber text
                    "initialization": QColor(220, 220, 220)  # Light gray text
                }
            else:
                # Light theme color scheme - original colors
                color_schemes = {
                    "default": QColor(255, 255, 255),  # White
                    "key_exchange": QColor(230, 255, 230),  # Light green
                    "message_sent": QColor(230, 230, 255),  # Light blue
                    "message_received": QColor(230, 230, 255),  # Light blue
                    "crypto_settings_changed": QColor(255, 240, 200),  # Light yellow
                    "initialization": QColor(240, 240, 240)  # Light gray
                }
                text_colors = {
                    "default": QColor(0, 0, 0),  # Black text
                    "key_exchange": QColor(0, 0, 0),  # Black text
                    "message_sent": QColor(0, 0, 0),  # Black text
                    "message_received": QColor(0, 0, 0),  # Black text
                    "crypto_settings_changed": QColor(0, 0, 0),  # Black text
                    "initialization": QColor(0, 0, 0)  # Black text
                }
            
            # Determine color based on event type
            bg_color = color_schemes.get("default")
            fg_color = text_colors.get("default")
            
            if event["type"] == "key_exchange":
                bg_color = color_schemes.get("key_exchange")
                fg_color = text_colors.get("key_exchange")
            elif event["type"] in ["message_sent", "message_received"]:
                bg_color = color_schemes.get("message_sent")
                fg_color = text_colors.get("message_sent")
            elif event["type"] == "crypto_settings_changed":
                bg_color = color_schemes.get("crypto_settings_changed")
                fg_color = text_colors.get("crypto_settings_changed")
            elif event["type"] == "initialization":
                bg_color = color_schemes.get("initialization")
                fg_color = text_colors.get("initialization")
            
            # Apply colors to all cells in the row
            for col in range(5):
                if self.logs_table.item(row, col):
                    self.logs_table.item(row, col).setBackground(bg_color)
                    self.logs_table.item(row, col).setForeground(fg_color)
    
    def _apply_filter(self):
        """Apply the current filter settings and refresh logs."""
        self._refresh_logs()
    
    def _confirm_clear_logs(self):
        """Show a confirmation dialog and clear logs if confirmed."""
        from PyQt5.QtWidgets import QMessageBox
        
        reply = QMessageBox.question(
            self,
            "Clear All Logs",
            "Are you sure you want to clear all logs? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.secure_logger.clear_logs()
            self._refresh_logs()
            QMessageBox.information(self, "Logs Cleared", "All logs have been cleared.")
