"""
Dialog for viewing key exchange history with true on-demand key decryption.
"""

import logging
import datetime
import base64
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QMenu, QAction, QTextEdit, QSplitter, QWidget, QApplication,
    QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QColor, QFont, QCursor

from ..crypto import KeyStorage

logger = logging.getLogger(__name__)


class KeyHistoryDialog(QDialog):
    """Dialog for viewing the history of key exchanges with true on-demand key decryption."""
    
    def __init__(self, key_storage: KeyStorage, secure_logger=None, parent=None):
        """Initialize the key history dialog."""
        super().__init__(parent)

        self.key_storage = key_storage
        self.secure_logger = secure_logger
        self.current_key_id = None      # Store key_id instead of decrypted key
        self.current_key = None         # Only set when explicitly decrypted
        self.decrypted_keys = set()     # Track which keys have been decrypted in this session

        self.setWindowTitle("Key Exchange History")
        self.setMinimumSize(900, 600)

        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("History of Key Exchanges")
        header_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header_label)
        
        # Description
        description = QLabel(
            "This dialog shows the history of key exchanges with peers. "
            "These keys are stored for reference but are not automatically reused."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Create a splitter for the table and key details
        splitter = QSplitter(Qt.Vertical)
        
        # Top part: Key history table
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Peer ID", "Exchange Time", "Key Exchange Algorithm", 
            "Symmetric Algorithm", "Key ID", "Key Preview"
        ])
        
        # Set stretch factors for columns
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Peer ID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Exchange Time
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Key Exchange Algo
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Symmetric Algo
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Key ID
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Key Preview
        
        # Connect selection change
        self.history_table.itemSelectionChanged.connect(self._selection_changed)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._show_context_menu)
        
        table_layout.addWidget(self.history_table)
        splitter.addWidget(table_widget)
        
        # Bottom part: Key details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        details_header = QLabel("Key Details")
        details_header.setStyleSheet("font-weight: bold;")
        details_layout.addWidget(details_header)
        
        # Add initial message
        self.key_details = QTextEdit()
        self.key_details.setReadOnly(True)
        self.key_details.setFont(QFont("Courier New", 10))
        self.key_details.setMinimumHeight(150)
        self.key_details.setPlainText("Select a key and click 'Decrypt & View Key' to view the decrypted key material.")
        details_layout.addWidget(self.key_details)
        
        # Add security controls
        security_layout = QHBoxLayout()
        
        # Add decrypt/hide button
        self.decrypt_button = QPushButton("Decrypt && View Key")
        self.decrypt_button.clicked.connect(self._toggle_key_visibility)
        self.decrypt_button.setEnabled(False)  # Initially disabled
        security_layout.addWidget(self.decrypt_button)
        
        # Add format controls
        format_layout = QHBoxLayout()
        
        # Create a button group to ensure mutual exclusivity
        self.format_group = QButtonGroup(self)
        
        # Create radio buttons
        self.show_hex_radio = QRadioButton("Show as Hex")
        self.show_hex_radio.setChecked(True)  # Default selection
        self.show_hex_radio.toggled.connect(self._update_key_display)
        format_layout.addWidget(self.show_hex_radio)
        self.format_group.addButton(self.show_hex_radio)
        
        self.show_base64_radio = QRadioButton("Show as Base64")
        self.show_base64_radio.toggled.connect(self._update_key_display)
        format_layout.addWidget(self.show_base64_radio)
        self.format_group.addButton(self.show_base64_radio)
        
        self.show_decimal_radio = QRadioButton("Show Decimal Values")
        self.show_decimal_radio.toggled.connect(self._update_key_display)
        format_layout.addWidget(self.show_decimal_radio)
        self.format_group.addButton(self.show_decimal_radio)
        
        # Initially disable format buttons
        self.show_hex_radio.setEnabled(False)
        self.show_base64_radio.setEnabled(False)
        self.show_decimal_radio.setEnabled(False)
        
        security_layout.addLayout(format_layout)
        
        # Add copy button
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self._copy_key_to_clipboard)
        self.copy_button.setEnabled(False)  # Initially disabled
        security_layout.addWidget(self.copy_button)
        
        details_layout.addLayout(security_layout)
        
        splitter.addWidget(details_widget)
        
        # Set initial splitter sizes (70% table, 30% details)
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._refresh_history)
        button_layout.addWidget(self.refresh_button)
        
        self.delete_selected_button = QPushButton("Delete Selected")
        self.delete_selected_button.clicked.connect(self._delete_selected)
        button_layout.addWidget(self.delete_selected_button)
        
        self.clear_all_button = QPushButton("Clear All History")
        self.clear_all_button.setStyleSheet("color: red;")
        self.clear_all_button.clicked.connect(self._clear_all_history)
        button_layout.addWidget(self.clear_all_button)
        
        button_layout.addStretch()
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Store key data for each row (without the decrypted keys)
        self.row_key_data = {}
        
        # Load initial data
        self._refresh_history()
    
    def _refresh_history(self):
        """Refresh the key history table."""
        self.history_table.setRowCount(0)  # Clear current rows
        self.row_key_data = {}  # Clear key data
        
        # Get key history WITHOUT decrypting keys
        key_history = self.key_storage.get_key_history(decrypt_keys=False)
        
        # Populate table
        for i, entry in enumerate(key_history):
            self.history_table.insertRow(i)
            
            # Store the key metadata for this row (without decrypted key)
            self.row_key_data[i] = entry
            
            # Peer ID (shortened)
            peer_id = entry.get("peer_id", "Unknown")
            peer_item = QTableWidgetItem(f"{peer_id[:12]}...")
            peer_item.setToolTip(peer_id)
            self.history_table.setItem(i, 0, peer_item)
            
            # Exchange Time
            timestamp = entry.get("created_at", 0)
            time_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            time_item = QTableWidgetItem(time_str)
            self.history_table.setItem(i, 1, time_item)
            
            # Key Exchange Algorithm
            algo_item = QTableWidgetItem(entry.get("algorithm", "Unknown"))
            self.history_table.setItem(i, 2, algo_item)
            
            # Symmetric Algorithm
            sym_algo_item = QTableWidgetItem(entry.get("symmetric_algorithm", "Unknown"))
            self.history_table.setItem(i, 3, sym_algo_item)
            
            # Key ID (shortened)
            key_id = entry.get("key_id", "Unknown")
            key_id_item = QTableWidgetItem(f"{key_id[:20]}...")
            key_id_item.setToolTip(key_id)
            key_id_item.setData(Qt.UserRole, key_id)  # Store full key ID for deletion
            self.history_table.setItem(i, 4, key_id_item)
            
            # Key Preview
            preview_item = QTableWidgetItem("(encrypted)")
            preview_item.setFont(QFont("Courier New"))
            self.history_table.setItem(i, 5, preview_item)
            
            # Apply alternating row colors
            if i % 2 == 0:
                for col in range(6):
                    self.history_table.item(i, col).setBackground(QColor(240, 240, 255))
    
    def _selection_changed(self):
        """Handle selection change in the history table."""
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            self.key_details.setPlainText("Select a key and click 'Decrypt & View Key' to view the decrypted key material.")
            self.current_key_id = None
            self.current_key = None
            self.decrypt_button.setEnabled(False)
            return

        # Get the row and ensure we're using the first column's data for consistent behavior
        row = selected_items[0].row()

        # Get the metadata for this row
        key_data = self.row_key_data.get(row)
        if not key_data:
            self.key_details.setPlainText("Select a key and click 'Decrypt & View Key' to view the decrypted key material.")
            self.current_key_id = None
            self.current_key = None
            self.decrypt_button.setEnabled(False)
            return

        # Store the key ID
        new_key_id = key_data.get("key_id")

        # Check if this is a different key than before
        if new_key_id != self.current_key_id:
            # It's a new key, clear any previous key data
            self.current_key = None
            self.current_key_id = new_key_id

            # Reset the view - don't decrypt the key automatically
            self.key_details.setPlainText(
                f"Key selected: {self.current_key_id}\n"
                f"Peer: {key_data.get('peer_id')}\n"
                f"Algorithm: {key_data.get('algorithm')}\n"
                f"Created: {datetime.datetime.fromtimestamp(key_data.get('created_at', 0)).strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Click 'Decrypt & View Key' to decrypt and view the key material."
            )

            # Check if this key was previously decrypted in this session
            if new_key_id in self.decrypted_keys:
                # It was decrypted before, so we need to decrypt it again
                self._decrypt_and_show_key()
            else:
                # Set up for initial decryption
                self.decrypt_button.setText("Decrypt && View Key")
                self.decrypt_button.setEnabled(True)

                # Disable format options and copy button until key is decrypted
                self.show_hex_radio.setEnabled(False)
                self.show_base64_radio.setEnabled(False)
                self.show_decimal_radio.setEnabled(False)
                self.copy_button.setEnabled(False)
    
    def _toggle_key_visibility(self):
        """Toggle between decrypting/viewing and hiding the key."""
        if self.decrypt_button.text() == "Decrypt && View Key":
            # User wants to decrypt and show the key - display a warning
            reply = QMessageBox.warning(
                self,
                "Security Warning",
                "You are about to decrypt and view sensitive key material. This could be a security risk if:\n\n"
                "• Your screen is visible to others\n"
                "• Your system has screen capture malware\n"
                "• You copy the key to clipboard with clipboard monitoring tools present\n\n"
                "The decrypted key will remain in memory only until you hide it or close this dialog.\n\n"
                "Are you sure you want to decrypt and view this key?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                # Decrypt and show the key
                self._decrypt_and_show_key()
        else:
            # Hide the key and clear it from memory
            self.key_details.setPlainText(
                f"Key ID: {self.current_key_id}\n"
                "Key hidden and cleared from memory. Click 'Decrypt & View Key' to view again."
            )
            self.decrypt_button.setText("Decrypt && View Key")

            # Log key clearing
            if self.secure_logger and self.current_key_id:
                # Get associated peer ID for logging
                peer_id = None
                for row, data in self.row_key_data.items():
                    if data.get("key_id") == self.current_key_id:
                        peer_id = data.get("peer_id")
                        break

                self.secure_logger.log_event(
                    event_type="key_history_access",
                    message=f"Key hidden and cleared from memory: {self.current_key_id}",
                    key_id=self.current_key_id,
                    peer_id=peer_id,
                    action="hide_clear"
                )

            # Remove from decrypted keys list
            if self.current_key_id in self.decrypted_keys:
                self.decrypted_keys.remove(self.current_key_id)

            # Clear the decrypted key from memory
            self.current_key = None

            # Disable format options and copy button
            self.show_hex_radio.setEnabled(False)
            self.show_base64_radio.setEnabled(False)
            self.show_decimal_radio.setEnabled(False)
            self.copy_button.setEnabled(False)
    
    def _decrypt_and_show_key(self):
        """Decrypt the key and display it."""
        if not self.current_key_id:
            return

        # Get associated peer ID for logging
        peer_id = None
        for row, data in self.row_key_data.items():
            if data.get("key_id") == self.current_key_id:
                peer_id = data.get("peer_id")
                break
            
        # Actually decrypt the key from storage
        decrypted_key = self.key_storage.decrypt_key(self.current_key_id)

        if not decrypted_key:
            self.key_details.setPlainText("Failed to decrypt key. The key may be corrupted or missing.")

            # Log failed decryption attempt
            if self.secure_logger:
                self.secure_logger.log_event(
                    event_type="key_history_error",
                    message=f"Failed to decrypt key {self.current_key_id}",
                    key_id=self.current_key_id,
                    peer_id=peer_id
                )
            return

        # Store the decrypted key and show it
        self.current_key = decrypted_key
        self.decrypt_button.setText("Hide && Clear Key")

        # Add to the set of decrypted keys
        self.decrypted_keys.add(self.current_key_id)

        # Log successful decryption
        if self.secure_logger:
            self.secure_logger.log_event(
                event_type="key_history_access",
                message=f"Key decrypted and viewed: {self.current_key_id}",
                key_id=self.current_key_id,
                peer_id=peer_id,
                action="decrypt_view"
            )

        # Enable format options and copy button
        self.show_hex_radio.setEnabled(True)
        self.show_base64_radio.setEnabled(True)
        self.show_decimal_radio.setEnabled(True)
        self.copy_button.setEnabled(True)

        # Update the display with the decrypted key
        self._update_key_display()
    
    def _update_key_display(self):
        """Update the key details display based on selected format."""
        if not self.current_key:
            return
        
        # Determine display format based on which radio button is checked
        if self.show_hex_radio.isChecked():
            # Show as hex
            if isinstance(self.current_key, bytes):
                hex_str = self.current_key.hex()
                # Format with spaces for readability
                formatted_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                self.key_details.setPlainText(f"Key (Hex Format):\n{formatted_hex}")
            else:
                self.key_details.setPlainText(f"Key (not in bytes format):\n{self.current_key}")
                
        elif self.show_base64_radio.isChecked():
            # Show as base64
            if isinstance(self.current_key, bytes):
                b64_str = base64.b64encode(self.current_key).decode('utf-8')
                self.key_details.setPlainText(f"Key (Base64 Format):\n{b64_str}")
            else:
                self.key_details.setPlainText(f"Key (not in bytes format):\n{self.current_key}")
                
        elif self.show_decimal_radio.isChecked():
            # Show as decimal values (0-255)
            if isinstance(self.current_key, bytes):
                # Convert each byte to its decimal value
                decimal_values = [str(b) for b in self.current_key]
                
                # Format with 8 values per line for readability
                lines = []
                for i in range(0, len(decimal_values), 8):
                    line = ' '.join(decimal_values[i:i+8])
                    lines.append(line)
                
                formatted_decimal = '\n'.join(lines)
                self.key_details.setPlainText(f"Key (Decimal Values):\n{formatted_decimal}")
            else:
                self.key_details.setPlainText(f"Key (not in bytes format):\n{self.current_key}")
    
    def _copy_key_to_clipboard(self):
        """Copy the currently displayed key to clipboard."""
        if not self.current_key:
            return
        
        # Get the text from the key details display
        key_text = self.key_details.toPlainText()
        
        # Extract just the key part (after the first line)
        lines = key_text.strip().split('\n')
        if len(lines) > 1:
            key_to_copy = '\n'.join(lines[1:])
        else:
            key_to_copy = key_text
            
        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(key_to_copy)
        
        # Show confirmation
        QMessageBox.information(self, "Copied", "Key copied to clipboard.")
    
    def _show_context_menu(self, position):
        """Show context menu for the history table."""
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return
            
        # Create context menu
        context_menu = QMenu(self)
        
        # Add actions
        decrypt_action = QAction("Decrypt && View Key", self)
        decrypt_action.triggered.connect(lambda: self._toggle_key_visibility())
        context_menu.addAction(decrypt_action)
        
        delete_action = QAction("Delete Selected Key", self)
        delete_action.triggered.connect(self._delete_selected)
        context_menu.addAction(delete_action)
        
        # Show the menu
        context_menu.exec_(QCursor.pos())
    
    def _delete_selected(self):
        """Delete the selected key from history."""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a key entry to delete.")
            return
        
        # Get the key ID from the selected row
        row = selected_rows[0].row()
        key_id_item = self.history_table.item(row, 4)
        key_id = key_id_item.data(Qt.UserRole)
        
        # Get peer ID for logging
        peer_id = None
        if row in self.row_key_data:
            peer_id = self.row_key_data[row].get("peer_id")
        
        # Confirm deletion
        reply = QMessageBox.question(
            self, 
            "Confirm Deletion",
            f"Are you sure you want to delete this key entry?\n\nKey ID: {key_id}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Delete the key
            success = self.key_storage.delete_key(key_id)
            
            if success:
                # Log successful deletion
                if self.secure_logger:
                    self.secure_logger.log_event(
                        event_type="key_history_changed",
                        message=f"Key deleted from history: {key_id}",
                        key_id=key_id,
                        peer_id=peer_id,
                        action="delete"
                    )
                    
                QMessageBox.information(self, "Success", "Key entry deleted successfully.")
                self._refresh_history()
            else:
                # Log failed deletion
                if self.secure_logger:
                    self.secure_logger.log_event(
                        event_type="key_history_error",
                        message=f"Failed to delete key: {key_id}",
                        key_id=key_id,
                        peer_id=peer_id,
                        action="delete_failed"
                    )
                    
                QMessageBox.warning(self, "Error", "Failed to delete key entry.")
    
    def _clear_all_history(self):
        """Clear all key history."""
        # Get current key history
        key_history = self.key_storage.get_key_history(decrypt_keys=False)
        
        if not key_history:
            QMessageBox.information(self, "No History", "There is no key history to clear.")
            return
        
        # Confirm deletion
        reply = QMessageBox.question(
            self, 
            "Confirm Clear All",
            f"Are you sure you want to delete ALL key history?\n\nThis will remove {len(key_history)} entries and cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Log beginning of clear all operation
            if self.secure_logger:
                self.secure_logger.log_event(
                    event_type="key_history_changed",
                    message=f"Clearing all key history ({len(key_history)} entries)",
                    action="clear_all_begin"
                )
                
            # Delete all key history entries
            success = True
            deleted_count = 0
            for entry in key_history:
                key_id = entry.get("key_id")
                if key_id:
                    if self.key_storage.delete_key(key_id):
                        deleted_count += 1
                    else:
                        success = False
            
            # Log result
            if self.secure_logger:
                self.secure_logger.log_event(
                    event_type="key_history_changed",
                    message=f"Cleared key history: {deleted_count} of {len(key_history)} entries deleted",
                    action="clear_all_complete",
                    success=success
                )
            
            if success:
                QMessageBox.information(self, "Success", "All key history cleared successfully.")
                self._refresh_history()
            else:
                QMessageBox.warning(self, "Partial Success", f"{deleted_count} of {len(key_history)} key entries were deleted. Some entries could not be deleted.")
                self._refresh_history()
    
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Clear any decrypted keys from memory for security
        self.current_key = None
        self.key_details.clear()
        self.decrypted_keys.clear()  # Clear the tracked decrypted keys

        # Accept the close event
        super().closeEvent(event)