"""
Diagnostic tool for testing and fixing secure logging issues.
"""

import logging
import json
import os
import time
from pathlib import Path
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QGroupBox, QFormLayout, QApplication
)
from PyQt5.QtCore import Qt, QTimer

from ..app import SecureLogger
from ..crypto.symmetric import AES256GCM

logger = logging.getLogger(__name__)


class LogDiagnosticsDialog(QDialog):
    """Dialog for diagnosing and fixing secure logging issues."""
    
    def __init__(self, secure_logger, parent=None):
        """Initialize the log diagnostics dialog.
        
        Args:
            secure_logger: The secure logger instance
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.secure_logger = secure_logger
        
        self.setWindowTitle("Log Diagnostics")
        self.setMinimumSize(700, 600)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Status section
        status_group = QGroupBox("Log System Status")
        status_layout = QFormLayout()
        
        # Display basic info
        self.log_path_label = QLabel(str(self.secure_logger.log_path))
        status_layout.addRow("Log Path:", self.log_path_label)
        
        # Check key file
        key_path = self.secure_logger.log_path.parent / "log_encryption_key"
        key_exists = key_path.exists()
        self.key_status_label = QLabel(
            f"{'Exists' if key_exists else 'Missing'} ({key_path})"
        )
        status_layout.addRow("Encryption Key File:", self.key_status_label)
        
        # Check log files
        log_files = list(self.secure_logger.log_path.glob("*.log"))
        self.log_files_label = QLabel(f"{len(log_files)} log files found")
        status_layout.addRow("Log Files:", self.log_files_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Diagnostic tests
        test_group = QGroupBox("Diagnostic Tests")
        test_layout = QVBoxLayout()
        
        # Log write test
        write_layout = QHBoxLayout()
        self.write_test_btn = QPushButton("Test Log Write")
        self.write_test_btn.clicked.connect(self._test_log_write)
        write_layout.addWidget(self.write_test_btn)
        self.write_status_label = QLabel("Not tested")
        write_layout.addWidget(self.write_status_label, 1)  # Stretch factor 1
        test_layout.addLayout(write_layout)
        
        # Log read test
        read_layout = QHBoxLayout()
        self.read_test_btn = QPushButton("Test Log Read")
        self.read_test_btn.clicked.connect(self._test_log_read)
        read_layout.addWidget(self.read_test_btn)
        self.read_status_label = QLabel("Not tested")
        read_layout.addWidget(self.read_status_label, 1)  # Stretch factor 1
        test_layout.addLayout(read_layout)
        
        # Write and read test
        cycle_layout = QHBoxLayout()
        self.cycle_test_btn = QPushButton("Test Write & Read Cycle")
        self.cycle_test_btn.clicked.connect(self._test_write_read_cycle)
        cycle_layout.addWidget(self.cycle_test_btn)
        self.cycle_status_label = QLabel("Not tested")
        cycle_layout.addWidget(self.cycle_status_label, 1)  # Stretch factor 1
        test_layout.addLayout(cycle_layout)
        
        test_group.setLayout(test_layout)
        layout.addWidget(test_group)
        
        # Detailed analysis
        analysis_group = QGroupBox("Detailed Analysis")
        analysis_layout = QVBoxLayout()
        
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        analysis_layout.addWidget(self.analysis_text)
        
        self.analyze_btn = QPushButton("Run Full Diagnostic Analysis")
        self.analyze_btn.clicked.connect(self._run_analysis)
        analysis_layout.addWidget(self.analyze_btn)
        
        analysis_group.setLayout(analysis_layout)
        layout.addWidget(analysis_group)
        
        # Debug options
        debug_group = QGroupBox("Advanced Debug Options")
        debug_layout = QVBoxLayout()
        
        debug_button_layout = QHBoxLayout()
        
        self.fix_key_btn = QPushButton("Regenerate Encryption Key")
        self.fix_key_btn.setStyleSheet("color: red;")
        self.fix_key_btn.clicked.connect(self._regenerate_key)
        debug_button_layout.addWidget(self.fix_key_btn)
        
        self.inspect_logs_btn = QPushButton("Inspect Raw Log Files")
        self.inspect_logs_btn.clicked.connect(self._inspect_raw_logs)
        debug_button_layout.addWidget(self.inspect_logs_btn)
        
        debug_layout.addLayout(debug_button_layout)
        
        debug_group.setLayout(debug_layout)
        layout.addWidget(debug_group)
        
        # Close button
        button_layout = QHBoxLayout()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _test_log_write(self):
        """Test writing a log entry."""
        try:
            # Create a test event
            test_id = f"test_{int(time.time())}"
            self.secure_logger.log_event(
                event_type="diagnostic_test",
                test_id=test_id,
                timestamp=time.time()
            )
            
            # Store test ID for later verification
            self.last_test_id = test_id
            
            self.write_status_label.setText("✓ Test log entry written successfully")
            self.write_status_label.setStyleSheet("color: green;")
            
            # Add to analysis
            self.analysis_text.append(f"Test log entry written with ID: {test_id}")
            
        except Exception as e:
            error_msg = f"Error writing test log entry: {str(e)}"
            self.write_status_label.setText(f"✗ {error_msg}")
            self.write_status_label.setStyleSheet("color: red;")
            self.analysis_text.append(error_msg)
            logger.error(error_msg, exc_info=True)
    
    def _test_log_read(self):
        """Test reading log entries."""
        try:
            # Get the most recent events
            events = self.secure_logger.get_events()
            
            if not events:
                self.read_status_label.setText("✗ No log entries could be read")
                self.read_status_label.setStyleSheet("color: red;")
                self.analysis_text.append("No log entries could be read.")
                return
            
            # Success!
            self.read_status_label.setText(f"✓ Read {len(events)} log entries successfully")
            self.read_status_label.setStyleSheet("color: green;")
            
            # Show sample of last entry
            last_entry = events[-1]
            entry_type = last_entry.get("type", "unknown")
            timestamp = last_entry.get("timestamp", 0)
            
            # Add to analysis
            self.analysis_text.append(f"Read {len(events)} log entries.")
            self.analysis_text.append(f"Last entry: Type={entry_type}, Timestamp={timestamp}")
            
        except Exception as e:
            error_msg = f"Error reading log entries: {str(e)}"
            self.read_status_label.setText(f"✗ {error_msg}")
            self.read_status_label.setStyleSheet("color: red;")
            self.analysis_text.append(error_msg)
            logger.error(error_msg, exc_info=True)
    
    def _test_write_read_cycle(self):
        """Test writing and then reading back a log entry."""
        try:
            # First, write a test entry
            test_id = f"cycle_test_{int(time.time())}"
            test_data = f"test_data_{test_id}"
            
            self.analysis_text.append(f"Writing test entry with ID: {test_id}")
            self.secure_logger.log_event(
                event_type="cycle_test",
                test_id=test_id,
                test_data=test_data,
                timestamp=time.time()
            )
            
            # Allow some time for file operations
            QApplication.processEvents()
            
            # Now try to read it back
            self.analysis_text.append("Attempting to read back the test entry...")
            events = self.secure_logger.get_events()
            
            # Look for our test entry
            found = False
            for event in events:
                if (event.get("type") == "cycle_test" and 
                    event.get("test_id") == test_id):
                    found = True
                    self.analysis_text.append("✓ Found the test entry in the logs!")
                    
                    # Verify the data
                    if event.get("test_data") == test_data:
                        self.analysis_text.append("✓ Test data matched correctly")
                    else:
                        self.analysis_text.append(f"✗ Data mismatch: {event.get('test_data')} != {test_data}")
                    
                    break
            
            if found:
                self.cycle_status_label.setText("✓ Write/read cycle completed successfully")
                self.cycle_status_label.setStyleSheet("color: green;")
            else:
                self.cycle_status_label.setText("✗ Could not find test entry after writing")
                self.cycle_status_label.setStyleSheet("color: red;")
                self.analysis_text.append("The test entry was not found in the logs after writing.")
                
        except Exception as e:
            error_msg = f"Error in write/read cycle test: {str(e)}"
            self.cycle_status_label.setText(f"✗ {error_msg}")
            self.cycle_status_label.setStyleSheet("color: red;")
            self.analysis_text.append(error_msg)
            logger.error(error_msg, exc_info=True)
    
    def _run_analysis(self):
        """Run a comprehensive analysis of the logging system."""
        self.analysis_text.clear()
        self.analysis_text.append("=== Starting Comprehensive Log System Analysis ===\n")
        
        # Check the encryption key
        key_path = self.secure_logger.log_path.parent / "log_encryption_key"
        if key_path.exists():
            self.analysis_text.append(f"✓ Encryption key exists at: {key_path}")
            
            # Check key permissions
            try:
                key_stat = os.stat(key_path)
                self.analysis_text.append(f"  Key file size: {key_stat.st_size} bytes")
                self.analysis_text.append(f"  Key file permissions: {oct(key_stat.st_mode)}")
            except Exception as e:
                self.analysis_text.append(f"  Error checking key file: {e}")
        else:
            self.analysis_text.append(f"✗ Encryption key missing from: {key_path}")
        
        # Check log directory
        self.analysis_text.append(f"\nLog directory: {self.secure_logger.log_path}")
        try:
            if self.secure_logger.log_path.exists():
                self.analysis_text.append(f"✓ Log directory exists")
                
                # Check log files
                log_files = list(self.secure_logger.log_path.glob("*.log"))
                self.analysis_text.append(f"  Found {len(log_files)} log files:")
                
                for log_file in log_files:
                    file_stat = os.stat(log_file)
                    self.analysis_text.append(f"  - {log_file.name}: {file_stat.st_size} bytes")
            else:
                self.analysis_text.append(f"✗ Log directory does not exist")
        except Exception as e:
            self.analysis_text.append(f"Error checking log directory: {e}")
        
        # Test encryption/decryption directly
        self.analysis_text.append("\n=== Testing Encryption/Decryption Directly ===")
        try:
            # Get the encryption key
            encryption_key = self.secure_logger.encryption_key
            self.analysis_text.append(f"Encryption key loaded, length: {len(encryption_key)} bytes")
            
            # Create test data
            test_data = f"Test data {time.time()}".encode()
            self.analysis_text.append(f"Created test data: {test_data}")
            
            # Create cipher instance
            cipher = AES256GCM()
            self.analysis_text.append(f"Created cipher instance: {cipher.__class__.__name__}")
            
            # Encrypt
            encrypted = cipher.encrypt(encryption_key, test_data)
            self.analysis_text.append(f"Encrypted test data, length: {len(encrypted)} bytes")
            
            # Decrypt
            decrypted = cipher.decrypt(encryption_key, encrypted)
            self.analysis_text.append(f"Decrypted test data: {decrypted}")
            
            # Verify
            if decrypted == test_data:
                self.analysis_text.append("✓ Direct encryption/decryption successful!")
            else:
                self.analysis_text.append("✗ Direct encryption/decryption failed - data mismatch")
                
        except Exception as e:
            self.analysis_text.append(f"✗ Error testing encryption: {e}")
        
        # Test the full logging cycle in memory
        self.analysis_text.append("\n=== Testing Full Log Cycle ===")
        self._test_write_read_cycle()
        
        # Done!
        self.analysis_text.append("\n=== Analysis Complete ===")
    
    def _regenerate_key(self):
        """Regenerate the encryption key."""
        from PyQt5.QtWidgets import QMessageBox
        
        reply = QMessageBox.warning(
            self,
            "Regenerate Encryption Key",
            "WARNING: This will make all existing logs unreadable!\n\n"
            "Are you sure you want to regenerate the encryption key?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Generate a new key
                key_path = self.secure_logger.log_path.parent / "log_encryption_key"
                
                # Backup the old key if it exists
                if key_path.exists():
                    backup_path = key_path.with_suffix(".key.bak")
                    with open(key_path, "rb") as src, open(backup_path, "wb") as dst:
                        dst.write(src.read())
                    self.analysis_text.append(f"Backed up old key to {backup_path}")
                
                # Generate a new key
                cipher = AES256GCM()
                new_key = cipher.generate_key()
                
                # Save the key
                with open(key_path, "wb") as f:
                    f.write(new_key)
                
                # Update the logger's key
                self.secure_logger.encryption_key = new_key
                
                self.analysis_text.append("✓ Generated new encryption key")
                
                # Show success message
                QMessageBox.information(
                    self,
                    "Key Regenerated",
                    "Encryption key has been regenerated successfully.\n\n"
                    "Note: Existing logs will no longer be readable."
                )
                
            except Exception as e:
                error_msg = f"Error regenerating key: {e}"
                self.analysis_text.append(f"✗ {error_msg}")
                logger.error(error_msg, exc_info=True)
                
                # Show error message
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to regenerate encryption key: {str(e)}"
                )
    
    def _inspect_raw_logs(self):
        """Inspect raw log files."""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QComboBox, QLabel, QHBoxLayout
        
        class RawLogInspectorDialog(QDialog):
            def __init__(self, log_path, parent=None):
                super().__init__(parent)
                self.log_path = log_path
                self.setWindowTitle("Raw Log Inspector")
                self.setMinimumSize(800, 600)
                
                layout = QVBoxLayout()
                
                # Log file selector
                selector_layout = QHBoxLayout()
                selector_layout.addWidget(QLabel("Select log file:"))
                
                self.file_combo = QComboBox()
                log_files = list(log_path.glob("*.log"))
                for log_file in log_files:
                    self.file_combo.addItem(log_file.name, str(log_file))
                selector_layout.addWidget(self.file_combo, 1)
                
                self.load_btn = QPushButton("Load")
                self.load_btn.clicked.connect(self._load_selected_file)
                selector_layout.addWidget(self.load_btn)
                
                layout.addLayout(selector_layout)
                
                # Raw content display
                self.content_text = QTextEdit()
                self.content_text.setReadOnly(True)
                self.content_text.setFontFamily("Courier New")
                layout.addWidget(self.content_text)
                
                # Close button
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(self.accept)
                layout.addWidget(close_btn)
                
                self.setLayout(layout)
                
                # Load the first file if any
                if self.file_combo.count() > 0:
                    self._load_selected_file()
            
            def _load_selected_file(self):
                file_path = self.file_combo.currentData()
                if not file_path:
                    return
                
                try:
                    self.content_text.clear()
                    with open(file_path, "rb") as f:
                        content = f.read()
                    
                    # Display hex dump
                    self._display_hex_dump(content)
                    
                except Exception as e:
                    self.content_text.setText(f"Error loading file: {str(e)}")
            
            def _display_hex_dump(self, data):
                """Display a hex dump of the data."""
                offset = 0
                result = []
                
                while offset < len(data):
                    # Get up to 16 bytes
                    chunk = data[offset:offset + 16]
                    
                    # Format as hex
                    hex_vals = " ".join(f"{b:02x}" for b in chunk)
                    
                    # Pad hex values
                    hex_vals = hex_vals.ljust(16 * 3 - 1)
                    
                    # Format as ASCII
                    ascii_vals = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    
                    # Combine
                    result.append(f"{offset:08x}:  {hex_vals}  |{ascii_vals}|")
                    
                    offset += 16
                
                self.content_text.setText("\n".join(result))
        
        # Show the raw log inspector
        dialog = RawLogInspectorDialog(self.secure_logger.log_path, self)
        dialog.exec_()
