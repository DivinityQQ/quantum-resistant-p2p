"""
Dialog for resetting the key storage password when it's forgotten.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox, QFormLayout, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QPalette

from ..crypto import KeyStorage

logger = logging.getLogger(__name__)


class ResetPasswordDialog(QDialog):
    """Dialog for resetting the key storage when the password is forgotten."""
    
    # Signal emitted when password reset is successful
    password_reset = pyqtSignal()
    
    def __init__(self, key_storage: KeyStorage, parent=None):
        """Initialize the password reset dialog.
        
        Args:
            key_storage: The key storage to reset
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.key_storage = key_storage
        
        self.setWindowTitle("Reset Password")
        self.setMinimumWidth(450)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Warning label
        warning_label = QLabel(
            "⚠️ WARNING: COMPLETE APPLICATION RESET ⚠️\n\n"
            "This action will:\n"
            "• Delete ALL stored keys and connections\n"
            "• Erase ALL secure logs and history\n"
            "• Create a brand new security profile\n\n"
            "This action CANNOT be undone. No backups will be kept."
        )
        warning_label.setAlignment(Qt.AlignCenter)
        warning_label.setWordWrap(True)
        
        # Set red text for warning
        palette = warning_label.palette()
        palette.setColor(QPalette.WindowText, QColor(200, 0, 0))
        warning_label.setPalette(palette)
        warning_label.setStyleSheet("font-weight: bold;")
        
        layout.addWidget(warning_label)
        
        # Form layout for password fields
        form_layout = QFormLayout()
        
        # New password field
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setPlaceholderText("Enter a strong password")
        form_layout.addRow("New Password:", self.new_password_input)
        
        # Confirm new password field
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm your new password")
        form_layout.addRow("Confirm Password:", self.confirm_password_input)
        
        layout.addLayout(form_layout)
        
        # Confirmation checkboxes
        self.confirm_checkbox1 = QCheckBox("I understand all my keys and connections will be permanently deleted")
        self.confirm_checkbox2 = QCheckBox("I understand all secure logs and history will be erased")
        self.confirm_checkbox3 = QCheckBox("I understand this action cannot be undone and no backups will be kept")
        
        layout.addWidget(self.confirm_checkbox1)
        layout.addWidget(self.confirm_checkbox2)
        layout.addWidget(self.confirm_checkbox3)
        
        # Password strength guidelines
        strength_label = QLabel(
            "Strong password tips:\n"
            "• At least 12 characters long\n"
            "• Mix of uppercase, lowercase, numbers, and symbols\n"
            "• Avoid easily guessable information"
        )
        strength_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(strength_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.reset_button = QPushButton("Reset Application")
        self.reset_button.clicked.connect(self._on_reset_clicked)
        self.reset_button.setEnabled(False)  # Disabled until confirmations checked
        
        # Connect checkboxes to enable/disable reset button
        self.confirm_checkbox1.stateChanged.connect(self._check_confirmations)
        self.confirm_checkbox2.stateChanged.connect(self._check_confirmations)
        self.confirm_checkbox3.stateChanged.connect(self._check_confirmations)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.reset_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect enter key to reset button
        self.new_password_input.returnPressed.connect(self._on_enter_pressed)
        self.confirm_password_input.returnPressed.connect(self._on_enter_pressed)
        
        # Set focus to new password input
        self.new_password_input.setFocus()
    
    def _check_confirmations(self):
        """Check if all confirmation checkboxes are checked and enable reset button if so."""
        all_checked = (
            self.confirm_checkbox1.isChecked() and
            self.confirm_checkbox2.isChecked() and
            self.confirm_checkbox3.isChecked()
        )
        self.reset_button.setEnabled(all_checked)
    
    def _on_enter_pressed(self):
        """Handle pressing enter in a text field."""
        if self.reset_button.isEnabled():
            self.reset_button.click()
    
    def _on_reset_clicked(self):
        """Handle clicking the reset password button."""
        # Get the passwords
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        # Validate inputs
        if not new_password:
            QMessageBox.warning(self, "Error", "Please enter a new password.")
            return
            
        if new_password != confirm_password:
            QMessageBox.warning(self, "Error", "New passwords do not match.")
            self.new_password_input.clear()
            self.confirm_password_input.clear()
            self.new_password_input.setFocus()
            return
            
        # Check password strength
        if len(new_password) < 8:
            response = QMessageBox.question(
                self,
                "Weak Password",
                "Your password is quite short. Are you sure you want to use it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if response == QMessageBox.No:
                return
        
        # Final confirmation with countdown
        response = QMessageBox.warning(
            self,
            "FINAL CONFIRMATION",
            "You are about to completely reset the application!\n\n"
            "• ALL keys and connections will be deleted\n"
            "• ALL secure logs will be erased\n"
            "• NO backups will be kept\n\n"
            "THIS CANNOT BE UNDONE.\n\n"
            "Are you absolutely sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if response == QMessageBox.No:
            return
        
        # Reset the key storage using the KeyStorage method
        try:
            # Pass create_backup=False to skip creating backups
            success = self.key_storage.reset_storage(new_password, create_backup=False)
            
            if success:
                QMessageBox.information(
                    self, "Success", 
                    "Application has been reset successfully.\n\n"
                    "• All keys and connections have been deleted\n"
                    "• All secure logs have been erased\n\n"
                    "You can now log in with your new password."
                )
                logger.info("Application reset successfully")
                self.password_reset.emit()
                self.accept()
            else:
                QMessageBox.warning(
                    self, "Error", 
                    "Failed to reset application. Please check application logs for details."
                )
                logger.error("Application reset failed")
        except Exception as e:
            QMessageBox.critical(
                self, "Error", 
                f"An error occurred while resetting the application: {str(e)}"
            )
            logger.error(f"Exception during application reset: {e}")