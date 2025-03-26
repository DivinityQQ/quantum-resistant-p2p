"""
Secure logging for cryptographic operations using unified file protection.
"""

import json
import os
import time
import logging
import datetime
import threading
import io
import struct
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..crypto.symmetric import AES256GCM
from ..utils.secure_file import SecureFile

logger = logging.getLogger(__name__)


class SecureLogger:
    """Secure logging for cryptographic operations with improved reliability.
    
    This class provides functionality to securely log cryptographic operations
    including key exchanges, message transfers, and security-related events,
    with enhanced safeguards against file corruption.
    """
    
    def __init__(self, log_path: Optional[str] = None, encryption_key: Optional[bytes] = None):
        """Initialize a new secure logger.
        
        Args:
            log_path: Path to the log directory. If None, uses
                     ~/.quantum_resistant_p2p/logs/
            encryption_key: Optional encryption key to use. If None, will
                          attempt to load or generate a key.
        """
        if log_path is None:
            # Use default path in user's home directory
            home_dir = Path.home()
            log_dir = home_dir / ".quantum_resistant_p2p" / "logs"
            log_dir.mkdir(exist_ok=True, parents=True)
            self.log_path = log_dir
        else:
            self.log_path = Path(log_path)
            # Make sure directory exists
            self.log_path.mkdir(exist_ok=True, parents=True)
        
        # Use provided key or load/generate one
        self.encryption_key = encryption_key if encryption_key is not None else self._load_or_generate_key()
        
        # Create a single cipher instance for consistency
        self.cipher = AES256GCM()
        
        # Create a lock for thread safety
        self.lock = threading.RLock()
        
        # Compile regex for valid log filenames (YYYY-MM-DD.log)
        self.log_filename_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}\.log$')
        
        # Track if we're already inside an error handler to prevent recursion
        self._in_error_handler = False
        
        logger.info(f"Secure logger initialized at {self.log_path}")
    
    def _load_or_generate_key(self) -> bytes:
        """Load the encryption key or generate a new one.
        
        Returns:
            The encryption key
        """
        key_path = self.log_path.parent / "log_encryption_key"
        key_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Use SecureFile for reliable file operations
        key_file = SecureFile(key_path)
        
        key_data = key_file.read_bytes()
        if key_data:
            # Load existing key
            logger.debug("Loaded existing log encryption key")
            key = key_data
        else:
            # Generate a new key
            key = self.cipher.generate_key()
            
            # Save the key
            if not key_file.append_bytes(key):
                logger.error("Failed to save encryption key")
            else:
                logger.debug("Generated new log encryption key")
        
        return key
    
    def log_event(self, event_type: str, **kwargs) -> None:
        """Log a security-related event.
        
        Args:
            event_type: The type of event
            **kwargs: Additional event data
        """
        # Use a lock to ensure thread safety
        with self.lock:
            try:
                # Create the log entry
                entry = {
                    "timestamp": time.time(),
                    "type": event_type,
                    **kwargs
                }
                
                # Get the current date for the log file name
                date_str = datetime.datetime.now().strftime("%Y-%m-%d")
                log_file_path = self.log_path / f"{date_str}.log"
                
                # Create a SecureFile instance for this log file
                log_file = SecureFile(log_file_path)
                
                # Encrypt the log entry
                entry_json = json.dumps(entry).encode()
                encrypted_entry = self.cipher.encrypt(self.encryption_key, entry_json)
                
                # Create the complete record (length + encrypted data)
                length = len(encrypted_entry).to_bytes(4, byteorder="big")
                record = length + encrypted_entry
                
                # Write to the log file
                success = log_file.append_bytes(record)
                
                if success:
                    logger.debug(f"Logged {event_type} event")
                else:
                    self._safe_error(f"Failed to write {event_type} event to log")
                
            except Exception as e:
                self._safe_error(f"Failed to log event: {e}")
    
    def _safe_error(self, message: str, exc_info: bool = False) -> None:
        """Safely log an error message, avoiding recursive errors.
        
        Args:
            message: The error message
            exc_info: Whether to include exception info
        """
        # Use a flag to prevent recursive error handling
        if not self._in_error_handler:
            try:
                self._in_error_handler = True
                logger.error(message, exc_info=exc_info)
            finally:
                self._in_error_handler = False
    
    def _recover_from_corruption(self, file_data: bytes, position: int) -> tuple[bool, int]:
        """Attempt to recover from file corruption by finding the next valid entry.
        
        Args:
            file_data: The file contents
            position: The current file position
            
        Returns:
            Tuple of (success, new_position)
        """
        # Record current position
        start_pos = position
        data_len = len(file_data)
        
        # Set a limit for how far to scan for recovery
        MAX_SCAN = 1024 * 1024  # 1MB max scan
        
        # Try to find a valid entry header
        for offset in range(1, min(MAX_SCAN, data_len - start_pos - 8)):
            try:
                # Try to read 4 bytes for length at this offset
                length_bytes = file_data[start_pos + offset:start_pos + offset + 4]
                length = int.from_bytes(length_bytes, byteorder="big")
                
                # Check if length looks reasonable
                if 0 < length < 1_000_000 and start_pos + offset + 4 + length <= data_len:
                    # This might be a valid entry, try to decrypt it
                    entry_data = file_data[start_pos + offset + 4:start_pos + offset + 4 + length]
                    
                    try:
                        entry_json = self.cipher.decrypt(self.encryption_key, entry_data)
                        json.loads(entry_json.decode())
                        
                        # If we got here, we found a valid entry!
                        self._safe_error(f"Recovered from corruption at position {start_pos}, "
                                        f"valid entry found at offset +{offset}")
                        
                        # Return the start of this entry for the caller to process
                        return True, start_pos + offset
                    except Exception:
                        # Not a valid entry, continue scanning
                        pass
            except Exception:
                # Error during scan, continue
                pass
        
        # No valid entry found within scan limit
        return False, position
    
    def get_events(self, start_time: Optional[float] = None, 
                   end_time: Optional[float] = None,
                   event_type: Optional[str] = None,
                   limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get events from the log.
        
        Args:
            start_time: Only include events after this timestamp
            end_time: Only include events before this timestamp
            event_type: Only include events of this type
            limit: Maximum number of events to return
            
        Returns:
            List of log entries
        """
        events = []
        error_count = 0
        MAX_ERRORS = 5  # Stop after this many consecutive errors per file
        ENTRY_SIZE_LIMIT = 100_000  # Reasonable max size for an entry (100KB)
        
        # Get all log files that match our date pattern
        try:
            # Filter to only include correctly formatted log files (YYYY-MM-DD.log)
            log_files = []
            for file in self.log_path.glob("*.log"):
                if self.log_filename_pattern.match(file.name):
                    log_files.append(file)
            log_files.sort()  # Sort by date
        except Exception as e:
            self._safe_error(f"Error listing log files: {e}")
            return []
        
        # Determine date range if timestamps are provided
        if start_time is not None:
            start_date = datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d")
            log_files = [f for f in log_files if f.name >= f"{start_date}.log"]
        
        if end_time is not None:
            end_date = datetime.datetime.fromtimestamp(end_time).strftime("%Y-%m-%d")
            log_files = [f for f in log_files if f.name <= f"{end_date}.log"]
        
        # Process each log file
        for log_file_path in log_files:
            try:
                if not log_file_path.exists() or not log_file_path.is_file():
                    continue
                
                # Skip empty files
                if log_file_path.stat().st_size == 0:
                    continue
                
                # Use SecureFile to read the entire file at once
                log_file = SecureFile(log_file_path)
                file_data = log_file.read_bytes()
                
                if not file_data:
                    continue
                
                # Reset error count for each file
                error_count = 0
                position = 0
                
                while position < len(file_data):
                    # Check if we've reached the limit
                    if limit is not None and len(events) >= limit:
                        break
                    
                    # Try to read length of encrypted entry
                    if position + 4 > len(file_data):
                        break  # End of file
                    
                    try:
                        length = int.from_bytes(file_data[position:position + 4], byteorder="big")
                        
                        # Sanity check - make sure length is reasonable
                        if length <= 0 or length > ENTRY_SIZE_LIMIT:
                            self._safe_error(f"Invalid entry length in {log_file_path.name}: {length}")
                            
                            # Try to recover from corruption
                            success, new_position = self._recover_from_corruption(file_data, position)
                            if success:
                                # Recovery found a valid entry, continue processing
                                position = new_position
                                continue
                            else:
                                # Could not recover, skip this file
                                break
                        
                        # Ensure we have enough data
                        if position + 4 + length > len(file_data):
                            self._safe_error(f"Incomplete entry in {log_file_path.name}")
                            break
                        
                        # Read the encrypted entry
                        encrypted_entry = file_data[position + 4:position + 4 + length]
                        
                        # Reset error count on successful read
                        error_count = 0
                        
                        # Decrypt the entry
                        entry_json = self.cipher.decrypt(self.encryption_key, encrypted_entry)
                        entry = json.loads(entry_json.decode())
                        
                        # Filter by timestamp and event type
                        if start_time is not None and entry["timestamp"] < start_time:
                            position += 4 + length
                            continue
                        if end_time is not None and entry["timestamp"] > end_time:
                            position += 4 + length
                            continue
                        if event_type is not None and entry["type"] != event_type:
                            position += 4 + length
                            continue
                        
                        events.append(entry)
                        
                        # Move to next entry
                        position += 4 + length
                        
                    except Exception as e:
                        error_count += 1
                        self._safe_error(f"Failed to process log entry in {log_file_path.name} at position {position}: {e}")
                        
                        # Try to recover from corruption
                        success, new_position = self._recover_from_corruption(file_data, position)
                        if success:
                            # Recovery worked, reset error count
                            error_count = 0
                            position = new_position
                            continue
                        else:
                            # Move ahead a byte and try again
                            position += 1
                        
                        # Stop trying if we hit too many errors in a row
                        if error_count >= MAX_ERRORS:
                            self._safe_error(f"Too many consecutive errors ({MAX_ERRORS}) in {log_file_path.name}, stopping log processing")
                            break
                            
            except Exception as e:
                self._safe_error(f"Error reading log file {log_file_path}: {e}")
        
        # Sort events by timestamp
        events.sort(key=lambda e: e["timestamp"])
        
        return events
    
    def get_event_summary(self, start_time: Optional[float] = None,
                          end_time: Optional[float] = None) -> Dict[str, int]:
        """Get a summary of events by type.
        
        Args:
            start_time: Only include events after this timestamp
            end_time: Only include events before this timestamp
            
        Returns:
            Dictionary mapping event types to counts
        """
        # Get events with a reasonable limit to avoid issues with corrupted files
        events = self.get_events(start_time, end_time, limit=1000)
        
        summary = {}
        for event in events:
            event_type = event["type"]
            if event_type not in summary:
                summary[event_type] = 0
            summary[event_type] += 1
        
        return summary
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics based on the logs.
        
        Returns:
            Dictionary of security metrics
        """
        # Get events with a reasonable limit to avoid issues with corrupted files
        events = self.get_events(limit=1000)
        
        # Calculate metrics
        metrics = {
            "total_events": len(events),
            "key_exchanges": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "files_transferred": 0,
            "total_bytes_transferred": 0,
            "algorithms_used": {},
            "first_event_time": None,
            "last_event_time": None
        }
        
        for event in events:
            event_type = event["type"]
            
            # Update time range
            if metrics["first_event_time"] is None or event["timestamp"] < metrics["first_event_time"]:
                metrics["first_event_time"] = event["timestamp"]
            if metrics["last_event_time"] is None or event["timestamp"] > metrics["last_event_time"]:
                metrics["last_event_time"] = event["timestamp"]
            
            # Update event counts
            if event_type == "key_exchange":
                metrics["key_exchanges"] += 1
            elif event_type == "message_sent":
                metrics["messages_sent"] += 1
                if event.get("is_file", False):
                    metrics["files_transferred"] += 1
                metrics["total_bytes_transferred"] += event.get("size", 0)
            elif event_type == "message_received":
                metrics["messages_received"] += 1
                if event.get("is_file", False):
                    metrics["files_transferred"] += 1
                metrics["total_bytes_transferred"] += event.get("size", 0)
            
            # Track algorithms used
            for key in ["encryption_algorithm", "signature_algorithm", "algorithm"]:
                if key in event:
                    algorithm = event[key]
                    if algorithm not in metrics["algorithms_used"]:
                        metrics["algorithms_used"][algorithm] = 0
                    metrics["algorithms_used"][algorithm] += 1
        
        return metrics
    
    def clear_logs(self) -> None:
        """Clear all logs.
        
        This is a destructive operation and should be used with caution.
        """
        # Use a lock to ensure thread safety
        with self.lock:
            # Only clear files that match our date pattern
            for log_file_path in self.log_path.glob("*.log"):
                if self.log_filename_pattern.match(log_file_path.name):
                    try:
                        os.remove(log_file_path)
                        logger.debug(f"Removed log file {log_file_path}")
                    except Exception as e:
                        self._safe_error(f"Failed to remove log file {log_file_path}: {e}")
            
            logger.info("Cleared all logs")