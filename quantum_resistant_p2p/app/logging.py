"""
Secure logging for cryptographic operations.
"""

import json
import os
import time
import logging
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..crypto.symmetric import AES256GCM

logger = logging.getLogger(__name__)


class SecureLogger:
    """Secure logging for cryptographic operations.
    
    This class provides functionality to securely log cryptographic operations,
    including key exchanges, message transfers, and security-related events.
    """
    
    def __init__(self, log_path: Optional[str] = None):
        """Initialize a new secure logger.
        
        Args:
            log_path: Path to the log directory. If None, uses
                     ~/.quantum_resistant_p2p/logs/
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
        
        # Encryption key for log entries
        self.encryption_key = self._load_or_generate_key()
        
        logger.info(f"Secure logger initialized at {self.log_path}")
    
    def _load_or_generate_key(self) -> bytes:
        """Load the encryption key or generate a new one.
        
        Returns:
            The encryption key
        """
        key_path = self.log_path.parent / "log_encryption_key"
        key_path.parent.mkdir(exist_ok=True, parents=True)
        
        if key_path.exists():
            # Load existing key
            with open(key_path, "rb") as f:
                key = f.read()
            logger.debug("Loaded existing log encryption key")
        else:
            # Generate a new key
            cipher = AES256GCM()
            key = cipher.generate_key()
            
            # Save the key
            with open(key_path, "wb") as f:
                f.write(key)
            
            logger.debug("Generated new log encryption key")
        
        return key
    
    def log_event(self, event_type: str, **kwargs) -> None:
        """Log a security-related event.
        
        Args:
            event_type: The type of event
            **kwargs: Additional event data
        """
        # Create the log entry
        entry = {
            "timestamp": time.time(),
            "type": event_type,
            **kwargs
        }
        
        # Get the current date for the log file name
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = self.log_path / f"{date_str}.log"
        
        # Encrypt the log entry
        cipher = AES256GCM()
        entry_json = json.dumps(entry).encode()
        encrypted_entry = cipher.encrypt(self.encryption_key, entry_json)
        
        # Write to the log file
        with open(log_file, "ab") as f:
            # Write length of encrypted entry followed by the entry
            length = len(encrypted_entry).to_bytes(4, byteorder="big")
            f.write(length)
            f.write(encrypted_entry)
        
        logger.debug(f"Logged {event_type} event")
    
    def get_events(self, start_time: Optional[float] = None, 
                end_time: Optional[float] = None,
                event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get events from the log.
        
        Args:
            start_time: Only include events after this timestamp
            end_time: Only include events before this timestamp
            event_type: Only include events of this type
            
        Returns:
            List of log entries
        """
        events = []
        
        # Get all log files
        log_files = sorted(self.log_path.glob("*.log"))
        
        # Determine date range if timestamps are provided
        if start_time is not None:
            start_date = datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d")
            log_files = [f for f in log_files if f.name >= f"{start_date}.log"]
        
        if end_time is not None:
            end_date = datetime.datetime.fromtimestamp(end_time).strftime("%Y-%m-%d")
            log_files = [f for f in log_files if f.name <= f"{end_date}.log"]
        
        cipher = AES256GCM()
        
        # Read and decrypt each log file
        for log_file in log_files:
            try:
                with open(log_file, "rb") as f:
                    while True:
                        # Read length of encrypted entry
                        length_bytes = f.read(4)
                        if not length_bytes:
                            break
                        
                        length = int.from_bytes(length_bytes, byteorder="big")
                        encrypted_entry = f.read(length)
                        
                        # Decrypt the entry
                        try:
                            entry_json = cipher.decrypt(self.encryption_key, encrypted_entry)
                            entry = json.loads(entry_json.decode())
                            
                            # Filter by timestamp and event type
                            if start_time is not None and entry["timestamp"] < start_time:
                                continue
                            if end_time is not None and entry["timestamp"] > end_time:
                                continue
                            if event_type is not None and entry["type"] != event_type:
                                continue
                            
                            events.append(entry)
                            
                        except Exception as e:
                            logger.error(f"Failed to decrypt log entry: {e}")
                            continue
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")
        
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
        events = self.get_events(start_time, end_time)
        
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
        # Get all events
        events = self.get_events()
        
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
        for log_file in self.log_path.glob("*.log"):
            try:
                os.remove(log_file)
                logger.debug(f"Removed log file {log_file}")
            except Exception as e:
                logger.error(f"Failed to remove log file {log_file}: {e}")
        
        logger.info("Cleared all logs")
