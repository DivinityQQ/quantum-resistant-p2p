"""
Secure file operations with corruption protection.

This module provides utilities for securely reading and writing files with
protection against corruption, concurrent access issues, and proper cleanup.
"""

import os
import sys
import time
import json
import tempfile
import shutil
import logging
import platform
import base64
from pathlib import Path
from typing import Any, Dict, Optional, Union, BinaryIO, TextIO, TypeVar, Generic, Callable

logger = logging.getLogger(__name__)

# Type variable for generic return types
T = TypeVar('T')

# Platform-specific file locking
WINDOWS = platform.system() == "Windows"

if WINDOWS:
    # Windows locking with msvcrt
    import msvcrt
    
    def _lock_file(file_handle: BinaryIO, exclusive: bool = True) -> bool:
        """Lock a file on Windows.
        
        Args:
            file_handle: The file handle to lock
            exclusive: Whether to use exclusive (write) or shared (read) locking
            
        Returns:
            True if lock successful, False otherwise
        """
        try:
            # 0x1 = LK_UNLCK, 0x2 = LK_NBLCK, 0x4 = LK_NBRLCK
            mode = 0x2 if exclusive else 0x4
            # Lock from current position to max size
            msvcrt.locking(file_handle.fileno(), mode, 0x7FFFFFFF)
            return True
        except (IOError, PermissionError, OSError):
            # File already locked, or other error
            return False
    
    def _unlock_file(file_handle: BinaryIO) -> bool:
        """Unlock a file on Windows.
        
        Args:
            file_handle: The file handle to unlock
            
        Returns:
            True if unlock successful, False otherwise
        """
        try:
            # 0 = Unlock
            msvcrt.locking(file_handle.fileno(), 0, 0x7FFFFFFF)
            return True
        except (IOError, PermissionError, OSError):
            # File already unlocked, or other error
            return False
else:
    # Unix locking with fcntl
    try:
        import fcntl
        
        def _lock_file(file_handle: BinaryIO, exclusive: bool = True) -> bool:
            """Lock a file on Unix-like systems.
            
            Args:
                file_handle: The file handle to lock
                exclusive: Whether to use exclusive (write) or shared (read) locking
                
            Returns:
                True if lock successful, False otherwise
            """
            try:
                mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(file_handle.fileno(), mode | fcntl.LOCK_NB)
                return True
            except (IOError, PermissionError, OSError):
                # File already locked, or other error
                return False
        
        def _unlock_file(file_handle: BinaryIO) -> bool:
            """Unlock a file on Unix-like systems.
            
            Args:
                file_handle: The file handle to unlock
                
            Returns:
                True if unlock successful, False otherwise
            """
            try:
                fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)
                return True
            except (IOError, PermissionError, OSError):
                # File already unlocked, or other error
                return False
    except ImportError:
        # Fallback if fcntl is not available
        def _lock_file(file_handle: BinaryIO, exclusive: bool = True) -> bool:
            """Dummy lock function when fcntl is not available."""
            logger.warning("File locking not available - fcntl module missing")
            return True
            
        def _unlock_file(file_handle: BinaryIO) -> bool:
            """Dummy unlock function when fcntl is not available."""
            return True


class SecureFile:
    """A secure file handler with protection against corruption and concurrent access."""
    
    def __init__(self, file_path: Union[str, Path]):
        """Initialize a secure file handler.
        
        Args:
            file_path: The path to the file
        """
        self.file_path = Path(file_path)
        self.lock_path = self.file_path.with_suffix(self.file_path.suffix + '.lock')
        self.backup_path = self.file_path.with_suffix(self.file_path.suffix + '.bak')
    
    def _acquire_process_lock(self) -> bool:
        """Acquire a process-level lock using a lock file.
        
        This is a higher-level lock across processes, complementing
        the file handle locking for individual operations.
        
        Returns:
            True if lock acquired, False otherwise
        """
        try:
            # Try to create the lock file - will fail if it already exists
            with open(self.lock_path, 'x') as f:
                # Write the current process ID to the lock file
                f.write(str(os.getpid()))
                f.write('\n')
                f.write(str(time.time()))
            return True
        except FileExistsError:
            # Lock file already exists
            try:
                # Check if the lock is stale (process no longer exists or too old)
                lock_age = time.time() - self.lock_path.stat().st_mtime
                
                # If lock file is older than 1 hour, consider it stale
                if lock_age > 3600:  # 1 hour in seconds
                    logger.warning(f"Found stale lock file (age: {lock_age:.1f}s), removing")
                    self._release_process_lock()
                    # Try again
                    return self._acquire_process_lock()
                
                # Otherwise, check the process
                with open(self.lock_path, 'r') as f:
                    pid_str = f.readline().strip()
                    try:
                        pid = int(pid_str)
                        
                        # Check if the process exists
                        try:
                            if WINDOWS:
                                # On Windows, check using the tasklist command
                                import subprocess
                                output = subprocess.check_output(f'tasklist /FI "PID eq {pid}" /NH', shell=True)
                                if str(pid) not in output.decode():
                                    raise ProcessLookupError
                            else:
                                # On Unix, use os.kill with signal 0
                                os.kill(pid, 0)
                        except (ProcessLookupError, subprocess.CalledProcessError):
                            # Process doesn't exist, lock is stale
                            logger.warning(f"Found stale lock file for PID {pid}, removing")
                            self._release_process_lock()
                            # Try again
                            return self._acquire_process_lock()
                    except ValueError:
                        # Invalid PID in lock file
                        logger.warning("Found invalid lock file, removing")
                        self._release_process_lock()
                        # Try again
                        return self._acquire_process_lock()
            except Exception as e:
                logger.error(f"Error checking lock file: {e}")
            
            # Lock is valid and in use
            return False
        except Exception as e:
            logger.error(f"Error acquiring lock: {e}")
            return False
    
    def _release_process_lock(self) -> bool:
        """Release the process-level lock.
        
        Returns:
            True if lock released, False otherwise
        """
        try:
            if self.lock_path.exists():
                os.remove(self.lock_path)
            return True
        except Exception as e:
            logger.error(f"Error releasing lock: {e}")
            return False
    
    def read_json(self) -> Optional[Dict[str, Any]]:
        """Read and parse a JSON file safely.
        
        Returns:
            The parsed JSON data, or None if the file doesn't exist or is invalid
        """
        # First try the primary file
        data = self._read_json_file(self.file_path)
        
        # If primary file is corrupted but backup exists, use the backup
        if data is None and self.backup_path.exists():
            logger.warning(f"Using backup file for {self.file_path}")
            data = self._read_json_file(self.backup_path)
            
            # If backup is valid, restore it to the main file
            if data is not None:
                self.write_json(data)
        
        return data
    
    def _read_json_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Read and parse a single JSON file with locking.
        
        Args:
            file_path: The path to the JSON file
            
        Returns:
            The parsed JSON data, or None if the file doesn't exist or is invalid
        """
        if not file_path.exists():
            return None
        
        try:
            with open(file_path, 'rb') as f:
                # Try to get a shared lock for reading
                lock_acquired = _lock_file(f, exclusive=False)
                try:
                    # Read the file even if lock fails
                    file_data = f.read()
                    
                    # Detect empty file
                    if not file_data:
                        logger.warning(f"Empty file: {file_path}")
                        return None
                    
                    # Attempt to parse the JSON
                    return json.loads(file_data.decode('utf-8'))
                finally:
                    if lock_acquired:
                        _unlock_file(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return None
    
    def write_json(self, data: Dict[str, Any]) -> bool:
        """Write data to a JSON file safely with atomic updates and backups.
        
        Args:
            data: The data to write
            
        Returns:
            True if the write was successful, False otherwise
        """
        # Try to acquire the process lock
        if not self._acquire_process_lock():
            logger.error(f"Could not acquire lock for {self.file_path}")
            return False
        
        try:
            # Create parent directory if it doesn't exist
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Make a backup of the existing file if it exists
            if self.file_path.exists():
                try:
                    shutil.copy2(self.file_path, self.backup_path)
                except Exception as e:
                    logger.warning(f"Failed to create backup: {e}")
            
            # Write to a temporary file first
            with tempfile.NamedTemporaryFile(
                mode='w', delete=False, dir=self.file_path.parent
            ) as temp_file:
                # Write the JSON data
                json.dump(data, temp_file, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())  # Ensure data is written to disk
                temp_path = temp_file.name
            
            # Now atomically move the temp file to the target
            shutil.move(temp_path, self.file_path)
            
            return True
        except Exception as e:
            logger.error(f"Error writing to {self.file_path}: {e}")
            return False
        finally:
            # Always release the process lock
            self._release_process_lock()
    
    def append_bytes(self, data: bytes) -> bool:
        """Append binary data to a file with locking.
        
        Args:
            data: The binary data to append
            
        Returns:
            True if the append was successful, False otherwise
        """
        try:
            # Create parent directory if it doesn't exist
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.file_path, 'ab') as f:
                # Try to get an exclusive lock for writing
                lock_acquired = _lock_file(f, exclusive=True)
                try:
                    # Write the data
                    f.write(data)
                    f.flush()
                    return True
                finally:
                    if lock_acquired:
                        _unlock_file(f)
            
            return True
        except Exception as e:
            logger.error(f"Error appending to {self.file_path}: {e}")
            return False
    
    def read_bytes(self) -> Optional[bytes]:
        """Read binary data from a file with locking.
        
        Returns:
            The file contents as bytes, or None if the file doesn't exist or can't be read
        """
        if not self.file_path.exists():
            return None
        
        try:
            with open(self.file_path, 'rb') as f:
                # Try to get a shared lock for reading
                lock_acquired = _lock_file(f, exclusive=False)
                try:
                    # Read the file
                    return f.read()
                finally:
                    if lock_acquired:
                        _unlock_file(f)
        except Exception as e:
            logger.error(f"Error reading {self.file_path}: {e}")
            return None
    
    def with_file_lock(self, callback: Callable[[BinaryIO], T], exclusive: bool = True) -> Optional[T]:
        """Execute a callback with a file lock.
        
        Args:
            callback: The function to call with the file handle
            exclusive: Whether to use exclusive (write) or shared (read) locking
            
        Returns:
            The return value of the callback, or None if an error occurred
        """
        mode = 'ab' if exclusive else 'rb'
        
        try:
            # Create parent directory if it doesn't exist and we're writing
            if exclusive:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.file_path, mode) as f:
                # Try to get a lock
                lock_acquired = _lock_file(f, exclusive=exclusive)
                try:
                    # Call the callback with the file handle
                    return callback(f)
                finally:
                    if lock_acquired:
                        _unlock_file(f)
        except Exception as e:
            logger.error(f"Error with file lock on {self.file_path}: {e}")
            return None