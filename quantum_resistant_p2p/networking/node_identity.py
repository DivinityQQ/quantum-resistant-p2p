"""
Secure node identity management with encryption support.
"""

import os
import uuid
import logging
import stat
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

def get_app_data_dir() -> Path:
    """Get the application data directory, creating it if it doesn't exist."""
    app_dir = Path.home() / ".quantum_resistant_p2p"
    app_dir.mkdir(exist_ok=True, parents=True)
    
    # Set directory permissions to be accessible only by the owner
    try:
        if os.name == 'posix':  # Unix/Linux/MacOS
            os.chmod(app_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 0o700 permissions
    except Exception as e:
        logger.warning(f"Failed to set directory permissions: {e}")
    
    return app_dir

def load_or_generate_node_id(key_storage=None, custom_id: Optional[str] = None) -> str:
    """Load an existing node ID from secure storage or generate a new persistent one.
    
    Args:
        key_storage: Optional KeyStorage instance for secure storage. If None, uses file storage.
        custom_id: Optional custom ID to use instead of generating or loading
        
    Returns:
        The node ID as a string
    """
    # If a custom ID is provided, use it and save it
    if custom_id:
        save_node_id(key_storage, custom_id)
        return custom_id
    
    # First try to load from KeyStorage if provided (encrypted storage)
    if key_storage:
        node_id_key = "system_node_id"
        node_id_data = key_storage.get_key(node_id_key)
        
        if node_id_data and "node_id" in node_id_data:
            node_id = node_id_data["node_id"]
            logger.info(f"Loaded encrypted node ID: {node_id[:8]}...")
            return node_id
    
    # If not in KeyStorage or KeyStorage not provided, try the file location
    node_id_file = get_app_data_dir() / "node_id"
    
    if node_id_file.exists():
        try:
            with open(node_id_file, "r") as f:
                node_id = f.read().strip()
                if node_id:  # Make sure it's not empty
                    logger.info(f"Loaded node ID from file: {node_id[:8]}...")
                    
                    # Migrate to secure storage if KeyStorage is available
                    if key_storage:
                        save_node_id(key_storage, node_id)
                        # Delete the file after migration
                        try:
                            os.remove(node_id_file)
                            logger.info("Deleted plaintext node ID file after migration to secure storage")
                        except Exception as e:
                            logger.warning(f"Failed to delete plaintext node ID file: {e}")
                    
                    return node_id
        except Exception as e:
            logger.error(f"Failed to load node ID from file: {e}")
    
    # Generate a new ID if no existing ID was found
    node_id = str(uuid.uuid4())
    
    # Save the new ID
    save_node_id(key_storage, node_id)
    logger.info(f"Generated new persistent node ID: {node_id[:8]}...")
    
    return node_id

def save_node_id(key_storage, node_id: str) -> bool:
    """Save a node ID to storage for persistence.
    
    Args:
        key_storage: Optional KeyStorage instance for secure storage. If None, uses file storage.
        node_id: The node ID to save
        
    Returns:
        True if saving succeeded, False otherwise
    """
    # If KeyStorage is provided, use it for encrypted storage
    if key_storage:
        node_id_key = "system_node_id"
        
        # Store the node ID in KeyStorage
        node_id_data = {
            "node_id": node_id,
            "created_at": time.time()  # Use time.time() instead of non-existent method
        }
        
        success = key_storage.store_key(node_id_key, node_id_data)
        if success:
            logger.debug(f"Saved encrypted node ID: {node_id[:8]}...")
            return True
        else:
            logger.error("Failed to save encrypted node ID")
            # Fall back to file storage if KeyStorage fails
    
    # Use file storage as fallback or if KeyStorage not provided
    node_id_file = get_app_data_dir() / "node_id"
    
    try:
        # Write the ID to the file
        with open(node_id_file, "w") as f:
            f.write(node_id)
        
        # Set file permissions to be readable/writable only by the owner
        if os.name == 'posix':  # Unix/Linux/MacOS
            os.chmod(node_id_file, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 permissions
            
        logger.debug(f"Saved node ID to file: {node_id[:8]}...")
        return True
    except Exception as e:
        logger.error(f"Failed to save node ID to file: {e}")
        return False