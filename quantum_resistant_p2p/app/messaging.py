"""
Secure messaging functionality for the P2P application.
"""

import json
import logging
import os
import time
import uuid
import hashlib
import asyncio
import base64
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict, field

from ..networking import P2PNode
from ..crypto import (
    KeyExchangeAlgorithm, MLKEMKeyExchange, HQCKeyExchange, FrodoKEMKeyExchange,
    SymmetricAlgorithm, AES256GCM, ChaCha20Poly1305,
    SignatureAlgorithm, MLDSASignature, SPHINCSSignature,
    KeyStorage
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .logging import SecureLogger

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """A secure P2P message."""
    
    content: bytes
    sender_id: str
    recipient_id: Optional[str] = None  # Explicit recipient field
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    is_file: bool = False
    filename: Optional[str] = None
    signature: Optional[bytes] = None
    # Add algorithm info fields
    key_exchange_algo: Optional[str] = None
    symmetric_algo: Optional[str] = None
    signature_algo: Optional[str] = None
    # Special field for system messages
    is_system: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the message to a dictionary."""
        result = asdict(self)
        # Convert bytes to base64
        if isinstance(result['content'], bytes):
            import base64
            result['content'] = base64.b64encode(result['content']).decode('utf-8')
        if result['signature'] is not None:
            result['signature'] = base64.b64encode(result['signature']).decode('utf-8')
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create a message from a dictionary."""
        # Convert base64 to bytes
        if 'content' in data and isinstance(data['content'], str):
            import base64
            data['content'] = base64.b64decode(data['content'].encode('utf-8'))
        if 'signature' in data and isinstance(data['signature'], str):
            data['signature'] = base64.b64decode(data['signature'].encode('utf-8'))
        return cls(**data)
    
    @classmethod
    def system_message(cls, content: str) -> 'Message':
        """Create a system message.
        
        Args:
            content: The message content
            
        Returns:
            A new system message
        """
        return cls(
            content=content.encode('utf-8'),
            sender_id="SYSTEM",
            is_system=True
        )


class KeyExchangeState:
    """State of a key exchange with a peer."""
    NONE = 0
    INITIATED = 1
    RESPONDED = 2
    CONFIRMED = 3
    ESTABLISHED = 4


class SecureMessaging:
    """Secure messaging functionality using post-quantum cryptography.
    
    This class provides high-level functionality for secure messaging,
    including key exchange, encryption, and digital signatures.
    """
    
    def __init__(self, 
                 node: P2PNode,
                 key_storage: KeyStorage,
                 logger: SecureLogger,
                 key_exchange_algorithm: Optional[KeyExchangeAlgorithm] = None,
                 symmetric_algorithm: Optional[SymmetricAlgorithm] = None,
                 signature_algorithm: Optional[SignatureAlgorithm] = None):
        """Initialize secure messaging functionality.

        Args:
            node: The P2P node for communication
            key_storage: The key storage for cryptographic keys
            logger: The secure logger for logging events
            key_exchange_algorithm: The algorithm to use for key exchange
            symmetric_algorithm: The algorithm to use for symmetric encryption
            signature_algorithm: The algorithm to use for digital signatures
        """
        self.node = node
        self.key_storage = key_storage
        self.secure_logger = logger  # Rename to avoid conflict with global logger

        # Use default algorithms if not specified
        self.key_exchange = key_exchange_algorithm or MLKEMKeyExchange()
        self.symmetric = symmetric_algorithm or AES256GCM()
        self.signature = signature_algorithm or MLDSASignature()

        # Dictionary mapping peer IDs to shared symmetric keys
        self.shared_keys: Dict[str, bytes] = {}

        # Dictionary mapping peer IDs to original shared secrets (before derivation)
        self.key_exchange_originals: Dict[str, bytes] = {}

        # Dictionary mapping peer IDs to key exchange states
        self.key_exchange_states: Dict[str, int] = {}

        # Dictionary mapping message IDs to callbacks for received messages
        self.message_callbacks: Dict[str, Callable[[Any], None]] = {}

        # List of global message handlers
        self.global_message_handlers: List[Callable[[Message], None]] = []

        # List of settings change listeners
        self.settings_change_listeners: List[Callable[[], None]] = []

        # Store peer crypto settings
        self.peer_crypto_settings: Dict[str, Dict[str, str]] = {}

        # Track processed message IDs to prevent duplicates
        self.processed_message_ids = set()

        # Register message handlers
        self.node.register_message_handler("key_exchange_init", self._handle_key_exchange_init)
        self.node.register_message_handler("key_exchange_response", self._handle_key_exchange_response)
        self.node.register_message_handler("key_exchange_confirm", self._handle_key_exchange_confirm)
        self.node.register_message_handler("key_exchange_test", self._handle_key_exchange_test)
        self.node.register_message_handler("secure_message", self._handle_secure_message)
        self.node.register_message_handler("crypto_settings_update", self._handle_crypto_settings_update)
        self.node.register_message_handler("crypto_settings_request", self._handle_crypto_settings_request)
        self.node.register_message_handler("key_exchange_rejected", self._handle_key_exchange_rejected)

        # Generate or load our keypair
        self._load_or_generate_keypair()

        # Load saved peer keys
        # self._load_peer_keys()

        # Log initialization
        self.secure_logger.log_event(
            event_type="initialization",
            message=f"Secure messaging initialized with {self.key_exchange.name}, "
                    f"{self.symmetric.name}, and {self.signature.name}"
        )

        # Use the module logger
        logging.getLogger(__name__).info(
            f"Secure messaging initialized with {self.key_exchange.name}, "
            f"{self.symmetric.name}, and {self.signature.name}"
        )

        # Register connection event handler to automatically share settings
        self.node.register_connection_handler(self._handle_new_connection)
    
    def register_global_message_handler(self, handler: Callable[[Message], None]) -> None:
        """Register a handler for all messages.
        
        Args:
            handler: Callback function that takes a Message as parameter
        """
        # Check if this handler is already registered (by its memory address)
        handler_id = id(handler)
        
        # Avoid adding the same handler twice
        if any(id(h) == handler_id for h in self.global_message_handlers):
            logger.debug(f"Handler {handler_id} already registered, skipping")
            return
            
        self.global_message_handlers.append(handler)
        logger.debug(f"Registered global message handler {handler_id}")
    
    def register_settings_change_listener(self, listener: Callable[[], None]) -> None:
        """Register a listener for cryptography settings changes.
        
        Args:
            listener: Callback function that takes no parameters
        """
        listener_id = id(listener)
        
        # Avoid adding the same listener twice
        if any(id(l) == listener_id for l in self.settings_change_listeners):
            logger.debug(f"Settings change listener {listener_id} already registered, skipping")
            return
            
        self.settings_change_listeners.append(listener)
        logger.debug(f"Registered crypto settings change listener {listener_id}")
    
    def _notify_settings_change(self) -> None:
        """Notify all registered listeners that cryptography settings have changed."""
        for listener in self.settings_change_listeners:
            try:
                listener()
            except Exception as e:
                logger.error(f"Error in crypto settings change listener: {e}")
    
    def _generate_key_id(self, peer_id: str) -> str:
        """Generate a deterministic key ID for a peer.

        Both peers should generate the same key ID regardless of who initiated.

        Args:
            peer_id: The ID of the peer

        Returns:
            A unique key ID
        """
        # Sort the node IDs so both sides generate the same key ID
        node_ids = sorted([self.node.node_id, peer_id])
        key_material = f"{node_ids[0]}:{node_ids[1]}:{self.key_exchange.name}"
        key_hash = hashlib.sha256(key_material.encode()).hexdigest()[:16]
        return f"peer_shared_key_{key_hash}"

    def _generate_ephemeral_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a fresh ephemeral keypair for a single key exchange.

        Returns:
            Tuple of (public_key, private_key)
        """
        public_key, private_key = self.key_exchange.generate_keypair()
        logger.info(f"Generated ephemeral keypair for {self.key_exchange.name}")
        return public_key, private_key
    
    def _load_or_generate_keypair(self) -> None:
        """Load existing signature keypair or generate a new one if it doesn't exist.

        Note: KEM keypairs are now generated ephemerally per exchange 
        and are not stored in KeyStorage anymore.
        """
        # We only store signature keypairs persistently now
        # KEM keypairs are generated fresh for each exchange
        signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
        if signature_key is None:
            # Generate a new keypair
            public_key, private_key = self.signature.generate_keypair()
            signature_key = {
                "algorithm": self.signature.name,
                "public_key": public_key,
                "private_key": private_key
            }
            self.key_storage.store_key(f"signature_{self.signature.name}", signature_key)
            logger.info(f"Generated new signature keypair for {self.signature.name}")
    
    def _save_peer_key(self, peer_id: str, shared_key: bytes) -> None:
        """Save a shared key for a peer in KeyStorage.
    
        Args:
            peer_id: The ID of the peer
            shared_key: The derived shared key
        """
        # Always update in-memory shared keys
        self.shared_keys[peer_id] = shared_key
        self.key_exchange_states[peer_id] = KeyExchangeState.ESTABLISHED
        
        # Generate a timestamped key ID for history
        timestamp = int(time.time())
        key_id = f"peer_shared_key_{peer_id}_{timestamp}"
    
        # Get the original shared secret if available
        original_secret = self.key_exchange_originals.get(peer_id)
    
        key_data = {
            "peer_id": peer_id,
            "our_node_id": self.node.node_id,  # Store our node ID with the key
            "shared_key": shared_key,
            "algorithm": self.key_exchange.name,
            "symmetric_algorithm": self.symmetric.name,
            "created_at": timestamp
        }
    
        # Store the original secret if available
        if original_secret:
            key_data["original_shared_secret"] = original_secret
    
        success = self.key_storage.store_key(key_id, key_data)
        if success:
            logger.info(f"Saved shared key history for peer {peer_id}")
        else:
            logger.error(f"Failed to save shared key for peer {peer_id}")
    
    def _load_peer_keys(self) -> None:
        """Load all saved peer keys from KeyStorage."""
        # List all keys and find peer shared keys
        for key_id, key_data in self.key_storage.list_keys():
            if key_id.startswith("peer_shared_key_"):
                peer_id = key_data.get("peer_id")
                shared_key = key_data.get("shared_key")
                original_secret = key_data.get("original_shared_secret")
                stored_node_id = key_data.get("our_node_id")
    
                # Skip keys if our node ID has changed
                if stored_node_id != self.node.node_id:
                    logger.info(f"Skipping key for peer {peer_id}: our node ID has changed")
                    continue
                
                # Convert from base64 if needed
                if isinstance(shared_key, str):
                    import base64
                    try:
                        shared_key = base64.b64decode(shared_key)
                    except:
                        logger.error(f"Failed to decode shared key for peer {peer_id}")
                        continue
                    
                # Also convert original secret if available
                if original_secret and isinstance(original_secret, str):
                    import base64
                    try:
                        original_secret = base64.b64decode(original_secret)
                        # Store the original secret
                        self.key_exchange_originals[peer_id] = original_secret
                    except:
                        logger.error(f"Failed to decode original shared secret for peer {peer_id}")
    
                if peer_id and shared_key:
                    self.shared_keys[peer_id] = shared_key
                    self.key_exchange_states[peer_id] = KeyExchangeState.ESTABLISHED
                    logger.info(f"Loaded shared key for peer {peer_id}")

    def _derive_symmetric_key(self, shared_secret: bytes, peer_id: str) -> bytes:
        """Derive a symmetric key of the appropriate length from a shared secret.

        Args:
            shared_secret: The shared secret from key exchange
            peer_id: The ID of the peer (used as context info)

        Returns:
            A derived key of the appropriate length for the current symmetric algorithm
        """
        # Get the required key size for the current symmetric algorithm
        required_key_size = self.symmetric.key_size

        # Use HKDF to derive a key of the exact length needed
        # - The salt can be None for our purposes
        # - CRITICAL: The info parameter must be identical for both peers
        # - To ensure this, sort the node IDs alphabetically
        node_ids = sorted([self.node.node_id, peer_id])

        # Create a deterministic, symmetric info string
        info = f"quantum_resistant_p2p-v1-{node_ids[0]}-{node_ids[1]}-{self.symmetric.name}".encode()

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=required_key_size,
            salt=None,
            info=info,
        ).derive(shared_secret)

        logger.debug(f"Derived {required_key_size}-byte key for {self.symmetric.name} from "
                    f"{len(shared_secret)}-byte shared secret")

        return derived_key

    def is_algorithm_compatible_with_peer(self, peer_id: str) -> bool:
        """Check if our current algorithm is compatible with the peer's algorithm.

        Args:
            peer_id: The ID of the peer to check

        Returns:
            True if algorithms are compatible, False otherwise
        """
        if peer_id not in self.peer_crypto_settings:
            # If we don't know the peer's settings, assume incompatible
            return False

        peer_settings = self.peer_crypto_settings[peer_id]

        # Check if the key exchange algorithms match exactly
        peer_key_exchange = peer_settings.get("key_exchange", "")
        our_key_exchange = self.key_exchange.display_name

        # Must be the same algorithm type for compatibility
        return peer_key_exchange == our_key_exchange


    async def _handle_new_connection(self, peer_id: str) -> None:
        """Handle a new connection with a peer.

        Args:
            peer_id: The ID of the newly connected peer
        """
        # Check for disconnect event (format: "disconnect:peer_id")
        if peer_id.startswith("disconnect:"):
            disconnected_peer = peer_id.split(":", 1)[1]
            logger.info(f"Handling disconnect event for peer {disconnected_peer}")

            # Remove shared keys and state for this peer
            if disconnected_peer in self.shared_keys:
                del self.shared_keys[disconnected_peer]
            if disconnected_peer in self.key_exchange_states:
                del self.key_exchange_states[disconnected_peer]

            # Notify listeners that a peer disconnected
            for handler in self.global_message_handlers:
                try:
                    disconnect_message = Message.system_message(
                        f"Peer {disconnected_peer} has disconnected"
                    )
                    handler(disconnect_message)
                except Exception as e:
                    logger.error(f"Error in peer disconnect handler: {e}")

            # Notify UI about the change
            self._notify_settings_change()
            return

        logger.info(f"New connection established with {peer_id}, sharing crypto settings")

        try:
            # First send our settings to the peer
            await self.send_crypto_settings_to_peer(peer_id)

            # Then request their settings
            await self.request_crypto_settings_from_peer(peer_id)

            # Clear any existing keys to ensure they aren't reused between sessions
            # but DON'T automatically initiate a key exchange
            if peer_id in self.shared_keys:
                del self.shared_keys[peer_id]
            if peer_id in self.key_exchange_states:
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE

            # Notify that a secure channel needs to be established
            for handler in self.global_message_handlers:
                try:
                    message = Message.system_message(
                        f"Connection established with peer {peer_id}. "
                        f"Use 'Establish Shared Key' button to create a secure channel."
                    )
                    handler(message)
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")

            # Notify any listeners that might want to update UI
            self._notify_settings_change()

            # Log the connection
            self.secure_logger.log_event(
                event_type="connection",
                peer_id=peer_id,
                direction="established"
            )
        except Exception as e:
            logger.error(f"Error handling new connection with {peer_id}: {e}")
    
    async def send_crypto_settings_to_peer(self, peer_id: str) -> None:
        """Send our cryptography settings to a specific peer.

        Args:
            peer_id: The ID of the peer to send settings to
        """
        # Create settings info message
        settings_info = {
            "key_exchange": self.key_exchange.name,
            "symmetric": self.symmetric.name,
            "signature": self.signature.name,
            "timestamp": time.time()
        }

        # Encode the settings info
        message_json = json.dumps(settings_info).encode()

        # Send the settings update (without signature)
        try:
            await self.node.send_message(
                peer_id=peer_id,
                message_type="crypto_settings_update",
                settings=base64.b64encode(message_json).decode()
            )
            logger.debug(f"Sent crypto settings to {peer_id}")
        except Exception as e:
            logger.error(f"Failed to send crypto settings to {peer_id}: {e}")
    
    async def request_crypto_settings_from_peer(self, peer_id: str) -> None:
        """Request cryptography settings from a specific peer.
        
        Args:
            peer_id: The ID of the peer to request settings from
        """
        try:
            await self.node.send_message(
                peer_id=peer_id,
                message_type="crypto_settings_request",
                timestamp=time.time()
            )
            logger.debug(f"Requested crypto settings from {peer_id}")
        except Exception as e:
            logger.error(f"Failed to request crypto settings from {peer_id}: {e}")
    
    async def _handle_crypto_settings_request(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a request for cryptography settings from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the request
            message: The message data
        """
        logger.debug(f"Received crypto settings request from {peer_id}")
        
        # Respond with our settings
        await self.send_crypto_settings_to_peer(peer_id)
    
    async def notify_peers_of_settings_change(self) -> None:
        """Notify all connected peers about cryptography settings changes."""
        peers = self.node.get_peers()
        if not peers:
            return
        
        # Send to all connected peers
        for peer_id in peers:
            try:
                await self.send_crypto_settings_to_peer(peer_id)
            except Exception as e:
                logger.error(f"Failed to notify peer {peer_id} of settings change: {e}")
    
    async def initiate_key_exchange(self, peer_id: str) -> bool:
        """Initiate an authenticated key exchange with a peer using ephemeral keys.

        Args:
            peer_id: The ID of the peer to exchange keys with

        Returns:
            True if key exchange initiated successfully, False otherwise
        """
        logger.debug(f"Initiating authenticated key exchange with {peer_id}")

        # If we already have a key exchange in progress, don't start another
        if peer_id in self.key_exchange_states and self.key_exchange_states[peer_id] in [
            KeyExchangeState.INITIATED, KeyExchangeState.RESPONDED, KeyExchangeState.CONFIRMED
        ]:
            logger.warning(f"Key exchange already in progress with {peer_id}")
            return False

        # Check for algorithm compatibility before proceeding
        compatible = self.is_algorithm_compatible_with_peer(peer_id)
        if not compatible:
            peer_algo = "unknown"
            if peer_id in self.peer_crypto_settings:
                peer_algo = self.peer_crypto_settings[peer_id].get("key_exchange", "unknown")

            logger.warning(f"Algorithm incompatibility with peer {peer_id}: " +
                          f"we use {self.key_exchange.display_name}, they use {peer_algo}")

            # Notify about algorithm mismatch via system message
            for handler in self.global_message_handlers:
                try:
                    mismatch_message = Message.system_message(
                        f"Cannot perform key exchange: Algorithm incompatibility - we use " +
                        f"{self.key_exchange.display_name}, peer uses {peer_algo}. " +
                        f"Both peers must use the same algorithm type."
                    )
                    handler(mismatch_message)
                except Exception as e:
                    logger.error(f"Error in algorithm mismatch handler: {e}")

            return False

        try:
            # Generate a fresh ephemeral keypair for this exchange
            public_key, private_key = self._generate_ephemeral_keypair()

            # Store the private key in memory temporarily (only for this exchange)
            # We'll use a dictionary to map peer_id to ephemeral private keys
            # This is cleared once the exchange is complete
            if not hasattr(self, 'ephemeral_private_keys'):
                self.ephemeral_private_keys = {}
            self.ephemeral_private_keys[peer_id] = private_key

            # Get our signature keypair for authentication
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                logger.error(f"Missing signature keypair for {self.signature.name}")
                return False

            # Create a structured message with metadata
            ke_data = {
                "public_key": base64.b64encode(public_key).decode(),
                "algorithm": self.key_exchange.display_name,
                "sender_id": self.node.node_id,
                "recipient_id": peer_id,
                "timestamp": time.time(),
                "message_id": str(uuid.uuid4())
            }

            # Serialize the data for signing
            ke_data_json = json.dumps(ke_data).encode()

            # Sign the key exchange data
            private_key_sig = signature_key["private_key"]
            signature = self.signature.sign(private_key_sig, ke_data_json)

            # Generate a message ID for tracking the response
            message_id = ke_data["message_id"]

            # Create a future for the response
            future = asyncio.Future()

            # Register a callback for the response
            def callback(result):
                if isinstance(result, Exception):
                    # Don't set exception if we already have the shared key
                    if peer_id in self.shared_keys:
                        future.set_result(True)
                    else:
                        future.set_exception(result)
                else:
                    future.set_result(True)

                # Clean up ephemeral private key regardless of result
                if peer_id in self.ephemeral_private_keys:
                    del self.ephemeral_private_keys[peer_id]

            self.message_callbacks[message_id] = callback

            # Set key exchange state
            self.key_exchange_states[peer_id] = KeyExchangeState.INITIATED

            # Send the authenticated key exchange initiation
            success = await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_init",
                message_id=message_id,
                ke_data=base64.b64encode(ke_data_json).decode(),
                signature=base64.b64encode(signature).decode(),
                public_key=base64.b64encode(signature_key["public_key"]).decode()
            )

            if not success:
                logger.error(f"Failed to send key exchange initiation to {peer_id}")
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE
                # Clean up ephemeral private key
                if peer_id in self.ephemeral_private_keys:
                    del self.ephemeral_private_keys[peer_id]
                return False

            # Wait for the response with timeout
            try:
                await asyncio.wait_for(future, timeout=20.0)
                return True
            except asyncio.TimeoutError:
                # Check if we have a shared key despite the timeout
                if peer_id in self.shared_keys:
                    logger.warning(f"Key exchange callback timed out but shared key exists for {peer_id}")
                    return True

                logger.error(f"Timeout waiting for key exchange response from {peer_id}")
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE
                # Clean up ephemeral private key
                if peer_id in self.ephemeral_private_keys:
                    del self.ephemeral_private_keys[peer_id]
                return False

        except Exception as e:
            logger.error(f"Error initiating key exchange with {peer_id}: {e}")
            self.key_exchange_states[peer_id] = KeyExchangeState.NONE
            # Clean up ephemeral private key
            if hasattr(self, 'ephemeral_private_keys') and peer_id in self.ephemeral_private_keys:
                del self.ephemeral_private_keys[peer_id]
            # Check if we have a shared key despite the error
            if peer_id in self.shared_keys:
                logger.warning(f"Key exchange failed with error but shared key exists for {peer_id}")
                return True
            return False
    
    async def _handle_key_exchange_init(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an authenticated key exchange initiation message from a peer.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange initiation from {peer_id}")

        try:
            # Extract authentication components
            ke_data_b64 = message.get("ke_data")
            signature_b64 = message.get("signature")
            public_key_b64 = message.get("public_key")
            message_id = message.get("message_id")

            if not ke_data_b64 or not signature_b64 or not public_key_b64 or not message_id:
                logger.error(f"Invalid key exchange initiation from {peer_id}, missing required fields")
                return

            # Decode the components
            ke_data_json = base64.b64decode(ke_data_b64)
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)

            # Verify the signature
            verified = self.signature.verify(public_key, ke_data_json, signature)
            if not verified:
                logger.error(f"Invalid signature on key exchange initiation from {peer_id}")
                # Send rejection due to signature verification failure
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="invalid_signature"
                )
                return

            # Parse the verified data
            ke_data = json.loads(ke_data_json.decode())

            # Verify the sender and recipient IDs
            if ke_data.get("sender_id") != peer_id or ke_data.get("recipient_id") != self.node.node_id:
                logger.error(f"Sender/recipient mismatch in key exchange from {peer_id}")
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="identity_mismatch"
                )
                return

            # Verify timestamp is within reasonable bounds (5 minute window)
            timestamp = ke_data.get("timestamp", 0)
            current_time = time.time()
            if abs(current_time - timestamp) > 300:  # 5 minutes
                logger.error(f"Key exchange timestamp from {peer_id} is too old or in the future")
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="timestamp_invalid"
                )
                return

            # Extract the key exchange components
            public_key_b64 = ke_data.get("public_key")
            algorithm_name = ke_data.get("algorithm")

            if not algorithm_name or not public_key_b64:
                logger.error(f"Invalid key exchange initiation from {peer_id}, missing key exchange data")
                return

            # Update peer's crypto settings immediately
            if peer_id not in self.peer_crypto_settings:
                self.peer_crypto_settings[peer_id] = {}

            # Store algorithm name directly
            self.peer_crypto_settings[peer_id]["key_exchange"] = algorithm_name

            # Notify UI about settings update
            self._notify_settings_change()

            # Check if peer's algorithm is compatible with ours
            our_algo_display = self.key_exchange.display_name
            if algorithm_name != our_algo_display:
                logger.warning(f"Peer {peer_id} is using a different key exchange algorithm: {algorithm_name}" +
                              f" (our algorithm: {our_algo_display})")

                # Notify about algorithm mismatch
                for handler in self.global_message_handlers:
                    try:
                        mismatch_message = Message.system_message(
                            f"Peer is using a different key exchange algorithm: {algorithm_name}. " +
                            f"Key exchange will fail unless both peers use the same algorithm."
                        )
                        mismatch_message.key_exchange_algo = algorithm_name
                        handler(mismatch_message)
                    except Exception as e:
                        logger.error(f"Error in algorithm mismatch handler: {e}")

                # Send rejection message to inform peer about incompatibility
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="algorithm_mismatch",
                    our_algorithm=our_algo_display
                )
                return

            # Generate a fresh ephemeral keypair for this response
            # No longer using stored keypairs for key exchange
            try:
                ephemeral_public_key, ephemeral_private_key = self._generate_ephemeral_keypair()
            except Exception as e:
                logger.error(f"Failed to generate ephemeral keypair: {e}")
                # Send rejection due to keypair generation error
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="keypair_generation_error"
                )
                return

            # Get our signature keypair for response authentication
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                logger.error(f"Missing signature keypair for {self.signature.name}")
                return

            # Encapsulate a shared secret
            try:
                public_key_bytes = base64.b64decode(public_key_b64)
                ciphertext, shared_secret = self.key_exchange.encapsulate(public_key_bytes)
            except Exception as e:
                logger.error(f"Failed to encapsulate shared secret: {e}")

                # Send rejection due to encapsulation error
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message_id,
                    reason="encapsulation_error"
                )
                return

            # Store both original shared secret and derived key
            self.key_exchange_originals[peer_id] = shared_secret
            derived_key = self._derive_symmetric_key(shared_secret, peer_id)
            self.shared_keys[peer_id] = derived_key
            self.key_exchange_states[peer_id] = KeyExchangeState.RESPONDED

            # Create authenticated response
            response_data = {
                "algorithm": self.key_exchange.display_name,
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "responder_public_key": base64.b64encode(ephemeral_public_key).decode(),  # Include our ephemeral public key
                "message_id": message_id,
                "sender_id": self.node.node_id,
                "recipient_id": peer_id,
                "timestamp": time.time()
            }

            # Serialize the response data
            response_json = json.dumps(response_data).encode()

            # Sign the response
            response_signature = self.signature.sign(signature_key["private_key"], response_json)

            # Log the key exchange
            self.secure_logger.log_event(
                event_type="key_exchange",
                algorithm=self.key_exchange.display_name,
                peer_id=peer_id,
                direction="received",
                state="responded",
                security_level=getattr(self.key_exchange, "security_level", 3)
            )

            # Send the response
            await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_response",
                response_data=base64.b64encode(response_json).decode(),
                signature=base64.b64encode(response_signature).decode(),
                public_key=base64.b64encode(signature_key["public_key"]).decode(),
                message_id=message_id
            )

            # We don't need to store the ephemeral private key since we've already encapsulated
            # the shared secret and won't need it again
            # ephemeral_private_key gets garbage collected here

            logger.info(f"Sent authenticated key exchange response to {peer_id}")

        except Exception as e:
            logger.error(f"Error handling key exchange initiation from {peer_id}: {e}")

            # Send rejection due to general error
            try:
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_rejected",
                    message_id=message.get("message_id"),
                    reason="general_error",
                    error=str(e)
                )
            except Exception:
                pass
                
    async def _handle_key_exchange_response(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an authenticated key exchange response message from a peer.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange response from {peer_id}")

        try:
            # Extract authentication components
            response_data_b64 = message.get("response_data")
            signature_b64 = message.get("signature")
            public_key_b64 = message.get("public_key")
            message_id = message.get("message_id")

            if not response_data_b64 or not signature_b64 or not public_key_b64 or not message_id:
                logger.error(f"Invalid key exchange response from {peer_id}, missing required fields")
                return

            # Decode the components
            response_json = base64.b64decode(response_data_b64)
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)

            # Verify the signature
            verified = self.signature.verify(public_key, response_json, signature)
            if not verified:
                logger.error(f"Invalid signature on key exchange response from {peer_id}")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception("Invalid signature on key exchange response")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]
                return

            # Parse the verified data
            response_data = json.loads(response_json.decode())

            # Verify the sender and recipient IDs
            if response_data.get("sender_id") != peer_id or response_data.get("recipient_id") != self.node.node_id:
                logger.error(f"Sender/recipient mismatch in key exchange response from {peer_id}")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception("Sender/recipient mismatch in key exchange response")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]
                return

            # Verify timestamp is within reasonable bounds (5 minute window)
            timestamp = response_data.get("timestamp", 0)
            current_time = time.time()
            if abs(current_time - timestamp) > 300:  # 5 minutes
                logger.error(f"Key exchange response timestamp from {peer_id} is too old or in the future")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception("Key exchange response timestamp invalid")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]
                return

            # Extract key exchange specific fields
            algorithm_name = response_data.get("algorithm")
            ciphertext_b64 = response_data.get("ciphertext")
            response_message_id = response_data.get("message_id")
            responder_public_key_b64 = response_data.get("responder_public_key")  # Get responder's ephemeral public key

            if not algorithm_name or not ciphertext_b64 or not response_message_id:
                logger.error(f"Invalid key exchange response from {peer_id}, missing key exchange data")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception("Invalid key exchange response, missing key exchange data")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]
                return

            # Update peer's crypto settings
            if peer_id not in self.peer_crypto_settings:
                self.peer_crypto_settings[peer_id] = {}

            # Store algorithm name directly
            self.peer_crypto_settings[peer_id]["key_exchange"] = algorithm_name

            # Notify UI about settings update
            self._notify_settings_change()

            # Check for algorithm mismatch
            if algorithm_name != self.key_exchange.display_name:
                logger.warning(f"Peer {peer_id} is using a different key exchange algorithm: {algorithm_name}")

                # Notify about algorithm mismatch
                for handler in self.global_message_handlers:
                    try:
                        mismatch_message = Message.system_message(
                            f"Peer is using a different key exchange algorithm: {algorithm_name}. " +
                            f"Key exchange may fail."
                        )
                        mismatch_message.key_exchange_algo = algorithm_name
                        handler(mismatch_message)
                    except Exception as e:
                        logger.error(f"Error in algorithm mismatch handler: {e}")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception(f"Algorithm mismatch: expected {self.key_exchange.display_name}, got {algorithm_name}")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]

                return

            # Get the ephemeral private key for this exchange
            if not hasattr(self, 'ephemeral_private_keys') or peer_id not in self.ephemeral_private_keys:
                logger.error(f"No ephemeral private key found for exchange with {peer_id}")

                # Call any registered callbacks with an error
                if message_id in self.message_callbacks:
                    error = Exception(f"No ephemeral private key found for exchange with {peer_id}")
                    self.message_callbacks[message_id](error)
                    del self.message_callbacks[message_id]
                return

            # Get our ephemeral private key
            ephemeral_private_key = self.ephemeral_private_keys[peer_id]

            # Decapsulate the shared secret
            try:
                ciphertext = base64.b64decode(ciphertext_b64)
                shared_secret = self.key_exchange.decapsulate(ephemeral_private_key, ciphertext)

                # We're done with the ephemeral private key - delete it immediately
                del self.ephemeral_private_keys[peer_id]
            except Exception as e:
                logger.error(f"Error during key decapsulation: {e}")

                # Clean up ephemeral private key
                if peer_id in self.ephemeral_private_keys:
                    del self.ephemeral_private_keys[peer_id]

                # Call any registered callbacks with the error
                if message_id in self.message_callbacks:
                    self.message_callbacks[message_id](e)
                    del self.message_callbacks[message_id]

                # Notify user about the failure
                for handler in self.global_message_handlers:
                    try:
                        error_message = Message.system_message(
                            f"Key exchange failed: Unable to complete key establishment. Error: {str(e)}"
                        )
                        handler(error_message)
                    except Exception as ex:
                        logger.error(f"Error in key exchange error handler: {ex}")

                return

            # Store both original shared secret and derived key
            self.key_exchange_originals[peer_id] = shared_secret
            derived_key = self._derive_symmetric_key(shared_secret, peer_id)
            self.shared_keys[peer_id] = derived_key
            self.key_exchange_states[peer_id] = KeyExchangeState.CONFIRMED

            # Get our signature keypair for confirmation message
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                logger.error(f"Missing signature keypair for {self.signature.name}")
                # We can still proceed with key exchange even without sending the confirmation
            else:
                # Create authenticated confirmation message
                confirm_data = {
                    "type": "key_exchange_confirm",
                    "algorithm": self.key_exchange.display_name,
                    "message_id": message_id,
                    "sender_id": self.node.node_id,
                    "recipient_id": peer_id,
                    "timestamp": time.time()
                }

                # Serialize and sign the confirmation
                confirm_json = json.dumps(confirm_data).encode()
                confirm_signature = self.signature.sign(signature_key["private_key"], confirm_json)

                # Send a confirmation message
                await self.node.send_message(
                    peer_id=peer_id,
                    message_type="key_exchange_confirm",
                    confirm_data=base64.b64encode(confirm_json).decode(),
                    signature=base64.b64encode(confirm_signature).decode(),
                    public_key=base64.b64encode(signature_key["public_key"]).decode(),
                    message_id=message_id
                )

            # Send a test message to verify the key works
            test_data = {
                "test": True,
                "timestamp": time.time()
            }
            test_data_json = json.dumps(test_data).encode()
            encrypted_test = self.symmetric.encrypt(derived_key, test_data_json)

            await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_test",
                ciphertext=base64.b64encode(encrypted_test).decode()
            )

            # Now save the key permanently
            self._save_peer_key(peer_id, derived_key)

            # Log the key exchange
            self.secure_logger.log_event(
                event_type="key_exchange",
                algorithm=self.key_exchange.display_name,
                peer_id=peer_id,
                direction="initiated",
                state="established",
                security_level=getattr(self.key_exchange, "security_level", 3)
            )

            logger.info(f"Completed key exchange with {peer_id} (as initiator)")

            # Call any registered callbacks for this message
            if message_id in self.message_callbacks:
                self.message_callbacks[message_id](None)
                del self.message_callbacks[message_id]

        except Exception as e:
            logger.error(f"Error handling key exchange response from {peer_id}: {e}")

            # Clean up ephemeral private key
            if hasattr(self, 'ephemeral_private_keys') and peer_id in self.ephemeral_private_keys:
                del self.ephemeral_private_keys[peer_id]

            # Call any registered callbacks with the error
            if message_id in self.message_callbacks:
                self.message_callbacks[message_id](e)
                del self.message_callbacks[message_id]
    
    async def _handle_key_exchange_confirm(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an authenticated key exchange confirmation message from a peer.
    
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange confirmation from {peer_id}")
    
        try:
            # Extract authentication components
            confirm_data_b64 = message.get("confirm_data")
            signature_b64 = message.get("signature")
            public_key_b64 = message.get("public_key")
            message_id = message.get("message_id")
    
            if not confirm_data_b64 or not signature_b64 or not public_key_b64:
                logger.error(f"Invalid key exchange confirmation from {peer_id}, missing required fields")
                return
    
            # Decode the components
            confirm_json = base64.b64decode(confirm_data_b64)
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)
    
            # Verify the signature
            verified = self.signature.verify(public_key, confirm_json, signature)
            if not verified:
                logger.error(f"Invalid signature on key exchange confirmation from {peer_id}")
                return
    
            # Parse the verified data
            confirm_data = json.loads(confirm_json.decode())
    
            # Verify the sender and recipient IDs
            if confirm_data.get("sender_id") != peer_id or confirm_data.get("recipient_id") != self.node.node_id:
                logger.error(f"Sender/recipient mismatch in key exchange confirmation from {peer_id}")
                return
    
            # Verify timestamp is within reasonable bounds (5 minute window)
            timestamp = confirm_data.get("timestamp", 0)
            current_time = time.time()
            if abs(current_time - timestamp) > 300:  # 5 minutes
                logger.error(f"Key exchange confirmation timestamp from {peer_id} is too old or in the future")
                return
    
            # If we have a shared key and current state is RESPONDED, save it permanently
            if (peer_id in self.shared_keys and 
                self.key_exchange_states.get(peer_id) == KeyExchangeState.RESPONDED):
                
                self._save_peer_key(peer_id, self.shared_keys[peer_id])
                logger.info(f"Completed key exchange with {peer_id} (as responder)")
                
                # Log the key exchange completion
                self.secure_logger.log_event(
                    event_type="key_exchange",
                    algorithm=self.key_exchange.display_name,
                    peer_id=peer_id,
                    direction="received",
                    state="established",
                    security_level=getattr(self.key_exchange, "security_level", 3)
                )
                
                # Notify about successful key exchange
                for handler in self.global_message_handlers:
                    try:
                        success_message = Message.system_message(
                            f"Secure connection established with {peer_id}"
                        )
                        handler(success_message)
                    except Exception as e:
                        logger.error(f"Error in key exchange success handler: {e}")
        
        except Exception as e:
            logger.error(f"Error handling key exchange confirmation from {peer_id}: {e}")
    
    async def _handle_key_exchange_test(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a key exchange test message from a peer.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange test message from {peer_id}")

        # If we don't have a shared key, ignore the message
        if peer_id not in self.shared_keys:
            logger.error(f"Received key exchange test from {peer_id} but no shared key exists")
            return

        try:
            ciphertext = message.get("ciphertext")
            if not ciphertext:
                logger.error(f"Invalid key exchange test from {peer_id}")
                return

            # Try to decrypt the test message
            ciphertext_bytes = base64.b64decode(ciphertext)
            plaintext = self.symmetric.decrypt(self.shared_keys[peer_id], ciphertext_bytes)

            # Parse the test data
            test_data = json.loads(plaintext.decode())
            if test_data.get("test"):
                logger.info(f"Key exchange test successful with {peer_id}")

                # Notify about successful key exchange
                for handler in self.global_message_handlers:
                    try:
                        success_message = Message.system_message(
                            f"Secure connection established with {peer_id}"
                        )
                        handler(success_message)
                    except Exception as e:
                        logger.error(f"Error in key exchange success handler: {e}")

                # Notify settings change listeners to update UI
                self._notify_settings_change()

        except Exception as e:
            logger.error(f"Key exchange test failed with {peer_id}: {e}")
            # Shared key might be invalid, need to renegotiate
            if peer_id in self.key_exchange_states:
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE

                # Notify about key exchange failure
                for handler in self.global_message_handlers:
                    try:
                        error_message = Message.system_message(
                            f"Key exchange test failed with {peer_id}: {str(e)}"
                        )
                        handler(error_message)
                    except Exception as ex:
                        logger.error(f"Error in key exchange failure handler: {ex}")

    async def _handle_key_exchange_rejected(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a key exchange rejection message from a peer.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        reason = message.get("reason", "unknown")
        logger.warning(f"Key exchange rejected by {peer_id}. Reason: {reason}")

        # Update peer's crypto settings if provided
        if "our_algorithm" in message and peer_id in self.peer_crypto_settings:
            algorithm = message.get("our_algorithm")
            self.peer_crypto_settings[peer_id]["key_exchange"] = algorithm
            # Notify settings listeners
            self._notify_settings_change()

        # Clear any ongoing key exchange state
        if peer_id in self.key_exchange_states:
            self.key_exchange_states[peer_id] = KeyExchangeState.NONE

        # If we had a shared key, remove it as it's no longer valid
        if peer_id in self.shared_keys:
            del self.shared_keys[peer_id]

        # Notify the user about the rejection
        message_text = f"Key exchange rejected by peer. "

        if reason == "algorithm_mismatch":
            peer_algo = message.get("our_algorithm", "unknown")
            message_text += (
                f"Algorithm mismatch: you're using {self.key_exchange.display_name}, " +
                f"peer is using {peer_algo}. Both peers must use the same algorithm type."
            )
        elif reason == "missing_keypair":
            message_text += "Peer is missing required key material."
        elif reason == "encapsulation_error":
            message_text += "Failed to process your public key."
        elif reason == "general_error":
            error = message.get("error", "unknown error")
            message_text += f"Error: {error}"

        # Send system message to notify user
        for handler in self.global_message_handlers:
            try:
                system_message = Message.system_message(message_text)
                handler(system_message)
            except Exception as e:
                logger.error(f"Error in key exchange rejection handler: {e}")

        # Call any registered callbacks for this message with an error
        message_id = message.get("message_id")
        if message_id and message_id in self.message_callbacks:
            error = Exception(f"Key exchange rejected: {reason}")
            self.message_callbacks[message_id](error)
            del self.message_callbacks[message_id]

    async def _handle_crypto_settings_update(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a cryptography settings update from a peer.
    
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received crypto settings update from {peer_id}")
    
        try:
            settings_data = message.get("settings")
    
            if not settings_data:
                logger.error(f"Invalid crypto settings update from {peer_id}")
                return
    
            # Decode the settings
            settings_json = base64.b64decode(settings_data)
            
            # Parse the settings
            settings = json.loads(settings_json.decode())
    
            # Store the peer's settings
            settings_changed = False
    
            if peer_id not in self.peer_crypto_settings:
                self.peer_crypto_settings[peer_id] = {}
                settings_changed = True
    
            # Check if settings have actually changed
            if (self.peer_crypto_settings[peer_id].get("key_exchange") != settings.get("key_exchange") or
                self.peer_crypto_settings[peer_id].get("symmetric") != settings.get("symmetric") or
                self.peer_crypto_settings[peer_id].get("signature") != settings.get("signature")):
                settings_changed = True
    
            # Update stored settings
            self.peer_crypto_settings[peer_id]["key_exchange"] = settings.get("key_exchange")
            self.peer_crypto_settings[peer_id]["symmetric"] = settings.get("symmetric")
            self.peer_crypto_settings[peer_id]["signature"] = settings.get("signature")
            self.peer_crypto_settings[peer_id]["last_updated"] = time.time()
    
            # Log the update
            logger.info(f"Peer {peer_id} uses cryptography settings: "
                       f"key_exchange={settings.get('key_exchange')}, "
                       f"symmetric={settings.get('symmetric')}, "
                       f"signature={settings.get('signature')}")
    
            # Check for mismatches with our settings
            our_settings = {
                "key_exchange": self.key_exchange.name,
                "symmetric": self.symmetric.name,
                "signature": self.signature.name
            }
    
            mismatches = []
            for key in our_settings:
                if settings.get(key) != our_settings[key]:
                    mismatches.append(f"{key}: {settings.get(key)} vs {our_settings[key]}")
    
            if mismatches:
                # Log the mismatch
                logger.warning(f"Cryptography settings mismatch with peer {peer_id}: {', '.join(mismatches)}")
    
                # Notify listeners about the mismatch
                for handler in self.global_message_handlers:
                    try:
                        # Create a special system message for the UI
                        mismatch_message = Message.system_message(
                            f"Peer uses different cryptography settings: {len(mismatches)} differences"
                        )
                        mismatch_message.key_exchange_algo = settings.get("key_exchange")
                        mismatch_message.symmetric_algo = settings.get("symmetric")
                        mismatch_message.signature_algo = settings.get("signature")
                        handler(mismatch_message)
                    except Exception as e:
                        logger.error(f"Error in settings mismatch handler: {e}")
    
                # If the key exchange algorithm differs, initiate a new key exchange
                if settings.get("key_exchange") != our_settings["key_exchange"]:
                    # Remove any existing shared key
                    if peer_id in self.shared_keys:
                        del self.shared_keys[peer_id]
                    if peer_id in self.key_exchange_states:
                        del self.key_exchange_states[peer_id]
    
                    # Initiate a new key exchange if peer is connected
                    if peer_id in self.node.get_peers():
                        asyncio.create_task(self.initiate_key_exchange(peer_id))
                        logger.info(f"Initiated new key exchange with {peer_id} due to algorithm mismatch")
    
            # Only notify if settings have actually changed
            if settings_changed:
                # Notify settings change listeners for UI updates
                self._notify_settings_change()
    
        except Exception as e:
            logger.error(f"Error handling crypto settings update from {peer_id}: {e}")

    async def _handle_secure_message(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a secure message from a peer.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received secure message from {peer_id}")

        try:
            # Step 1: Get the encrypted package and associated data
            ciphertext = message.get("ciphertext")
            associated_data_b64 = message.get("associated_data")

            if not ciphertext or not associated_data_b64:
                logger.error(f"Invalid secure message from {peer_id}, missing ciphertext or associated data")
                return

            # We require associated data
            associated_data = base64.b64decode(associated_data_b64)

            # Make sure we have a shared key
            if peer_id not in self.shared_keys:
                logger.error(f"No shared key established with {peer_id}")
                return

            # Step 2: Decrypt the package using AEAD
            ciphertext_bytes = base64.b64decode(ciphertext)
            decrypted_package_json = self.symmetric.decrypt(
                self.shared_keys[peer_id], 
                ciphertext_bytes,
                associated_data=associated_data
            )

            # Step 3: Parse the signed package
            signed_package = json.loads(decrypted_package_json.decode())

            # Step 4: Extract the components
            message_json = base64.b64decode(signed_package["message"])
            signature_bytes = base64.b64decode(signed_package["signature"])
            public_key_bytes = base64.b64decode(signed_package["public_key"])

            # Step 5: Verify the signature
            verified = self.signature.verify(public_key_bytes, message_json, signature_bytes)
            if not verified:
                logger.error(f"Signature verification failed for message from {peer_id}")
                return

            # Step 6: Parse the verified message
            message_data = json.loads(message_json.decode())
            decrypted_message = Message.from_dict(message_data)

            # Step 7: Verify associated data matches message content
            ad_data = json.loads(associated_data.decode())

            # Verify critical metadata matches
            if ad_data.get("message_id") != decrypted_message.message_id:
                logger.error(f"Message ID mismatch in associated data from {peer_id}")
                return

            if ad_data.get("sender_id") != peer_id:
                logger.error(f"Sender ID mismatch in associated data from {peer_id}")
                return

            if ad_data.get("recipient_id") != self.node.node_id:
                logger.error(f"Recipient ID mismatch in associated data from {peer_id}")
                return

            # Step 8: Check for duplicate message
            if decrypted_message.message_id in self.processed_message_ids:
                logger.debug(f"Message {decrypted_message.message_id} already processed, skipping")
                return

            # Add to processed IDs
            self.processed_message_ids.add(decrypted_message.message_id)

            # Clean up processed IDs occasionally
            if len(self.processed_message_ids) > 100:
                old_ids = list(self.processed_message_ids)[:50]
                for old_id in old_ids:
                    self.processed_message_ids.remove(old_id)

            # Update peer crypto settings from message metadata
            if peer_id not in self.peer_crypto_settings:
                self.peer_crypto_settings[peer_id] = {}

            if hasattr(decrypted_message, 'key_exchange_algo') and decrypted_message.key_exchange_algo:
                self.peer_crypto_settings[peer_id]["key_exchange"] = decrypted_message.key_exchange_algo

            if hasattr(decrypted_message, 'symmetric_algo') and decrypted_message.symmetric_algo:
                self.peer_crypto_settings[peer_id]["symmetric"] = decrypted_message.symmetric_algo

            if hasattr(decrypted_message, 'signature_algo') and decrypted_message.signature_algo:
                self.peer_crypto_settings[peer_id]["signature"] = decrypted_message.signature_algo

            # Log the message
            self.secure_logger.log_event(
                event_type="message_received",
                peer_id=peer_id,
                message_id=decrypted_message.message_id,
                encryption_algorithm=self.symmetric.name,
                signature_algorithm=self.signature.name,
                is_file=decrypted_message.is_file,
                size=len(message_json)
            )

            logger.info(f"Received and verified message from {peer_id}")

            # Notify global message handlers
            for handler in self.global_message_handlers:
                try:
                    handler(decrypted_message)
                except Exception as e:
                    logger.error(f"Error in global message handler: {e}")

            # Call any registered callbacks for this message
            if decrypted_message.message_id in self.message_callbacks:
                self.message_callbacks[decrypted_message.message_id](decrypted_message)
                del self.message_callbacks[decrypted_message.message_id]

        except Exception as e:
            logger.error(f"Error handling secure message from {peer_id}: {e}")

    async def send_message(self, peer_id: str, content: bytes, 
                       is_file: bool = False, filename: Optional[str] = None) -> bool:
        """Send a secure message to a peer.

        Args:
            peer_id: The ID of the peer to send the message to
            content: The message content
            is_file: Whether the content is a file
            filename: The filename, if is_file is True

        Returns:
            True if message sent successfully, False otherwise
        """
        logger.debug(f"Sending message to {peer_id}")

        # Verify the key exchange is valid
        if not self.verify_key_exchange_state(peer_id):
            logger.warning(f"Key exchange with {peer_id} is not valid or complete")
            # Notify about the issue
            for handler in self.global_message_handlers:
                try:
                    system_message = Message.system_message(
                        f"Cannot send message to {peer_id}: Secure channel not established. Please initiate key exchange."
                    )
                    handler(system_message)
                except Exception as e:
                    logger.error(f"Error in system message handler: {e}")
            return False

        # Make sure we have a shared key
        if peer_id not in self.shared_keys:
            logger.info(f"No shared key with {peer_id}, initiating key exchange")
            success = await self.initiate_key_exchange(peer_id)
            if not success:
                logger.error(f"Failed to establish shared key with {peer_id}")
                return False

        try:
            # Get our signature keypair
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                logger.error(f"Missing signature keypair for {self.signature.name}")
                return False

            # Step 1: Create the message object
            message = Message(
                content=content,
                sender_id=self.node.node_id,
                recipient_id=peer_id,
                is_file=is_file,
                filename=filename,
                # Include algorithm information in the message
                key_exchange_algo=self.key_exchange.name,
                symmetric_algo=self.symmetric.name,
                signature_algo=self.signature.name
            )

            # Step 2: Convert to JSON (this is what will be signed)
            message_json = json.dumps(message.to_dict()).encode()

            # Step 3: Sign the message JSON
            private_key = signature_key["private_key"]
            signature = self.signature.sign(private_key, message_json)

            # Step 4: Create signed package (message + signature + public key)
            signed_package = {
                "message": base64.b64encode(message_json).decode(),
                "signature": base64.b64encode(signature).decode(),
                "public_key": base64.b64encode(signature_key["public_key"]).decode()
            }

            # Step 5: Serialize the signed package to JSON
            signed_package_json = json.dumps(signed_package).encode()

            # Step 6: Create AEAD associated data from critical metadata
            associated_data = json.dumps({
                "type": "secure_message",
                "message_id": message.message_id,
                "sender_id": self.node.node_id,
                "recipient_id": peer_id,
                "timestamp": message.timestamp,
                "is_file": is_file,
            }).encode()

            # Step 7: Encrypt the signed package with AEAD
            ciphertext = self.symmetric.encrypt(
                self.shared_keys[peer_id], 
                signed_package_json,
                associated_data=associated_data
            )

            # Log the message
            self.secure_logger.log_event(
                event_type="message_sent",
                peer_id=peer_id,
                message_id=message.message_id,
                encryption_algorithm=self.symmetric.name,
                signature_algorithm=self.signature.name,
                is_file=is_file,
                size=len(content)
            )

            # Step 8: Send the encrypted package and associated data
            success = await self.node.send_message(
                peer_id=peer_id,
                message_type="secure_message",
                ciphertext=base64.b64encode(ciphertext).decode(),
                associated_data=base64.b64encode(associated_data).decode()
            )

            if not success:
                logger.error(f"Failed to send message to {peer_id}")
                return False

            logger.info(f"Sent secure message to {peer_id}")
            return True

        except Exception as e:
            logger.error(f"Error sending message to {peer_id}: {e}")
            return False
    
    async def send_file(self, peer_id: str, file_path: str) -> bool:
        """Send a file to a peer using chunked messaging.

        Args:
            peer_id: The ID of the peer to send the file to
            file_path: The path to the file

        Returns:
            True if file sent successfully, False otherwise
        """
        logger.debug(f"Sending file {file_path} to {peer_id}")

        try:
            # Get file info
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            # Log the transfer
            self.secure_logger.log_event(
                event_type="message_sent",
                peer_id=peer_id,
                is_file=True,
                filename=file_name,
                size=file_size
            )

            # Read the file
            with open(file_path, "rb") as f:
                content = f.read()

            # Now send the file data as a secure message
            # The node's chunking mechanism will handle large files automatically
            return await self.send_message(peer_id, content, is_file=True, filename=file_name)

        except Exception as e:
            logger.error(f"Error sending file {file_path} to {peer_id}: {e}")
            return False
    
    def register_message_callback(self, message_id: str, 
                               callback: Callable[[Message], None]) -> None:
        """Register a callback for a specific message ID.
        
        Args:
            message_id: The ID of the message to wait for
            callback: The callback function to call when the message is received
        """
        self.message_callbacks[message_id] = callback
        logger.debug(f"Registered callback for message {message_id}")
    
    def get_peer_crypto_settings(self, peer_id: str) -> Optional[Dict[str, str]]:
        """Get the cryptography settings of a peer.
        
        Args:
            peer_id: The ID of the peer
            
        Returns:
            Dictionary of peer's cryptography settings, or None if not available
        """
        return self.peer_crypto_settings.get(peer_id)
    
    def set_key_exchange_algorithm(self, algorithm: KeyExchangeAlgorithm) -> None:
        """Set the key exchange algorithm.
        
        Args:
            algorithm: The algorithm to use
        """
        # Only take action if the algorithm has actually changed
        if self.key_exchange.name != algorithm.name:
            # Store old algorithm name for logging
            old_algorithm = self.key_exchange.name
            
            # Update the algorithm
            self.key_exchange = algorithm
            
            # Clear all shared keys and key exchange states
            # This is important - we need to renegotiate with all peers
            old_peer_ids = list(self.shared_keys.keys())
            self.shared_keys = {}
            self.key_exchange_states = {}
            
            # Log the change
            logger.info(f"Changed key exchange algorithm from {old_algorithm} to {self.key_exchange.name}")
            self.secure_logger.log_event(
                event_type="crypto_settings_changed",
                component="key_exchange",
                old_algorithm=old_algorithm,
                new_algorithm=self.key_exchange.name
            )
            
            # Notify cryptography settings change listeners
            self._notify_settings_change()
            
            # For all connected peers, start key exchange asynchronously
            for peer_id in old_peer_ids:
                if peer_id in self.node.get_peers():
                    # Use create_task to start the key exchange asynchronously
                    asyncio.create_task(self.initiate_key_exchange(peer_id))
                    logger.info(f"Triggered new key exchange with {peer_id} due to algorithm change")
            
            # Notify peers about our settings change
            asyncio.create_task(self.notify_peers_of_settings_change())
    
    def set_symmetric_algorithm(self, algorithm: SymmetricAlgorithm) -> None:
        """Set the symmetric encryption algorithm.

        Args:
            algorithm: The algorithm to use
        """
        # Only take action if the algorithm has actually changed
        if self.symmetric.name != algorithm.name:
            # Store old algorithm name for logging
            old_algorithm = self.symmetric.name

            # Update the algorithm
            self.symmetric = algorithm

            # Re-derive keys for all peers with available original shared secrets
            for peer_id, original_secret in list(self.key_exchange_originals.items()):
                if peer_id in self.key_exchange_states and self.key_exchange_states[peer_id] == KeyExchangeState.ESTABLISHED:
                    try:
                        # Derive a new key with the new algorithm's requirements
                        derived_key = self._derive_symmetric_key(original_secret, peer_id)
                        self.shared_keys[peer_id] = derived_key

                        # Save the updated key
                        self._save_peer_key(peer_id, derived_key)

                        logger.info(f"Re-derived key for peer {peer_id} with new algorithm {self.symmetric.name}")
                    except Exception as e:
                        logger.error(f"Failed to re-derive key for peer {peer_id}: {e}")

            # Log the change
            logger.info(f"Changed symmetric algorithm from {old_algorithm} to {self.symmetric.name}")
            self.secure_logger.log_event(
                event_type="crypto_settings_changed",
                component="symmetric",
                old_algorithm=old_algorithm,
                new_algorithm=self.symmetric.name
            )

            # Notify cryptography settings change listeners
            self._notify_settings_change()

            # Notify peers about our settings change
            asyncio.create_task(self.notify_peers_of_settings_change())
    
    def set_signature_algorithm(self, algorithm: SignatureAlgorithm) -> None:
        """Set the digital signature algorithm.
        
        Args:
            algorithm: The algorithm to use
        """
        # Only take action if the algorithm has actually changed
        if self.signature.name != algorithm.name:
            # Store old algorithm name for logging
            old_algorithm = self.signature.name
            
            # Update the algorithm
            self.signature = algorithm
            
            # Generate a keypair if we don't have one
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                public_key, private_key = self.signature.generate_keypair()
                signature_key = {
                    "algorithm": self.signature.name,
                    "public_key": public_key,
                    "private_key": private_key
                }
                self.key_storage.store_key(f"signature_{self.signature.name}", signature_key)
                logger.info(f"Generated new signature keypair for {self.signature.name}")
            
            # Log the change
            logger.info(f"Changed signature algorithm from {old_algorithm} to {self.signature.name}")
            self.secure_logger.log_event(
                event_type="crypto_settings_changed",
                component="signature",
                old_algorithm=old_algorithm,
                new_algorithm=self.signature.name
            )
            
            # Notify cryptography settings change listeners
            self._notify_settings_change()
            
            # Notify peers about our settings change
            asyncio.create_task(self.notify_peers_of_settings_change())
    
    def get_security_info(self) -> Dict[str, Any]:
        """Get information about the current security configuration.
        
        Returns:
            Dictionary with security information
        """
        return {
            "key_exchange": {
                "algorithm": self.key_exchange.name,
                "security_level": getattr(self.key_exchange, "security_level", 3),
                "description": self.key_exchange.description
            },
            "symmetric": {
                "algorithm": self.symmetric.name,
                "key_size": self.symmetric.key_size,
                "description": self.symmetric.description
            },
            "signature": {
                "algorithm": self.signature.name,
                "security_level": getattr(self.signature, "security_level", 3),
                "description": self.signature.description
            },
            "peers_with_shared_keys": len(self.shared_keys)
        }

    def adopt_peer_settings(self, peer_id: str) -> bool:
        """Adopt the cryptography settings of a peer.

        Args:
            peer_id: The ID of the peer whose settings to adopt

        Returns:
            True if settings were adopted, False otherwise
        """
        if peer_id not in self.peer_crypto_settings:
            logger.error(f"No settings available for peer {peer_id}")
            return False

        peer_settings = self.peer_crypto_settings[peer_id]
        settings_changed = False

        # Adopt key exchange algorithm if needed
        key_exchange_algo = peer_settings.get("key_exchange")
        if key_exchange_algo and key_exchange_algo != self.key_exchange.name:
            # Map algorithm name to actual algorithm
            from ..crypto import MLKEMKeyExchange, HQCKeyExchange, FrodoKEMKeyExchange

            if "ML-KEM" in key_exchange_algo:
                # Get the security level from the name
                if "Level 1" in key_exchange_algo:
                    level = 1
                elif "Level 3" in key_exchange_algo:
                    level = 3
                elif "Level 5" in key_exchange_algo:
                    level = 5
                else:
                    level = 3  # Default
                algorithm = MLKEMKeyExchange(security_level=level)
            elif "HQC" in key_exchange_algo:
                # Get the security level from the name
                if "Level 1" in key_exchange_algo:
                    level = 1
                elif "Level 3" in key_exchange_algo:
                    level = 3
                elif "Level 5" in key_exchange_algo:
                    level = 5
                else:
                    level = 3  # Default
                algorithm = HQCKeyExchange(security_level=level)
            elif "FrodoKEM" in key_exchange_algo:
                # Get the security level from the name
                if "Level 1" in key_exchange_algo:
                    level = 1
                elif "Level 3" in key_exchange_algo:
                    level = 3
                elif "Level 5" in key_exchange_algo:
                    level = 5
                else:
                    level = 3  # Default
                # Check if it's AES or SHAKE
                use_aes = "AES" in key_exchange_algo
                algorithm = FrodoKEMKeyExchange(security_level=level, use_aes=use_aes)
            else:
                logger.warning(f"Unknown key exchange algorithm: {key_exchange_algo}")
                return False

            self.set_key_exchange_algorithm(algorithm)
            settings_changed = True

        # Adopt symmetric algorithm if needed
        symmetric_algo = peer_settings.get("symmetric")
        if symmetric_algo and symmetric_algo != self.symmetric.name:
            if symmetric_algo == "AES-256-GCM":
                algorithm = AES256GCM()
            elif symmetric_algo == "ChaCha20-Poly1305":
                algorithm = ChaCha20Poly1305()
            else:
                logger.warning(f"Unknown symmetric algorithm: {symmetric_algo}")
                return False

            self.set_symmetric_algorithm(algorithm)
            settings_changed = True

        # Adopt signature algorithm if needed
        signature_algo = peer_settings.get("signature")
        if signature_algo and signature_algo != self.signature.name:
            # Map algorithm name to actual algorithm
            from ..crypto import MLDSASignature, SPHINCSSignature

            if "ML-DSA" in signature_algo:
                # Get the security level from the name
                if "Level 2" in signature_algo:
                    level = 2
                elif "Level 3" in signature_algo:
                    level = 3
                elif "Level 5" in signature_algo:
                    level = 5
                else:
                    level = 3  # Default
                algorithm = MLDSASignature(security_level=level)
            elif "SPHINCS+" in signature_algo:
                # Get the security level from the name
                if "Level 1" in signature_algo:
                    level = 1
                elif "Level 3" in signature_algo:
                    level = 3
                elif "Level 5" in signature_algo:
                    level = 5
                else:
                    level = 3  # Default
                algorithm = SPHINCSSignature(security_level=level)
            else:
                logger.warning(f"Unknown signature algorithm: {signature_algo}")
                return False

            self.set_signature_algorithm(algorithm)
            settings_changed = True

        if settings_changed:
            logger.info(f"Successfully adopted settings from peer {peer_id}")
            return True
        else:
            logger.info(f"No settings changes needed for peer {peer_id}")
            return False

    def verify_key_exchange_state(self, peer_id: str) -> bool:
        """Verify the key exchange state for a peer.

        This function checks if a key exchange with a peer is actually valid
        and properly established, not just assumed from a previous connection.

        Args:
            peer_id: The ID of the peer

        Returns:
            True if the key exchange is valid, False otherwise
        """
        # Check if we have a shared key
        if peer_id not in self.shared_keys:
            logger.debug(f"No shared key exists for peer {peer_id}")
            return False

        # Check if the key exchange is in a valid state
        valid_states = [KeyExchangeState.CONFIRMED, KeyExchangeState.ESTABLISHED]
        if peer_id not in self.key_exchange_states or self.key_exchange_states[peer_id] not in valid_states:
            logger.warning(f"Key exchange with {peer_id} is in an invalid state: " +
                          f"{self.key_exchange_states.get(peer_id, 'NONE')}")
            return False

        # Check if the peer is actually connected
        if peer_id not in self.node.get_peers():
            logger.warning(f"Peer {peer_id} has a shared key but is not connected")
            return False

        # All checks passed, key exchange is valid
        return True

class MessageStore:
    """Store for secure messages to provide persistence and unread count tracking."""
    
    def __init__(self):
        """Initialize a new message store."""
        # Maps peer_id -> list of Message objects
        self.messages = {}
        # Maps peer_id -> count of unread messages
        self.unread_counts = {}
        # Maps peer_id -> timestamp of last message
        self.last_activity = {}
        # Current node ID to identify local messages
        self.current_node_id = None
    
    def add_message(self, message, mark_as_read=False):
        """Add a message to the store.
        
        Args:
            message: The message to store
            mark_as_read: Whether to mark the message as read immediately
        """
        # Determine the conversation peer_id based on message direction
        store_peer_id = None
        
        if hasattr(message, 'recipient_id') and message.recipient_id:
            if message.sender_id == self.current_node_id:
                # Outgoing message - use recipient_id as the conversation key
                store_peer_id = message.recipient_id
            elif message.recipient_id == self.current_node_id:
                # Incoming direct message - use sender_id as the conversation key
                store_peer_id = message.sender_id
        
        if store_peer_id is None:
            # Fallback to sender_id if direction can't be determined
            store_peer_id = message.sender_id
            
            # Skip system messages that aren't part of a conversation
            if message.is_system:
                return
        
        # Initialize data structures for this peer if needed
        if store_peer_id not in self.messages:
            self.messages[store_peer_id] = []
            self.unread_counts[store_peer_id] = 0
        
        # Add the message
        self.messages[store_peer_id].append(message)
        
        # Update last activity timestamp
        self.last_activity[store_peer_id] = message.timestamp
        
        # Increment unread count if not marked as read
        if not mark_as_read:
            self.unread_counts[store_peer_id] = self.unread_counts.get(store_peer_id, 0) + 1
    
    def get_messages(self, peer_id):
        """Get all messages for a peer.
        
        Args:
            peer_id: The ID of the peer
            
        Returns:
            List of Message objects
        """
        return self.messages.get(peer_id, [])
    
    def mark_all_read(self, peer_id):
        """Mark all messages from a peer as read.
        
        Args:
            peer_id: The ID of the peer
        """
        self.unread_counts[peer_id] = 0
    
    def get_unread_count(self, peer_id):
        """Get the number of unread messages from a peer.
        
        Args:
            peer_id: The ID of the peer
            
        Returns:
            The number of unread messages
        """
        return self.unread_counts.get(peer_id, 0)
    
    def has_unread_messages(self, peer_id):
        """Check if a peer has any unread messages.
        
        Args:
            peer_id: The ID of the peer
            
        Returns:
            True if there are unread messages, False otherwise
        """
        return self.get_unread_count(peer_id) > 0
        
    def set_current_node_id(self, node_id):
        """Set the current node ID for determining message direction.
        
        Args:
            node_id: The ID of the current node
        """
        self.current_node_id = node_id