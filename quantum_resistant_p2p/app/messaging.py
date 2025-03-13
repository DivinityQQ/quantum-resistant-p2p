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
    KeyExchangeAlgorithm, KyberKeyExchange, NTRUKeyExchange,
    SymmetricAlgorithm, AES256GCM, ChaCha20Poly1305,
    SignatureAlgorithm, DilithiumSignature, SPHINCSSignature,
    KeyStorage
)
from .logging import SecureLogger

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """A secure P2P message."""
    
    content: bytes
    sender_id: str
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    is_file: bool = False
    filename: Optional[str] = None
    signature: Optional[bytes] = None
    
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
        self.key_exchange = key_exchange_algorithm or KyberKeyExchange()
        self.symmetric = symmetric_algorithm or AES256GCM()
        self.signature = signature_algorithm or DilithiumSignature()
        
        # Dictionary mapping peer IDs to shared symmetric keys
        self.shared_keys: Dict[str, bytes] = {}
        
        # Dictionary mapping peer IDs to key exchange states
        self.key_exchange_states: Dict[str, int] = {}
        
        # Dictionary mapping message IDs to callbacks for received messages
        self.message_callbacks: Dict[str, Callable[[Any], None]] = {}
        
        # List of global message handlers
        self.global_message_handlers: List[Callable[[Message], None]] = []
        
        # Register message handlers
        self.node.register_message_handler("key_exchange_init", self._handle_key_exchange_init)
        self.node.register_message_handler("key_exchange_response", self._handle_key_exchange_response)
        self.node.register_message_handler("key_exchange_confirm", self._handle_key_exchange_confirm)
        self.node.register_message_handler("key_exchange_test", self._handle_key_exchange_test)
        self.node.register_message_handler("secure_message", self._handle_secure_message)
        
        # Generate or load our keypair
        self._load_or_generate_keypair()
        
        # Load saved peer keys
        self._load_peer_keys()
        
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
    
    def register_global_message_handler(self, handler: Callable[[Message], None]) -> None:
        """Register a handler for all messages.
        
        Args:
            handler: Callback function that takes a Message as parameter
        """
        self.global_message_handlers.append(handler)
        logger.debug("Registered global message handler")
    
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
    
    def _load_or_generate_keypair(self) -> None:
        """Load existing keypairs or generate new ones if they don't exist."""
        # Check if we have key exchange keypair
        key_exchange_key = self.key_storage.get_key(f"key_exchange_{self.key_exchange.name}")
        if key_exchange_key is None:
            # Generate a new keypair
            public_key, private_key = self.key_exchange.generate_keypair()
            key_exchange_key = {
                "algorithm": self.key_exchange.name,
                "public_key": public_key,
                "private_key": private_key
            }
            self.key_storage.store_key(f"key_exchange_{self.key_exchange.name}", key_exchange_key)
            logger.info(f"Generated new key exchange keypair for {self.key_exchange.name}")
        
        # Check if we have signature keypair
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
            shared_key: The shared key
        """
        # Generate a deterministic key ID based on both peer IDs
        key_id = self._generate_key_id(peer_id)
        
        key_data = {
            "peer_id": peer_id,
            "shared_key": shared_key,
            "algorithm": self.key_exchange.name,
            "created_at": time.time()
        }
        success = self.key_storage.store_key(key_id, key_data)
        if success:
            logger.info(f"Saved shared key for peer {peer_id}")
            # Mark the key exchange as established
            self.key_exchange_states[peer_id] = KeyExchangeState.ESTABLISHED
        else:
            logger.error(f"Failed to save shared key for peer {peer_id}")
    
    def _load_peer_keys(self) -> None:
        """Load all saved peer keys from KeyStorage."""
        # List all keys and find peer shared keys
        for key_id, key_data in self.key_storage.list_keys():
            if key_id.startswith("peer_shared_key_"):
                peer_id = key_data.get("peer_id")
                shared_key = key_data.get("shared_key")
                
                # Convert from base64 if needed
                if isinstance(shared_key, str):
                    import base64
                    try:
                        shared_key = base64.b64decode(shared_key)
                    except:
                        logger.error(f"Failed to decode shared key for peer {peer_id}")
                        continue
                
                if peer_id and shared_key:
                    self.shared_keys[peer_id] = shared_key
                    self.key_exchange_states[peer_id] = KeyExchangeState.ESTABLISHED
                    logger.info(f"Loaded shared key for peer {peer_id}")
    
    async def initiate_key_exchange(self, peer_id: str) -> bool:
        """Initiate a key exchange with a peer.
        
        Args:
            peer_id: The ID of the peer to exchange keys with
            
        Returns:
            True if key exchange initiated successfully, False otherwise
        """
        logger.debug(f"Initiating key exchange with {peer_id}")
        
        # If we already have a key exchange in progress, don't start another
        if peer_id in self.key_exchange_states and self.key_exchange_states[peer_id] in [
            KeyExchangeState.INITIATED, KeyExchangeState.RESPONDED, KeyExchangeState.CONFIRMED
        ]:
            logger.warning(f"Key exchange already in progress with {peer_id}")
            return False
        
        try:
            # Get our keypair
            key_exchange_key = self.key_storage.get_key(f"key_exchange_{self.key_exchange.name}")
            if key_exchange_key is None:
                logger.error(f"Missing key exchange keypair for {self.key_exchange.name}")
                return False
            
            # Send our public key
            public_key = key_exchange_key["public_key"]
            
            # Generate a message ID for tracking the response
            message_id = str(uuid.uuid4())
            
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
            
            self.message_callbacks[message_id] = callback
            
            # Set key exchange state
            self.key_exchange_states[peer_id] = KeyExchangeState.INITIATED
            
            # Send the key exchange initiation
            success = await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_init",
                message_id=message_id,
                algorithm=self.key_exchange.name,
                public_key=base64.b64encode(public_key).decode()
            )
            
            if not success:
                logger.error(f"Failed to send key exchange initiation to {peer_id}")
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE
                return False
            
            # Wait for the response
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
                return False
            
        except Exception as e:
            logger.error(f"Error initiating key exchange with {peer_id}: {e}")
            self.key_exchange_states[peer_id] = KeyExchangeState.NONE
            # Check if we have a shared key despite the error
            if peer_id in self.shared_keys:
                logger.warning(f"Key exchange failed with error but shared key exists for {peer_id}")
                return True
            return False
    
    async def _handle_key_exchange_init(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a key exchange initiation message from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange initiation from {peer_id}")
        
        try:
            algorithm_name = message.get("algorithm")
            public_key = message.get("public_key")
            
            if not algorithm_name or not public_key:
                logger.error(f"Invalid key exchange initiation from {peer_id}")
                return
            
            # Make sure this is an algorithm we support
            if algorithm_name != self.key_exchange.name:
                logger.error(f"Unsupported key exchange algorithm from {peer_id}: {algorithm_name}")
                return
            
            # Get our keypair
            key_exchange_key = self.key_storage.get_key(f"key_exchange_{self.key_exchange.name}")
            if key_exchange_key is None:
                logger.error(f"Missing key exchange keypair for {self.key_exchange.name}")
                return
            
            # Encapsulate a shared secret
            public_key_bytes = base64.b64decode(public_key)
            ciphertext, shared_secret = self.key_exchange.encapsulate(public_key_bytes)
            
            # Store the shared secret temporarily
            self.shared_keys[peer_id] = shared_secret
            self.key_exchange_states[peer_id] = KeyExchangeState.RESPONDED
            
            # Log the key exchange
            self.secure_logger.log_event(
                event_type="key_exchange",
                algorithm=self.key_exchange.name,
                peer_id=peer_id,
                direction="received",
                state="responded",
                security_level=getattr(self.key_exchange, "security_level", 3)
            )
            
            # Send the response
            await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_response",
                algorithm=self.key_exchange.name,
                message_id=message.get("message_id"),
                ciphertext=base64.b64encode(ciphertext).decode()
            )
            
            logger.info(f"Sent key exchange response to {peer_id}")
            
        except Exception as e:
            logger.error(f"Error handling key exchange initiation from {peer_id}: {e}")
    
    async def _handle_key_exchange_response(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a key exchange response message from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange response from {peer_id}")
        
        try:
            algorithm_name = message.get("algorithm")
            ciphertext = message.get("ciphertext")
            
            if not algorithm_name or not ciphertext:
                logger.error(f"Invalid key exchange response from {peer_id}")
                return
            
            # Make sure this is an algorithm we support
            if algorithm_name != self.key_exchange.name:
                logger.error(f"Unsupported key exchange algorithm from {peer_id}: {algorithm_name}")
                return
            
            # Get our keypair
            key_exchange_key = self.key_storage.get_key(f"key_exchange_{self.key_exchange.name}")
            if key_exchange_key is None:
                logger.error(f"Missing key exchange keypair for {self.key_exchange.name}")
                return
            
            # Decapsulate the shared secret
            ciphertext_bytes = base64.b64decode(ciphertext)
            private_key = key_exchange_key["private_key"]
            shared_secret = self.key_exchange.decapsulate(private_key, ciphertext_bytes)
            
            # Store the shared secret
            self.shared_keys[peer_id] = shared_secret
            self.key_exchange_states[peer_id] = KeyExchangeState.CONFIRMED
            
            # Send a confirmation message
            await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_confirm",
                algorithm=self.key_exchange.name
            )
            
            # Send a test message to verify the key works
            test_data = {
                "test": True,
                "timestamp": time.time()
            }
            test_data_json = json.dumps(test_data).encode()
            encrypted_test = self.symmetric.encrypt(shared_secret, test_data_json)
            
            await self.node.send_message(
                peer_id=peer_id,
                message_type="key_exchange_test",
                ciphertext=base64.b64encode(encrypted_test).decode()
            )
            
            # Now save the key permanently
            self._save_peer_key(peer_id, shared_secret)
            
            # Log the key exchange
            self.secure_logger.log_event(
                event_type="key_exchange",
                algorithm=self.key_exchange.name,
                peer_id=peer_id,
                direction="initiated",
                state="established",
                security_level=getattr(self.key_exchange, "security_level", 3)
            )
            
            logger.info(f"Completed key exchange with {peer_id} (as initiator)")
            
            # Call any registered callbacks for this message
            message_id = message.get("message_id")
            if message_id and message_id in self.message_callbacks:
                self.message_callbacks[message_id](None)
                del self.message_callbacks[message_id]
            
        except Exception as e:
            logger.error(f"Error handling key exchange response from {peer_id}: {e}")
            
            # Call any registered callbacks for this message with the error
            message_id = message.get("message_id")
            if message_id and message_id in self.message_callbacks:
                self.message_callbacks[message_id](e)
                del self.message_callbacks[message_id]
    
    async def _handle_key_exchange_confirm(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a key exchange confirmation message from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received key exchange confirmation from {peer_id}")
        
        # If we have a shared key, save it permanently
        if peer_id in self.shared_keys and self.key_exchange_states.get(peer_id) == KeyExchangeState.RESPONDED:
            self._save_peer_key(peer_id, self.shared_keys[peer_id])
            logger.info(f"Completed key exchange with {peer_id} (as responder)")
    
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
            
        except Exception as e:
            logger.error(f"Key exchange test failed with {peer_id}: {e}")
            # Shared key might be invalid, need to renegotiate
            if peer_id in self.key_exchange_states:
                self.key_exchange_states[peer_id] = KeyExchangeState.NONE
    
    async def _handle_secure_message(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a secure message from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
        logger.debug(f"Received secure message from {peer_id}")
        
        try:
            ciphertext = message.get("ciphertext")
            signature = message.get("signature")
            public_key = message.get("public_key")
            
            if not ciphertext or not signature or not public_key:
                logger.error(f"Invalid secure message from {peer_id}")
                return
            
            # Make sure we have a shared key
            if peer_id not in self.shared_keys:
                logger.error(f"No shared key established with {peer_id}")
                return
            
            # Decrypt the message
            ciphertext_bytes = base64.b64decode(ciphertext)
            signature_bytes = base64.b64decode(signature)
            public_key_bytes = base64.b64decode(public_key)
            
            try:
                # Decrypt the message
                plaintext = self.symmetric.decrypt(self.shared_keys[peer_id], ciphertext_bytes)
                
                # Verify the signature
                verified = self.signature.verify(public_key_bytes, plaintext, signature_bytes)
                if not verified:
                    logger.error(f"Signature verification failed for message from {peer_id}")
                    return
                
                # Parse the message
                message_data = json.loads(plaintext.decode())
                decrypted_message = Message.from_dict(message_data)
                
                # Log the message
                self.secure_logger.log_event(
                    event_type="message_received",
                    peer_id=peer_id,
                    message_id=decrypted_message.message_id,
                    encryption_algorithm=self.symmetric.name,
                    signature_algorithm=self.signature.name,
                    is_file=decrypted_message.is_file,
                    size=len(plaintext)
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
                logger.error(f"Failed to decrypt or verify message from {peer_id}: {e}")
            
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
        
        # Make sure we have a shared key
        if peer_id not in self.shared_keys:
            logger.info(f"No shared key with {peer_id}, initiating key exchange")
            success = await self.initiate_key_exchange(peer_id)
            if not success:
                logger.error(f"Failed to establish shared key with {peer_id}")
                return False
        
        # Verify the key exchange is in a valid state
        valid_states = [KeyExchangeState.CONFIRMED, KeyExchangeState.ESTABLISHED]
        if peer_id not in self.key_exchange_states or self.key_exchange_states[peer_id] not in valid_states:
            logger.error(f"Key exchange with {peer_id} is not in a valid state for sending messages")
            return False
        
        try:
            # Get our signature keypair
            signature_key = self.key_storage.get_key(f"signature_{self.signature.name}")
            if signature_key is None:
                logger.error(f"Missing signature keypair for {self.signature.name}")
                return False
            
            # Create the message
            message = Message(
                content=content,
                sender_id=self.node.node_id,
                is_file=is_file,
                filename=filename
            )
            
            # Convert to JSON
            message_json = json.dumps(message.to_dict()).encode()
            
            # Sign the message
            private_key = signature_key["private_key"]
            signature = self.signature.sign(private_key, message_json)
            
            # Encrypt the message
            ciphertext = self.symmetric.encrypt(self.shared_keys[peer_id], message_json)
            
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
            
            # Send the encrypted message
            success = await self.node.send_message(
                peer_id=peer_id,
                message_type="secure_message",
                ciphertext=base64.b64encode(ciphertext).decode(),
                signature=base64.b64encode(signature).decode(),
                public_key=base64.b64encode(signature_key["public_key"]).decode()
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
        """Send a file to a peer.
        
        Args:
            peer_id: The ID of the peer to send the file to
            file_path: The path to the file
            
        Returns:
            True if file sent successfully, False otherwise
        """
        logger.debug(f"Sending file {file_path} to {peer_id}")
        
        try:
            # Read the file
            with open(file_path, "rb") as f:
                content = f.read()
            
            # Get the filename
            filename = os.path.basename(file_path)
            
            # Send the file as a message
            return await self.send_message(peer_id, content, is_file=True, filename=filename)
            
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
    
    def set_key_exchange_algorithm(self, algorithm: KeyExchangeAlgorithm) -> None:
        """Set the key exchange algorithm.
        
        Args:
            algorithm: The algorithm to use
        """
        self.key_exchange = algorithm
        # Generate a keypair if we don't have one
        key_exchange_key = self.key_storage.get_key(f"key_exchange_{self.key_exchange.name}")
        if key_exchange_key is None:
            public_key, private_key = self.key_exchange.generate_keypair()
            key_exchange_key = {
                "algorithm": self.key_exchange.name,
                "public_key": public_key,
                "private_key": private_key
            }
            self.key_storage.store_key(f"key_exchange_{self.key_exchange.name}", key_exchange_key)
            logger.info(f"Generated new key exchange keypair for {self.key_exchange.name}")
        
        logger.info(f"Set key exchange algorithm to {self.key_exchange.name}")
    
    def set_symmetric_algorithm(self, algorithm: SymmetricAlgorithm) -> None:
        """Set the symmetric encryption algorithm.
        
        Args:
            algorithm: The algorithm to use
        """
        self.symmetric = algorithm
        logger.info(f"Set symmetric algorithm to {self.symmetric.name}")
    
    def set_signature_algorithm(self, algorithm: SignatureAlgorithm) -> None:
        """Set the digital signature algorithm.
        
        Args:
            algorithm: The algorithm to use
        """
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
        
        logger.info(f"Set signature algorithm to {self.signature.name}")
    
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
