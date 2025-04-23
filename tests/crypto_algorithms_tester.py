"""
Comprehensive test suite for Quantum-Resistant P2P application.

This script systematically tests various combinations of post-quantum cryptographic
algorithms for key exchange, symmetric encryption, and digital signatures.
It also performs file transfer tests and collects performance metrics.

Optimized for speed using event-based signaling to minimize wait times.
"""

import asyncio
import logging
import sys
import os
import time
import uuid
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
import traceback
import shutil
import json
from datetime import datetime
import signal

# Add the parent directory to the path so we can import the package
parent_dir = str(Path(__file__).parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from quantum_resistant_p2p.networking import P2PNode
from quantum_resistant_p2p.crypto import (
    KeyStorage, KeyExchangeAlgorithm, SymmetricAlgorithm, SignatureAlgorithm,
    MLKEMKeyExchange, HQCKeyExchange, FrodoKEMKeyExchange,
    AES256GCM, ChaCha20Poly1305,
    MLDSASignature, SPHINCSSignature
)
from quantum_resistant_p2p.app import SecureMessaging, SecureLogger, MessageStore, Message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("crypto_algorithm_tester")


class TestNode:
    """A test node for comprehensive testing."""
    
    def __init__(self, port: int, name: str, base_dir: Optional[Path] = None):
        """Initialize a test node.
        
        Args:
            port: The port for the P2P node
            name: A name for this node
            base_dir: Base directory for node data (optional)
        """
        self.port = port
        self.name = name
        self.node_id = f"{name}-{uuid.uuid4().hex[:8]}"
        
        # Create directories for this instance
        if base_dir is None:
            self.base_dir = Path.home() / ".quantum_resistant_p2p" / name
        else:
            self.base_dir = base_dir / name
            
        self.base_dir.mkdir(exist_ok=True, parents=True)
        
        logs_dir = self.base_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.key_storage = KeyStorage(str(self.base_dir / "keys.json"))
        # Always use the same password for test instances
        self.key_storage.unlock("test_password")
        
        # Get or create a persistent key for the secure logger
        secure_logger_key = self.key_storage.get_or_create_persistent_key("secure_logger", key_size=32)
        if secure_logger_key is None:
            raise RuntimeError("Failed to obtain secure logger key from key storage")
        
        # Initialize the secure logger with the persistent key
        self.secure_logger = SecureLogger(str(logs_dir), encryption_key=secure_logger_key)
        
        # Create P2P node with specified port and our custom node_id
        # Use explicit localhost (127.0.0.1) for testing
        self.node = P2PNode(host='127.0.0.1', port=port, node_id=self.node_id)
        
        # Create secure messaging
        self.secure_messaging = SecureMessaging(
            node=self.node,
            key_storage=self.key_storage,
            logger=self.secure_logger
        )
        
        # Create a message store for storing messages
        self.message_store = MessageStore()
        self.message_store.set_current_node_id(self.node_id)
        
        # Track received messages for testing verification
        self.received_messages: List[Message] = []
        self.received_files: List[Message] = []
        
        # Event for signaling key exchange completion
        self.key_exchange_complete = asyncio.Event()
        # Event for signaling message received
        self.message_received = asyncio.Event()
        # Event for signaling file received
        self.file_received = asyncio.Event()
        
        # Register message handler
        self.secure_messaging.register_global_message_handler(self._handle_message)
        
        logger.info(f"Created test node {self.name} (ID: {self.node_id}) on port {self.port}")
    
    def _handle_message(self, message: Message) -> None:
        """Handle a received message.

        This must be a regular function (not async) since SecureMessaging
        expects non-coroutine message handlers.
        """
        logger.info(f"Node {self.name}: Received message from {message.sender_id[:8]}")

        # Store in message store
        self.message_store.add_message(message, mark_as_read=True)

        # Check for key exchange completion
        if message.is_system:
            # Check if this is a key exchange success message
            if message.content and b"Secure connection established" in message.content:
                logger.info(f"Node {self.name}: Received key exchange completion message")
                # Signal that key exchange is complete
                self.key_exchange_complete.set()

        # Verify shared key presence on any message during key exchange
        # This helps catch key exchange completion even if the system message is missed
        if hasattr(self, 'secure_messaging') and message.sender_id in self.secure_messaging.shared_keys:
            if not self.key_exchange_complete.is_set():
                logger.info(f"Node {self.name}: Key exchange detected via shared key presence")
                self.key_exchange_complete.set()

        # Track for test verification and set appropriate event
        if message.is_system:
            # Already handled above
            pass
        elif message.is_file:
            self.received_files.append(message)
            # Signal that file was received
            self.file_received.set()
        else:
            self.received_messages.append(message)
            # Signal that message was received
            self.message_received.set()
        
    async def start(self) -> None:
        """Start the node and wait for it to be ready."""
        # Start server task and save it for later cleanup
        self.node_task = asyncio.create_task(self.node.start())
        
        # Wait a brief moment for the server to start
        await asyncio.sleep(0.2)
        
        logger.info(f"Node {self.name}: P2P node started on port {self.port}")
    
    async def connect_to(self, other_port: int, max_attempts: int = 3) -> bool:
        """Connect to another node on localhost.
        
        Args:
            other_port: The port of the other node
            max_attempts: Maximum number of connection attempts
            
        Returns:
            True if connection successful, False otherwise
        """
        logger.info(f"Node {self.name}: Attempting to connect to localhost:{other_port}...")
        
        try:
            # Attempt connection with retry
            for attempt in range(max_attempts):
                success = await self.node.connect_to_peer('127.0.0.1', other_port)
                if success:
                    logger.info(f"Node {self.name}: Successfully connected to localhost:{other_port}")
                    return True
                else:
                    logger.warning(f"Node {self.name}: Connection attempt {attempt+1} failed")
                    if attempt < max_attempts - 1:
                        # Only sleep if we're going to retry
                        await asyncio.sleep(0.5)
            
            logger.error(f"Node {self.name}: Failed to connect after {max_attempts} attempts")
            return False
        except Exception as e:
            logger.error(f"Node {self.name}: Error connecting to localhost:{other_port}: {e}")
            return False
    
    async def send_message(self, peer_id: str, content: str) -> bool:
        """Send a message to a peer.
        
        Args:
            peer_id: The ID of the peer
            content: The message content
        """
        logger.info(f"Node {self.name}: Sending message to {peer_id[:8]}")
        try:
            # Clear message receipt event before sending
            self.message_received.clear()
            
            success = await self.secure_messaging.send_message(
                peer_id=peer_id,
                content=content.encode('utf-8')
            )
            if success:
                logger.info(f"Node {self.name}: Message sent successfully")
                return True
            else:
                logger.error(f"Node {self.name}: Failed to send message")
                return False
        except Exception as e:
            logger.error(f"Node {self.name}: Error sending message: {e}")
            return False
    
    async def send_file(self, peer_id: str, file_path: str) -> bool:
        """Send a file to a peer.
        
        Args:
            peer_id: The ID of the peer
            file_path: Path to the file to send
            
        Returns:
            True if file sent successfully, False otherwise
        """
        logger.info(f"Node {self.name}: Sending file to {peer_id[:8]}")
        try:
            # Clear file receipt event before sending
            self.file_received.clear()
            
            success = await self.secure_messaging.send_file(
                peer_id=peer_id,
                file_path=file_path
            )
            if success:
                logger.info(f"Node {self.name}: File sent successfully")
                return True
            else:
                logger.error(f"Node {self.name}: Failed to send file")
                return False
        except Exception as e:
            logger.error(f"Node {self.name}: Error sending file: {e}")
            return False

    async def wait_for_key_exchange(self, timeout: float = 10.0) -> bool:
        """Wait for key exchange to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if key exchange completed in time, False otherwise
        """
        # First check if we already have a shared key with any peer
        # This handles cases where the event might not have been set yet
        if hasattr(self, 'secure_messaging'):
            peers = self.node.get_peers()
            if peers and any(peer in self.secure_messaging.shared_keys for peer in peers):
                logger.info(f"Node {self.name}: Already has shared key with peer - setting completion event")
                self.key_exchange_complete.set()
                return True

        # Wait for the event with timeout
        try:
            await asyncio.wait_for(self.key_exchange_complete.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Node {self.name}: Timeout waiting for key exchange completion")

            # Double-check if key was established during wait (final verification)
            if hasattr(self, 'secure_messaging'):
                peers = self.node.get_peers()
                if peers and any(peer in self.secure_messaging.shared_keys for peer in peers):
                    logger.info(f"Node {self.name}: Shared key detected after timeout - setting completion event")
                    self.key_exchange_complete.set()
                    return True

            return False

    async def wait_for_message(self, timeout: float = 5.0) -> bool:
        """Wait for a message to be received.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if message received in time, False otherwise
        """
        try:
            await asyncio.wait_for(self.message_received.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Node {self.name}: Timeout waiting for message receipt")
            return False
    
    async def wait_for_file(self, timeout: float = 10.0) -> bool:
        """Wait for a file to be received.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if file received in time, False otherwise
        """
        try:
            await asyncio.wait_for(self.file_received.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Node {self.name}: Timeout waiting for file receipt")
            return False
    
    async def stop(self):
        """Stop the node and clean up resources."""
        if hasattr(self, 'node'):
            try:
                await self.node.stop()
            except Exception as e:
                logger.error(f"Error stopping node {self.name}: {e}")
        
        # Cancel the node task if it exists
        if hasattr(self, 'node_task') and not self.node_task.done():
            self.node_task.cancel()
            try:
                await self.node_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error canceling node task for {self.name}: {e}")
        
        logger.info(f"Node {self.name} stopped")


@dataclass
class TestResult:
    """Results of a single algorithm combination test."""
    key_exchange: str
    symmetric: str 
    signature: str
    connection_success: bool = False
    key_exchange_success: bool = False
    messaging_success: bool = False
    file_transfer_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    error: Optional[str] = None
    key_exchange_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "key_exchange": self.key_exchange,
            "symmetric": self.symmetric,
            "signature": self.signature,
            "connection_success": self.connection_success,
            "key_exchange_success": self.key_exchange_success,
            "messaging_success": self.messaging_success,
            "file_transfer_results": self.file_transfer_results,
            "error": self.error,
            "key_exchange_time": self.key_exchange_time
        }


class AlgorithmTester:
    """Test framework for different algorithm combinations."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize the tester.
        
        Args:
            base_dir: Base directory for test data (optional)
        """
        # Create temporary directory if no base directory provided
        self.should_cleanup_base_dir = base_dir is None
        if base_dir is None:
            self.base_dir = Path(tempfile.mkdtemp(prefix="qr_p2p_test_"))
        else:
            self.base_dir = base_dir
            self.base_dir.mkdir(exist_ok=True, parents=True)
        
        # Define test algorithms
        self.key_exchange_algorithms = self._create_key_exchange_algorithms()
        self.symmetric_algorithms = self._create_symmetric_algorithms()
        self.signature_algorithms = self._create_signature_algorithms()
        
        # Test file sizes
        self.file_sizes = [
            10 * 1024,       # 10 KB
            100 * 1024,      # 100 KB
            1024 * 1024,     # 1 MB
        ]
        
        # Track test results
        self.results: List[TestResult] = []
        
        # Track active tasks for proper cleanup
        self.active_tasks = []
    
    def _create_key_exchange_algorithms(self) -> Dict[str, Callable[[], KeyExchangeAlgorithm]]:
        """Create dict of key exchange algorithm constructors."""
        return {
            "ML-KEM (Level 1)": lambda: MLKEMKeyExchange(security_level=1),
            "ML-KEM (Level 3)": lambda: MLKEMKeyExchange(security_level=3),
            "ML-KEM (Level 5)": lambda: MLKEMKeyExchange(security_level=5),
            "HQC (Level 1)": lambda: HQCKeyExchange(security_level=1),
            "HQC (Level 3)": lambda: HQCKeyExchange(security_level=3),
            "HQC (Level 5)": lambda: HQCKeyExchange(security_level=5),
            "FrodoKEM (Level 1)": lambda: FrodoKEMKeyExchange(security_level=1),
            "FrodoKEM (Level 3)": lambda: FrodoKEMKeyExchange(security_level=3),
            "FrodoKEM (Level 5)": lambda: FrodoKEMKeyExchange(security_level=5),
        }
    
    def _create_symmetric_algorithms(self) -> Dict[str, Callable[[], SymmetricAlgorithm]]:
        """Create dict of symmetric algorithm constructors."""
        return {
            "AES-256-GCM": lambda: AES256GCM(),
            "ChaCha20-Poly1305": lambda: ChaCha20Poly1305(),
        }
    
    def _create_signature_algorithms(self) -> Dict[str, Callable[[], SignatureAlgorithm]]:
        """Create dict of signature algorithm constructors."""
        return {
            "ML-DSA (Level 2)": lambda: MLDSASignature(security_level=2),
            "ML-DSA (Level 3)": lambda: MLDSASignature(security_level=3),
            "ML-DSA (Level 5)": lambda: MLDSASignature(security_level=5),
            "SPHINCS+ (Level 1)": lambda: SPHINCSSignature(security_level=1),
            "SPHINCS+ (Level 3)": lambda: SPHINCSSignature(security_level=3),
            "SPHINCS+ (Level 5)": lambda: SPHINCSSignature(security_level=5),
        }
    
    def cleanup(self) -> None:
        """Clean up temporary files and directories."""
        # Cancel all active tasks
        for task in self.active_tasks:
            if not task.done():
                task.cancel()
        
        # Clean up temporary directory if needed
        if self.should_cleanup_base_dir and self.base_dir.exists():
            try:
                shutil.rmtree(self.base_dir)
                logger.info(f"Cleaned up base directory: {self.base_dir}")
            except Exception as e:
                logger.error(f"Error cleaning up base directory: {e}")
    
    async def run_tests(self) -> None:
        """Run tests for all algorithm combinations."""
        # Create server and client nodes
        server_node = TestNode(8000, "server", self.base_dir)
        client_node = TestNode(8001, "client", self.base_dir)

        try:
            # Start both nodes concurrently
            print("Starting nodes...")
            await asyncio.gather(
                server_node.start(),
                client_node.start()
            )
            
            # Create test files
            test_files = self._create_test_files()
            
            # Calculate total combinations for progress display
            total_combinations = (
                len(self.key_exchange_algorithms) * 
                len(self.symmetric_algorithms) * 
                len(self.signature_algorithms)
            )
            
            print(f"Testing {total_combinations} algorithm combinations...")
            print(f"Key Exchange: {len(self.key_exchange_algorithms)} algorithms")
            print(f"Symmetric: {len(self.symmetric_algorithms)} algorithms")
            print(f"Signature: {len(self.signature_algorithms)} algorithms")
            print()
            
            current_combination = 0

            # Run tests for all algorithm combinations
            for ke_name, ke_factory in self.key_exchange_algorithms.items():
                for sym_name, sym_factory in self.symmetric_algorithms.items():
                    for sig_name, sig_factory in self.signature_algorithms.items():
                        current_combination += 1
                        
                        print(f"Testing combination {current_combination}/{total_combinations}: "
                              f"{ke_name}, {sym_name}, {sig_name}")
                        
                        # Create result object
                        result = TestResult(
                            key_exchange=ke_name,
                            symmetric=sym_name,
                            signature=sig_name
                        )
                        
                        try:
                            # Configure both nodes with these algorithms
                            await self._configure_algorithms(
                                server_node, client_node, 
                                ke_factory, sym_factory, sig_factory,
                                ke_name, sym_name, sig_name
                            )
                            
                            # Connect client to server
                            connected = await client_node.connect_to(8000)
                            result.connection_success = connected
                            
                            if connected:
                                # Perform key exchange
                                start_time = time.time()
                                key_exchanged = await self._perform_key_exchange(
                                    client_node, server_node
                                )
                                result.key_exchange_time = time.time() - start_time
                                result.key_exchange_success = key_exchanged
                                
                                if key_exchanged:
                                    # Test basic messaging
                                    messaging_ok = await self._test_messaging(
                                        client_node, server_node
                                    )
                                    result.messaging_success = messaging_ok
                                    
                                    # Test file transfers
                                    if messaging_ok:
                                        file_results = await self._test_file_transfers(
                                            client_node, server_node, test_files
                                        )
                                        result.file_transfer_results = file_results
                        
                        except Exception as e:
                            logger.error(f"Error testing {ke_name}/{sym_name}/{sig_name}: {e}")
                            result.error = str(e)
                            traceback.print_exc()
                        
                        # Add result to results list
                        self.results.append(result)
                        
                        # Reset for next test
                        await self._reset_connections(client_node, server_node)
            
            # Generate report
            self._generate_report()
            
        finally:
            # Clean up the nodes
            print("Stopping nodes...")
            await asyncio.gather(
                server_node.stop(),
                client_node.stop(),
                return_exceptions=True
            )
            
            # Make sure to cancel all tasks we created
            self.cleanup()
    
    async def _configure_algorithms(
        self, 
        server_node: TestNode, 
        client_node: TestNode,
        ke_factory: Callable[[], KeyExchangeAlgorithm],
        sym_factory: Callable[[], SymmetricAlgorithm],
        sig_factory: Callable[[], SignatureAlgorithm],
        ke_name: str,
        sym_name: str,
        sig_name: str
    ) -> None:
        """Configure both nodes with the specified algorithms.
        
        Args:
            server_node: The server node
            client_node: The client node
            ke_factory: Factory function to create key exchange algorithm
            sym_factory: Factory function to create symmetric algorithm
            sig_factory: Factory function to create signature algorithm
            ke_name: Name of key exchange algorithm (for logging)
            sym_name: Name of symmetric algorithm (for logging)
            sig_name: Name of signature algorithm (for logging)
        """
        logger.info(f"Configuring nodes with: {ke_name}, {sym_name}, {sig_name}")
        
        # Clear event flags
        server_node.key_exchange_complete.clear()
        client_node.key_exchange_complete.clear()
        
        # Configure server with fresh algorithm instances
        server_node.secure_messaging.set_key_exchange_algorithm(ke_factory())
        server_node.secure_messaging.set_symmetric_algorithm(sym_factory())
        server_node.secure_messaging.set_signature_algorithm(sig_factory())
        
        # Configure client with fresh algorithm instances 
        client_node.secure_messaging.set_key_exchange_algorithm(ke_factory())
        client_node.secure_messaging.set_symmetric_algorithm(sym_factory())
        client_node.secure_messaging.set_signature_algorithm(sig_factory())
        
        # Wait a tiny bit for settings to apply
        await asyncio.sleep(0.1)
    
    async def _perform_key_exchange(self, client_node: TestNode, server_node: TestNode) -> bool:
        """Perform key exchange between client and server.

        Args:
            client_node: The client node
            server_node: The server node

        Returns:
            True if key exchange succeeded, False otherwise
        """
        logger.info(f"Initiating key exchange from {client_node.name} to {server_node.name}")

        try:
            # First synchronize crypto settings between peers
            await client_node.secure_messaging.request_crypto_settings_from_peer(server_node.node_id)
            await server_node.secure_messaging.request_crypto_settings_from_peer(client_node.node_id)

            # Wait for settings to be synchronized (max 3 attempts with increasing delay)
            for attempt in range(3):
                await asyncio.sleep(0.2 * (attempt + 1))

                client_knows_server = (
                    server_node.node_id in client_node.secure_messaging.peer_crypto_settings and
                    "key_exchange" in client_node.secure_messaging.peer_crypto_settings[server_node.node_id]
                )

                server_knows_client = (
                    client_node.node_id in server_node.secure_messaging.peer_crypto_settings and
                    "key_exchange" in server_node.secure_messaging.peer_crypto_settings[client_node.node_id]
                )

                if client_knows_server and server_knows_client:
                    logger.info("Crypto settings successfully exchanged between peers")
                    break

                if attempt < 2:
                    logger.warning(f"Waiting for crypto settings exchange (attempt {attempt+1})")

                # Resend settings on each attempt
                await client_node.secure_messaging.notify_peers_of_settings_change()
                await server_node.secure_messaging.notify_peers_of_settings_change()

            # Reset key exchange completion events
            client_node.key_exchange_complete.clear()
            server_node.key_exchange_complete.clear()

            # Initiate key exchange from client to server
            success = await client_node.secure_messaging.initiate_key_exchange(server_node.node_id)
            if not success:
                logger.warning("Key exchange initiation failed")
                return False

            # Wait for key exchange completion events with timeout (both sides)
            client_success = await client_node.wait_for_key_exchange(timeout=5.0)
            if not client_success:
                logger.warning("Client didn't receive key exchange confirmation")

            server_success = await server_node.wait_for_key_exchange(timeout=5.0)
            if not server_success:
                logger.warning("Server didn't receive key exchange confirmation")

            # Verify that both nodes have the shared key (this is the most reliable check)
            client_has_key = server_node.node_id in client_node.secure_messaging.shared_keys
            server_has_key = client_node.node_id in server_node.secure_messaging.shared_keys

            logger.info(f"Key exchange results - Client has key: {client_has_key}, Server has key: {server_has_key}")

            # For tests, we explicitly check for both nodes having the key
            # Even if the event notifications weren't properly received
            return client_has_key and server_has_key

        except Exception as e:
            logger.error(f"Error during key exchange: {e}")
            return False
    
    async def _test_messaging(self, client_node: TestNode, server_node: TestNode) -> bool:
        """Test messaging between client and server.
        
        Args:
            client_node: The client node
            server_node: The server node
            
        Returns:
            True if messaging succeeded, False otherwise
        """
        logger.info("Testing basic messaging")
        
        try:
            # Clear previous messages and message receipt events
            client_node.received_messages.clear()
            server_node.received_messages.clear()
            client_node.message_received.clear()
            server_node.message_received.clear()
            
            # Send message from client to server
            client_message = f"Test message from {client_node.name} at {time.time()}"
            client_to_server = await client_node.send_message(server_node.node_id, client_message)
            
            # Wait for server to receive message
            if client_to_server:
                server_got_message = await server_node.wait_for_message(timeout=3.0)
            else:
                server_got_message = False
            
            # Send message from server to client
            server_message = f"Test message from {server_node.name} at {time.time()}"
            server_to_client = await server_node.send_message(client_node.node_id, server_message)
            
            # Wait for client to receive message
            if server_to_client:
                client_got_message = await client_node.wait_for_message(timeout=3.0)
            else:
                client_got_message = False
            
            logger.info(f"Messaging results - Client to server: {client_to_server}, Server to client: {server_to_client}")
            logger.info(f"Message reception - Client received: {client_got_message}, Server received: {server_got_message}")
            
            # Both messages sent successfully and both messages received
            return client_to_server and server_to_client and client_got_message and server_got_message
            
        except Exception as e:
            logger.error(f"Error during messaging test: {e}")
            return False
    
    def _create_test_files(self) -> Dict[str, Path]:
        """Create test files of various sizes.
        
        Returns:
            Dictionary mapping file identifiers to file paths
        """
        test_files = {}
        
        file_dir = self.base_dir / "test_files"
        file_dir.mkdir(exist_ok=True, parents=True)
        
        for size in self.file_sizes:
            file_name = f"test_file_{size}bytes.dat"
            file_path = file_dir / file_name
            
            # Create random data file
            with open(file_path, "wb") as f:
                f.write(os.urandom(size))
            
            # Store in dictionary
            key = f"{size // 1024}KB"
            test_files[key] = file_path
            
            logger.info(f"Created test file: {file_path} ({size} bytes)")
        
        return test_files
    
    async def _test_file_transfers(
        self, 
        client_node: TestNode, 
        server_node: TestNode,
        test_files: Dict[str, Path]
    ) -> Dict[str, Dict[str, Any]]:
        """Test file transfers between client and server.
        
        Args:
            client_node: The client node
            server_node: The server node
            test_files: Dictionary of test files to send
            
        Returns:
            Dictionary of file transfer results
        """
        logger.info("Testing file transfers")
        results = {}
        
        for file_id, file_path in test_files.items():
            # Clear previous files and file receipt events
            client_node.received_files.clear()
            server_node.received_files.clear()
            client_node.file_received.clear()
            server_node.file_received.clear()
            
            try:
                # Get file size
                file_size = file_path.stat().st_size
                
                # Client to server transfer
                logger.info(f"Sending {file_id} file from client to server")
                start_time = time.time()
                c2s_success = await client_node.send_file(
                    server_node.node_id, str(file_path)
                )
                c2s_duration = time.time() - start_time
                
                # Wait for server to receive file
                if c2s_success:
                    c2s_received = await server_node.wait_for_file(timeout=5.0)
                else:
                    c2s_received = False
                
                if c2s_received:
                    c2s_throughput = file_size / c2s_duration / 1024  # KB/s
                else:
                    c2s_throughput = 0
                
                # Server to client transfer
                logger.info(f"Sending {file_id} file from server to client")
                start_time = time.time()
                s2c_success = await server_node.send_file(
                    client_node.node_id, str(file_path)
                )
                s2c_duration = time.time() - start_time
                
                # Wait for client to receive file
                if s2c_success:
                    s2c_received = await client_node.wait_for_file(timeout=5.0)
                else:
                    s2c_received = False
                
                if s2c_received:
                    s2c_throughput = file_size / s2c_duration / 1024  # KB/s
                else:
                    s2c_throughput = 0
                
                # Store results
                results[file_id] = {
                    "size": file_size,
                    "client_to_server": {
                        "success": c2s_success,
                        "received": c2s_received,
                        "duration": c2s_duration,
                        "throughput": c2s_throughput
                    },
                    "server_to_client": {
                        "success": s2c_success,
                        "received": s2c_received,
                        "duration": s2c_duration,
                        "throughput": s2c_throughput
                    }
                }
                
                logger.info(f"File transfer results for {file_id}:")
                logger.info(f"  Client to server: {c2s_success}, {c2s_throughput:.2f} KB/s")
                logger.info(f"  Server to client: {s2c_success}, {s2c_throughput:.2f} KB/s")
                
            except Exception as e:
                logger.error(f"Error transferring {file_id} file: {e}")
                results[file_id] = {
                    "error": str(e)
                }
        
        return results
    
    async def _reset_connections(self, client_node: TestNode, server_node: TestNode) -> None:
        """Reset connections between tests.
        
        Args:
            client_node: The client node
            server_node: The server node
        """
        # Get peer IDs
        server_peer_id = server_node.node_id
        client_peer_id = client_node.node_id
        
        # Remove shared keys and states
        if server_peer_id in client_node.secure_messaging.shared_keys:
            del client_node.secure_messaging.shared_keys[server_peer_id]
        if server_peer_id in client_node.secure_messaging.key_exchange_states:
            del client_node.secure_messaging.key_exchange_states[server_peer_id]
            
        if client_peer_id in server_node.secure_messaging.shared_keys:
            del server_node.secure_messaging.shared_keys[client_peer_id]
        if client_peer_id in server_node.secure_messaging.key_exchange_states:
            del server_node.secure_messaging.key_exchange_states[client_peer_id]
        
        # Clear peer crypto settings to ensure fresh start
        if server_peer_id in client_node.secure_messaging.peer_crypto_settings:
            del client_node.secure_messaging.peer_crypto_settings[server_peer_id]
        if client_peer_id in server_node.secure_messaging.peer_crypto_settings:
            del server_node.secure_messaging.peer_crypto_settings[client_peer_id]
        
        # Clear message stores
        client_node.received_messages.clear()
        server_node.received_messages.clear()
        client_node.received_files.clear()
        server_node.received_files.clear()
        
        # Reset all events
        client_node.key_exchange_complete.clear()
        server_node.key_exchange_complete.clear()
        client_node.message_received.clear()
        server_node.message_received.clear()
        client_node.file_received.clear()
        server_node.file_received.clear()
    
    def _generate_report(self) -> None:
        """Generate a report of test results with focus on algorithm comparison."""
        print(f"Generating report in: {self.base_dir}")
        report_file = self.base_dir / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        results_file = self.base_dir / "test_results.json"

        # Save raw results to JSON
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2)
        print(f"Raw results saved to: {results_file}")

        # Generate the formatted report
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"Quantum-Resistant P2P Algorithm Test Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"===============================================\n\n")

            f.write(f"Algorithm Compatibility Results:\n")
            f.write(f"-------------------------------\n")
            f.write(f"{'Key Exchange':<25} {'Symmetric':<20} {'Signature':<20} {'Connect':<10} {'Key Ex':<10} {'Messaging':<10} {'File':<10} {'KE Time(s)':<10}\n")
            f.write(f"{'-'*115}\n")

            # Add rows for each result
            success_count = 0
            total_count = 0

            for result in self.results:
                total_count += 1

                # Determine file transfer success
                file_success = "N/A"
                file_all_success = False

                if result.file_transfer_results:
                    all_success = True
                    for file_info in result.file_transfer_results.values():
                        if "error" in file_info:
                            all_success = False
                            break
                        
                        c2s = file_info.get("client_to_server", {})
                        s2c = file_info.get("server_to_client", {})

                        if not (c2s.get("success", False) and s2c.get("success", False)):
                            all_success = False
                            break

                    file_success = "PASS" if all_success else "FAIL"
                    file_all_success = all_success

                    if all_success:
                        success_count += 1

                # Write the result row
                f.write(f"{result.key_exchange:<25} {result.symmetric:<20} {result.signature:<20} "
                        f"{'PASS' if result.connection_success else 'FAIL':<10} "
                        f"{'PASS' if result.key_exchange_success else 'FAIL':<10} "
                        f"{'PASS' if result.messaging_success else 'FAIL':<10} "
                        f"{file_success:<10} "
                        f"{result.key_exchange_time:.2f}\n")

            # Add summary
            f.write(f"\nSummary: {success_count}/{total_count} combinations successful\n\n")

            # Process file transfer performance data, grouped by symmetric and signature algorithms only
            sym_sig_perf = {}  # (symmetric, signature) -> list of throughputs

            for result in self.results:
                if result.file_transfer_results and result.messaging_success:
                    # Get the combination key - key exchange is ignored!
                    combo_key = (result.symmetric, result.signature)

                    if combo_key not in sym_sig_perf:
                        sym_sig_perf[combo_key] = []

                    # Calculate average throughput across all files for this result
                    total_throughput = 0.0
                    count = 0

                    for file_info in result.file_transfer_results.values():
                        if "error" not in file_info:
                            c2s = file_info.get("client_to_server", {})
                            s2c = file_info.get("server_to_client", {})

                            if c2s.get("throughput", 0) > 0:
                                total_throughput += c2s.get("throughput", 0)
                                count += 1

                            if s2c.get("throughput", 0) > 0:
                                total_throughput += s2c.get("throughput", 0)
                                count += 1

                    if count > 0:
                        avg_throughput = total_throughput / count
                        sym_sig_perf[combo_key].append(avg_throughput)

            # Calculate final averages for each symmetric/signature combination
            final_perf = []
            for (symmetric, signature), throughputs in sym_sig_perf.items():
                # Only include combinations with actual data
                if throughputs:
                    avg_throughput = sum(throughputs) / len(throughputs)
                    final_perf.append({
                        "symmetric": symmetric,
                        "signature": signature,
                        "avg_throughput": avg_throughput,
                    })

            # Sort by throughput (descending)
            final_perf.sort(key=lambda x: x["avg_throughput"], reverse=True)

            # Generate file transfer performance section - ALL combinations
            f.write(f"\nFile Transfer Performance (Averaged by Symmetric+Signature):\n")
            f.write(f"--------------------------------------------------------\n")
            f.write(f"{'Rank':<6} {'Symmetric':<20} {'Signature':<20} {'Avg KB/s':<12}\n")
            f.write(f"{'-'*60}\n")

            # List all combinations
            for i, perf in enumerate(final_perf):
                f.write(f"{i+1:<6} {perf['symmetric']:<20} {perf['signature']:<20} "
                        f"{perf['avg_throughput']:.2f}\n")

            # Get file sizes and ensure proper order
            file_sizes = set()
            for result in self.results:
                for file_id in result.file_transfer_results:
                    file_sizes.add(file_id)

            # Define the proper order
            size_order = ["10KB", "100KB", "1024KB"]
            # Filter and sort file sizes
            ordered_sizes = [size for size in size_order if size in file_sizes]

            # Collect performance data by file size, grouped by symmetric and signature
            file_size_perf = {}
            for file_id in ordered_sizes:
                file_size_perf[file_id] = {}

                # Process all results for this file size
                for result in self.results:
                    if file_id in result.file_transfer_results:
                        file_info = result.file_transfer_results[file_id]

                        if "error" not in file_info:
                            c2s = file_info.get("client_to_server", {})
                            s2c = file_info.get("server_to_client", {})

                            if c2s.get("success", False) and s2c.get("success", False):
                                # Calculate average throughput for this transfer
                                avg_throughput = (c2s.get("throughput", 0) + s2c.get("throughput", 0)) / 2

                                # Get the combination key (symmetric+signature)
                                combo_key = (result.symmetric, result.signature)

                                # Add to the appropriate list
                                if combo_key not in file_size_perf[file_id]:
                                    file_size_perf[file_id][combo_key] = []

                                file_size_perf[file_id][combo_key].append(avg_throughput)

            # Calculate averages and create sorted lists for each file size
            file_size_averages = {}
            for file_id, combinations in file_size_perf.items():
                file_size_averages[file_id] = []

                for (symmetric, signature), throughputs in combinations.items():
                    if throughputs:
                        avg_throughput = sum(throughputs) / len(throughputs)
                        file_size_averages[file_id].append({
                            "symmetric": symmetric,
                            "signature": signature,
                            "avg_throughput": avg_throughput,
                        })

                # Sort by throughput (descending)
                file_size_averages[file_id].sort(key=lambda x: x["avg_throughput"], reverse=True)

            # Write file transfer details for each file size in proper order
            f.write(f"\nFile Transfer Details by File Size:\n")
            f.write(f"----------------------------------\n")

            for file_id in ordered_sizes:
                f.write(f"\nFile Size: {file_id}\n")
                f.write(f"{'-'*25}\n")

                # Get the sorted averages for this file size
                averages = file_size_averages.get(file_id, [])

                if averages:
                    f.write(f"{'Rank':<6} {'Symmetric':<20} {'Signature':<20} {'Avg KB/s':<12}\n")
                    f.write(f"{'-'*60}\n")

                    # Write all combinations
                    for i, avg in enumerate(averages):
                        f.write(f"{i+1:<6} {avg['symmetric']:<20} {avg['signature']:<20} "
                                f"{avg['avg_throughput']:.2f}\n")
                else:
                    f.write("No successful transfers for this file size\n")

        print(f"Report generation complete!")
        print(f"  - Report saved to: {report_file}")
        print(f"  - Raw results saved to: {results_file}")

async def main():
    """Run the comprehensive test suite."""
    print("\n=== Quantum-Resistant P2P Comprehensive Test Suite ===\n")
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Comprehensive testing for Quantum-Resistant P2P")
    parser.add_argument("--output-dir", help="Directory to store test output and results")
    args = parser.parse_args()
    
    # Set up graceful shutdown handler
    loop = asyncio.get_running_loop()
    
    # Install signal handlers for clean shutdown
    if sys.platform != "win32":  # Not Windows
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(loop)))
    else:
        # Windows needs a different approach
        signal.signal(signal.SIGINT, lambda sig, frame: asyncio.create_task(shutdown(loop)))
    
    # Create output directory if specified
    output_dir = None
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True, parents=True)
    
    # Create tester
    tester = AlgorithmTester(output_dir)
    
    try:
        # Run tests
        await tester.run_tests()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Error running tests: {e}")
        traceback.print_exc()
    finally:
        # Clean up
        tester.cleanup()
        
    print("\n=== Test Suite Complete ===\n")
    
    # Ensure the script exits cleanly by forcing it
    # This is a backup measure in case there are any hanging tasks
    os._exit(0)


async def shutdown(loop):
    """Gracefully shut down the application.
    
    Args:
        loop: The event loop
    """
    print("Shutting down gracefully...")
    
    # Cancel all tasks
    pending = asyncio.all_tasks(loop)
    for task in pending:
        if task is not asyncio.current_task():
            task.cancel()
    
    # Wait for all tasks to be cancelled
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    
    # Use os._exit as a last resort to ensure clean exit
    os._exit(0)


if __name__ == "__main__":
    # Run the test suite
    asyncio.run(main())
