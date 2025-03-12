"""
Simple direct localhost testing for P2P application.

This script tests P2P connections directly using localhost addresses,
bypassing discovery for more reliable testing.
"""

import asyncio
import logging
import sys
import os
import time
import uuid
from pathlib import Path

# Add the parent directory to the path so we can import the package
parent_dir = str(Path(__file__).parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from quantum_resistant_p2p.networking import P2PNode
from quantum_resistant_p2p.crypto import KeyStorage
from quantum_resistant_p2p.app import SecureMessaging, SecureLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("localhost_test")


class SimpleTestNode:
    """A simplified test node for direct localhost testing."""
    
    def __init__(self, port: int, name: str):
        """Initialize a test node.
        
        Args:
            port: The port for the P2P node
            name: A name for this node
        """
        self.port = port
        self.name = name
        self.node_id = f"{name}-{uuid.uuid4().hex[:8]}"
        
        # Create directories for this instance
        self.base_dir = Path.home() / ".quantum_resistant_p2p" / name
        self.base_dir.mkdir(exist_ok=True, parents=True)
        
        logs_dir = self.base_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.key_storage = KeyStorage(str(self.base_dir / "keys.json"))
        # Always use the same password for test instances
        self.key_storage.unlock("test_password")
        
        self.secure_logger = SecureLogger(str(logs_dir))
        
        # Create P2P node with specified port and our custom node_id
        # Use explicit localhost (127.0.0.1) for testing
        self.node = P2PNode(host='127.0.0.1', port=port, node_id=self.node_id)
        
        # Create secure messaging
        self.secure_messaging = SecureMessaging(
            node=self.node,
            key_storage=self.key_storage,
            logger=self.secure_logger
        )
        
        # Register message handler for secure messages
        self.node.register_message_handler("secure_message", self._handle_message)
        
        print(f"Created test node {self.name}")
        print(f"  Node ID: {self.node_id}")
        print(f"  Listening on: 127.0.0.1:{self.port}")
        
    async def start(self):
        """Start the node."""
        try:
            # Start P2P node
            node_task = asyncio.create_task(self.node.start())
            print(f"Node {self.name}: P2P node started on port {self.port}")
            return node_task
        except Exception as e:
            print(f"Node {self.name}: Error starting node: {e}")
            raise
    
    async def connect_to(self, other_port: int):
        """Connect to another node on localhost.
        
        Args:
            other_port: The port of the other node
        """
        print(f"Node {self.name}: Attempting to connect to localhost:{other_port}...")
        
        try:
            # Attempt connection (with retry)
            for attempt in range(3):
                success = await self.node.connect_to_peer('127.0.0.1', other_port)
                if success:
                    print(f"Node {self.name}: Successfully connected to localhost:{other_port}")
                    return True
                else:
                    print(f"Node {self.name}: Connection attempt {attempt+1} failed")
                    await asyncio.sleep(2)
            
            print(f"Node {self.name}: Failed to connect after 3 attempts")
            return False
        except Exception as e:
            print(f"Node {self.name}: Error connecting to localhost:{other_port}: {e}")
            return False
    
    async def send_message(self, peer_id: str, content: str):
        """Send a message to a peer.
        
        Args:
            peer_id: The ID of the peer
            content: The message content
        """
        print(f"Node {self.name}: Sending message to {peer_id}")
        try:
            success = await self.secure_messaging.send_message(
                peer_id=peer_id,
                content=content.encode('utf-8')
            )
            if success:
                print(f"Node {self.name}: Message sent successfully")
                return True
            else:
                print(f"Node {self.name}: Failed to send message")
                return False
        except Exception as e:
            print(f"Node {self.name}: Error sending message: {e}")
            return False
    
    async def _handle_message(self, peer_id, message):
        """Handle a received message."""
        print(f"\nNode {self.name}: Received message from {peer_id}")
        print(f"  Message type: {message.get('type', 'unknown')}")
        print(f"  From: {message.get('from', 'unknown')}")
        if 'ciphertext' in message:
            print(f"  [Encrypted content received]")
    
    def print_status(self):
        """Print the current status."""
        connected_peers = self.node.get_peers()
        
        print(f"\n--- Node {self.name} Status ---")
        print(f"Node ID: {self.node_id}")
        print(f"Listening on: 127.0.0.1:{self.port}")
        
        print(f"Connected peers ({len(connected_peers)}):")
        for peer_id in connected_peers:
            peer_info = self.node.get_peer_info(peer_id)
            if peer_info:
                host, port = peer_info
                print(f"  {peer_id} at {host}:{port}")
            else:
                print(f"  {peer_id} (no connection info)")
        
        print("-" * 30)


async def test_server(port: int, name: str):
    """Run a test server node.
    
    Args:
        port: The port to listen on
        name: The name for this node
    """
    # Create and start the server node
    server = SimpleTestNode(port, name)
    server_task = await server.start()
    
    # Run the main loop
    try:
        while True:
            server.print_status()
            await asyncio.sleep(5)
    except asyncio.CancelledError:
        print(f"Server {name} task cancelled")
    except KeyboardInterrupt:
        print(f"Server {name} interrupted by user")
    finally:
        # Clean up
        await server.node.stop()


async def test_client(port: int, name: str, server_port: int):
    """Run a test client node.
    
    Args:
        port: The port to listen on
        name: The name for this node
        server_port: The port of the server to connect to
    """
    # Create and start the client node
    client = SimpleTestNode(port, name)
    client_task = await client.start()
    
    # Let the server start fully
    print(f"Waiting for server to start...")
    await asyncio.sleep(3)
    
    # Connect to the server
    connected = await client.connect_to(server_port)
    if not connected:
        print(f"Could not connect to server at port {server_port}")
        print(f"Trying again in 5 seconds...")
        await asyncio.sleep(5)
        connected = await client.connect_to(server_port)
    
    # If connected, get the server's peer ID
    server_peer_id = None
    if connected:
        peers = client.node.get_peers()
        if peers:
            server_peer_id = peers[0]
            print(f"Connected to server with ID: {server_peer_id}")
    
    # Run the main loop
    try:
        message_counter = 0
        while True:
            client.print_status()
            
            # If connected to the server, send a message every few iterations
            if server_peer_id and message_counter % 3 == 0:
                message = f"Hello from {client.name} at {time.time()}"
                await client.send_message(server_peer_id, message)
            
            message_counter += 1
            await asyncio.sleep(5)
    except asyncio.CancelledError:
        print(f"Client {name} task cancelled")
    except KeyboardInterrupt:
        print(f"Client {name} interrupted by user")
    finally:
        # Clean up
        await client.node.stop()


async def main():
    """Main function to run the test."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python localhost_test.py server <port>")
        print("  python localhost_test.py client <port> <server_port>")
        return
    
    mode = sys.argv[1].lower()
    
    if mode == 'server':
        if len(sys.argv) < 3:
            print("Please specify a port for the server")
            return
        port = int(sys.argv[2])
        await test_server(port, "server")
    elif mode == 'client':
        if len(sys.argv) < 4:
            print("Please specify client port and server port")
            return
        port = int(sys.argv[2])
        server_port = int(sys.argv[3])
        await test_client(port, "client", server_port)
    else:
        print(f"Unknown mode: {mode}")
        print("Use 'server' or 'client'")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest terminated by user")