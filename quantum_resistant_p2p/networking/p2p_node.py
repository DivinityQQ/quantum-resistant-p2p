"""
P2P Node implementation for quantum-resistant P2P communication.
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Callable, Any, Tuple, Set
import uuid

logger = logging.getLogger(__name__)


class P2PNode:
    """A peer-to-peer network node supporting direct communication between peers.
    
    This class provides functionality for establishing connections with other
    P2P nodes, sending and receiving messages, and handling connection events.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8000, node_id: Optional[str] = None):
        """Initialize a new P2P node.
        
        Args:
            host: The host IP address to bind to
            port: The port number to listen on
            node_id: Unique identifier for this node. If None, a random UUID is generated.
        """
        self.host = host
        self.port = port
        self.node_id = node_id or str(uuid.uuid4())
        self.peers: Dict[str, Tuple[str, int]] = {}  # node_id -> (host, port)
        self.connections: Dict[str, asyncio.StreamWriter] = {}  # node_id -> writer
        self.server = None
        self.message_handlers: Dict[str, List[Callable]] = {}
        # New: Connection event handlers
        self.connection_handlers: Set[Callable[[str], None]] = set()
        self.running = False
        
        logger.info(f"P2P Node initialized with ID: {self.node_id}")
    
    async def start(self) -> None:
        """Start the P2P node server."""
        self.server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        
        self.running = True
        logger.info(f"P2P Node {self.node_id} listening on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self) -> None:
        """Stop the P2P node server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
            
            # Close all connections
            for writer in self.connections.values():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    logger.error(f"Error closing connection: {e}")
            
            self.connections.clear()
            logger.info(f"P2P Node {self.node_id} stopped")
    
    def register_connection_handler(self, handler: Callable[[str], None]) -> None:
        """Register a handler for new peer connections.
        
        Args:
            handler: Function to call when a new peer connects. Takes peer_id as parameter.
        """
        self.connection_handlers.add(handler)
        logger.debug(f"Registered connection handler {id(handler)}")
    
    async def _notify_connection_handlers(self, peer_id: str) -> None:
        """Notify all registered connection handlers about a new connection.
        
        Args:
            peer_id: The ID of the newly connected peer
        """
        for handler in self.connection_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(peer_id)
                else:
                    handler(peer_id)
            except Exception as e:
                logger.error(f"Error in connection handler for peer {peer_id}: {e}")
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle an incoming connection from a peer.
        
        Args:
            reader: Stream reader for the connection
            writer: Stream writer for the connection
        """
        peer_address = writer.get_extra_info('peername')
        logger.info(f"New connection from {peer_address}")
        
        try:
            # Read the initial message containing peer ID
            data = await reader.readline()
            if not data:
                logger.error(f"No data received from {peer_address}, closing connection")
                writer.close()
                return
                
            try:
                message = json.loads(data.decode())
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON received from {peer_address}, closing connection")
                writer.close()
                return
            
            if 'node_id' not in message:
                logger.error(f"Invalid initial message from {peer_address}, missing node_id")
                writer.close()
                return
            
            peer_id = message['node_id']
            peer_host, peer_port = peer_address
            
            # Send our own hello message if not already sent
            if message.get('type') == 'hello':
                response = {
                    'node_id': self.node_id,
                    'type': 'hello_response'
                }
                writer.write(json.dumps(response).encode() + b'\n')
                await writer.drain()
                logger.debug(f"Sent hello response to {peer_id}")
            
            # Store peer information
            self.peers[peer_id] = (peer_host, peer_port)
            self.connections[peer_id] = writer
            
            logger.info(f"Registered peer {peer_id} at {peer_host}:{peer_port}")
            
            # Notify connection handlers about the new peer
            await self._notify_connection_handlers(peer_id)
            
            # Handle incoming messages
            while True:
                data = await reader.readline()
                if not data:
                    logger.info(f"Connection closed by peer {peer_id}")
                    break
                
                await self._process_message(peer_id, data)
                
        except (asyncio.CancelledError, ConnectionError) as e:
            logger.error(f"Connection error with {peer_address}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error handling connection from {peer_address}: {e}")
        finally:
            # Clean up
            if 'peer_id' in locals():
                if peer_id in self.peers:
                    del self.peers[peer_id]
                if peer_id in self.connections:
                    del self.connections[peer_id]
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Error closing writer: {e}")
            logger.info(f"Connection closed with {peer_address}")
    
    async def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer at the specified host and port.
        
        Args:
            host: The host IP address or hostname of the peer
            port: The port number the peer is listening on
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        logger.info(f"Attempting to connect to peer at {host}:{port}")
        
        # First check if we're already connected to this peer by host and port
        for peer_id, (peer_host, peer_port) in self.peers.items():
            if peer_host == host and peer_port == port:
                logger.info(f"Already connected to peer {peer_id} at {host}:{port}")
                return True
        
        try:
            reader, writer = await asyncio.open_connection(host, port)
            
            # Send initial message with our node ID
            initial_message = {
                'node_id': self.node_id,
                'type': 'hello'
            }
            message_json = json.dumps(initial_message).encode() + b'\n'
            writer.write(message_json)
            await writer.drain()
            logger.debug(f"Sent hello message to {host}:{port}")
            
            # Read peer's response to get their node ID
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not data:
                    logger.error(f"No response from peer at {host}:{port}")
                    writer.close()
                    return False
            except asyncio.TimeoutError:
                logger.error(f"Timeout waiting for response from {host}:{port}")
                writer.close()
                return False
            
            try:
                message = json.loads(data.decode())
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON response from peer at {host}:{port}")
                writer.close()
                return False
            
            if 'node_id' not in message:
                logger.error(f"Invalid response from peer at {host}:{port}, missing node_id")
                writer.close()
                return False
            
            peer_id = message['node_id']
            
            # Don't connect to ourselves
            if peer_id == self.node_id:
                logger.warning(f"Attempted to connect to ourselves at {host}:{port}")
                writer.close()
                return False
            
            # Store peer information
            self.peers[peer_id] = (host, port)
            self.connections[peer_id] = writer
            
            logger.info(f"Connected to peer {peer_id} at {host}:{port}")
            
            # Start a task to handle messages from this peer
            asyncio.create_task(self._handle_peer_messages(peer_id, reader))
            
            # Notify connection handlers
            await self._notify_connection_handlers(peer_id)
            
            return True
            
        except (OSError, asyncio.TimeoutError) as e:
            logger.error(f"Failed to connect to peer at {host}:{port}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to peer at {host}:{port}: {e}")
            return False
    
    async def _handle_peer_messages(self, peer_id: str, reader: asyncio.StreamReader) -> None:
        """Handle messages from a connected peer.
        
        Args:
            peer_id: The ID of the peer
            reader: The stream reader for the connection
        """
        try:
            while True:
                data = await reader.readline()
                if not data:
                    logger.info(f"Connection closed by peer {peer_id}")
                    break
                
                await self._process_message(peer_id, data)
                
        except (asyncio.CancelledError, ConnectionError) as e:
            logger.error(f"Error reading from peer {peer_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error handling messages from peer {peer_id}: {e}")
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]
            if peer_id in self.connections:
                self.connections[peer_id].close()
                del self.connections[peer_id]
            
            logger.info(f"Connection with peer {peer_id} closed")
    
    async def _process_message(self, peer_id: str, data: bytes) -> None:
        """Process a message received from a peer.
        
        Args:
            peer_id: The ID of the peer who sent the message
            data: The raw message data
        """
        try:
            message = json.loads(data.decode())
            
            if 'type' not in message:
                logger.warning(f"Received message without type from {peer_id}")
                return
            
            message_type = message['type']
            logger.debug(f"Received message of type {message_type} from {peer_id}")
            
            # Call registered handlers for this message type
            if message_type in self.message_handlers:
                for handler in self.message_handlers[message_type]:
                    try:
                        await handler(peer_id, message)
                    except Exception as e:
                        logger.error(f"Error in message handler for {message_type}: {e}")
            else:
                logger.debug(f"No handler for message type {message_type} from {peer_id}")
                
        except json.JSONDecodeError:
            logger.warning(f"Received invalid JSON from {peer_id}")
        except Exception as e:
            logger.error(f"Error processing message from {peer_id}: {e}")
    
    async def send_message(self, peer_id: str, message_type: str, **kwargs) -> bool:
        """Send a message to a specific peer.
        
        Args:
            peer_id: The ID of the peer to send the message to
            message_type: The type of message being sent
            **kwargs: Additional key-value pairs to include in the message
            
        Returns:
            bool: True if message was sent, False otherwise
        """
        if peer_id not in self.connections:
            logger.error(f"Cannot send message to unknown peer {peer_id}")
            return False
        
        try:
            message = {
                'type': message_type,
                'from': self.node_id,
                **kwargs
            }
            
            writer = self.connections[peer_id]
            writer.write(json.dumps(message).encode() + b'\n')
            await writer.drain()
            
            logger.debug(f"Sent {message_type} message to {peer_id}")
            return True
            
        except (ConnectionError, asyncio.TimeoutError) as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending message to {peer_id}: {e}")
        
        # Remove the peer if we can't send to them
        if peer_id in self.peers:
            del self.peers[peer_id]
        if peer_id in self.connections:
            try:
                self.connections[peer_id].close()
            except Exception:
                pass
            del self.connections[peer_id]
        
        return False
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """Register a handler function for a specific message type.
        
        Args:
            message_type: The type of message to handle
            handler: The callback function to call when a message of this type is received.
                     The function should accept (peer_id, message) as parameters.
        """
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        
        self.message_handlers[message_type].append(handler)
        logger.debug(f"Registered handler for message type {message_type}")
    
    def get_peers(self) -> List[str]:
        """Get a list of connected peer IDs.
        
        Returns:
            List of peer IDs
        """
        return list(self.peers.keys())

    def get_peer_info(self, peer_id: str) -> Optional[Tuple[str, int]]:
        """Get the host and port for a specific peer.
        
        Args:
            peer_id: The ID of the peer
            
        Returns:
            Tuple of (host, port) if the peer exists, None otherwise
        """
        return self.peers.get(peer_id)