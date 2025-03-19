"""
Node discovery implementation for P2P network.
"""

import asyncio
import socket
import json
import logging
from typing import List, Dict, Set, Optional, Tuple, Any
import time

logger = logging.getLogger(__name__)


class NodeDiscovery:
    """Discovery mechanism for P2P nodes on the local network.
    
    This class provides functionality for discovering other nodes in the network
    using UDP broadcast messages. It implements both automatic discovery through
    broadcast messages and manual peer addition.
    """
    
    def __init__(self, node_id: str, host: str = '0.0.0.0', 
                port: int = 8000, discovery_port: int = 8001):
        """Initialize a new node discovery service.
        
        Args:
            node_id: The ID of the node this discovery service is for
            host: The host IP address the node is listening on
            port: The port number the node is listening on
            discovery_port: The port to use for discovery broadcasts
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        self.discovery_port = discovery_port
        self.discovered_nodes: Dict[str, Tuple[str, int, float]] = {}  # node_id -> (host, port, last_seen)
        self.running = False
        self.transport = None
        self.protocol = None
        
        # If host is 0.0.0.0, try to get the actual IP
        if host == '0.0.0.0':
            self.advertised_host = self._get_local_ip()
        else:
            self.advertised_host = host
            
        logger.info(f"Node Discovery initialized for node {node_id}, advertising as {self.advertised_host}:{port}")
    
    def _get_local_ip(self) -> str:
        """Get the local IP address of this machine.
        
        Returns:
            The local IP address as a string
        """
        try:
            # Create a socket to determine the outgoing interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't actually send any packets
            s.connect(('8.8.8.8', 53))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            return '127.0.0.1'  # Fallback to localhost
    
    async def start(self) -> None:
        """Start the discovery service."""
        # Define the protocol
        class DiscoveryProtocol(asyncio.DatagramProtocol):
            def __init__(self, parent):
                self.parent = parent
                self.transport = None
                
            def connection_made(self, transport):
                self.transport = transport
                
            def datagram_received(self, data, addr):
                self.parent._handle_discovery_message(data, addr)
                
            def error_received(self, exc):
                logger.error(f"Discovery protocol error: {exc}")
        
        try:
            # Manual socket approach for better control
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Set SO_REUSEADDR to allow reusing the address
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to the discovery port
            sock.bind(('0.0.0.0', self.discovery_port))
            
            # Set socket to non-blocking mode (needed for asyncio)
            sock.setblocking(False)
            
            # Enable broadcasting (needed for broadcasting announcements)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Create the transport and protocol
            loop = asyncio.get_running_loop()
            self.transport, self.protocol = await loop.create_datagram_endpoint(
                lambda: DiscoveryProtocol(self),
                sock=sock
            )
            
            self.running = True
            logger.info(f"Discovery service started on port {self.discovery_port}")
            
            # Start the announcement and cleanup tasks
            asyncio.create_task(self._periodic_announce())
            asyncio.create_task(self._cleanup_old_nodes())
            
        except Exception as e:
            logger.error(f"Failed to start discovery service: {e}")
            raise
    
    async def stop(self) -> None:
        """Stop the discovery service."""
        if self.transport:
            self.transport.close()
            self.running = False
            logger.info("Discovery service stopped")
    
    def _handle_discovery_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle an incoming discovery message.
        
        Args:
            data: The raw message data
            addr: The address (host, port) the message came from
        """
        try:
            message = json.loads(data.decode())
            
            if 'type' not in message or message['type'] != 'node_announcement':
                logger.debug(f"Received non-announcement message from {addr}")
                return
                
            if 'node_id' not in message or 'port' not in message:
                logger.warning(f"Received invalid announcement from {addr}")
                return
                
            node_id = message['node_id']
            port = message['port']
            host = addr[0]
            
            # Don't record ourselves
            if node_id == self.node_id:
                return
                
            # Update the node in our discovered list
            self.discovered_nodes[node_id] = (host, port, time.time())
            logger.info(f"Discovered node {node_id} at {host}:{port}")
            
        except json.JSONDecodeError:
            logger.warning(f"Received invalid JSON from {addr}")
        except Exception as e:
            logger.error(f"Error handling discovery message: {e}")
    
    async def _periodic_announce(self) -> None:
        """Periodically announce this node's presence to the network."""
        while self.running:
            try:
                self._send_announcement()
                await asyncio.sleep(60)  # Announce every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in announcement task: {e}")
                await asyncio.sleep(60)  # Still wait before trying again
    
    def _send_announcement(self) -> None:
        """Send an announcement message to the network."""
        announcement = {
            'type': 'node_announcement',
            'node_id': self.node_id,
            'host': self.advertised_host,
            'port': self.port
        }
        
        data = json.dumps(announcement).encode()
        
        # Broadcast on the local network
        try:
            broadcast_address = '255.255.255.255'  # Standard broadcast address
            self.transport.sendto(data, (broadcast_address, self.discovery_port))
            logger.debug("Sent node announcement via broadcast")
        except Exception as e:
            logger.error(f"Failed to send broadcast: {e}")

    def _send_direct_announcement(self, host: str, port: int) -> None:
        """Send an announcement message directly to a specific peer.
        
        Args:
            host: The host address to send to
            port: The port to send to (should be discovery_port, not regular port)
        """
        announcement = {
            'type': 'node_announcement',
            'node_id': self.node_id,
            'host': self.advertised_host,
            'port': self.port
        }
        
        data = json.dumps(announcement).encode()
        
        # Send directly to the peer's discovery port
        try:
            self.transport.sendto(data, (host, self.discovery_port))
            logger.debug(f"Sent direct node announcement to {host}:{self.discovery_port}")
        except Exception as e:
            logger.error(f"Failed to send direct announcement to {host}:{self.discovery_port}: {e}")

    async def _cleanup_old_nodes(self) -> None:
        """Periodically clean up nodes that haven't been seen recently."""
        while self.running:
            try:
                current_time = time.time()
                expired_nodes = []
                
                for node_id, (host, port, last_seen) in self.discovered_nodes.items():
                    # If we haven't seen this node in 5 minutes, remove it
                    if current_time - last_seen > 300:
                        expired_nodes.append(node_id)
                
                for node_id in expired_nodes:
                    logger.info(f"Node {node_id} expired from discovery")
                    del self.discovered_nodes[node_id]
                
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(60)  # Still wait before trying again
    
    def get_discovered_nodes(self) -> List[Tuple[str, str, int]]:
        """Get a list of all discovered nodes.
        
        Returns:
            List of tuples (node_id, host, port)
        """
        return [(node_id, host, port) 
                for node_id, (host, port, _) in self.discovered_nodes.items()]
    
    def add_known_node(self, node_id: str, host: str, port: int) -> None:
        """Manually add a known node to the discovery list.
        
        Args:
            node_id: The ID of the node
            host: The host IP address of the node
            port: The port number the node is listening on
        """
        self.discovered_nodes[node_id] = (host, port, time.time())
        logger.info(f"Manually added node {node_id} at {host}:{port}")
