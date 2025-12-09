#!/usr/bin/env python3
"""
BGP UPDATE Message Encoding

Implements BGP UPDATE message encoding according to RFC 4271.

Author: Sam Moes
Date: December 2025
"""

import struct
from typing import List, Tuple, Optional


# BGP Message Types (RFC 4271)
BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2
BGP_MSG_NOTIFICATION = 3
BGP_MSG_KEEPALIVE = 4

# BGP UPDATE Message Format:
# Marker (16 bytes) | Length (2 bytes) | Type (1 byte) | Withdrawn Routes | Path Attributes | NLRI


class BGPUpdateMessage:
    """BGP UPDATE message encoder/decoder."""
    
    def __init__(
        self,
        withdrawn_routes: Optional[bytes] = None,
        path_attributes: Optional[List[bytes]] = None,
        nlri: Optional[bytes] = None
    ):
        """
        Initialize BGP UPDATE message.
        
        Args:
            withdrawn_routes: Withdrawn routes (optional)
            path_attributes: List of path attribute encodings
            nlri: Network Layer Reachability Information
        """
        self.withdrawn_routes = withdrawn_routes or b''
        self.path_attributes = path_attributes or []
        self.nlri = nlri or b''
    
    def encode(self) -> bytes:
        """
        Encode BGP UPDATE message.
        
        Returns:
            Complete BGP message bytes
        """
        # BGP message header
        marker = b'\xff' * 16  # All 1s marker
        msg_type = BGP_MSG_UPDATE
        
        # Build message body
        body = self.withdrawn_routes
        
        # Path attributes length (2 bytes)
        total_attr_len = sum(len(attr) for attr in self.path_attributes)
        body += struct.pack('>H', total_attr_len)
        
        # Path attributes
        for attr in self.path_attributes:
            body += attr
        
        # NLRI
        body += self.nlri
        
        # Calculate total message length
        msg_length = 19 + len(body)  # 19 = 16 (marker) + 2 (length) + 1 (type)
        
        # Build complete message
        message = marker + struct.pack('>HB', msg_length, msg_type) + body
        
        return message
    
    @classmethod
    def decode(cls, data: bytes) -> 'BGPUpdateMessage':
        """Decode BGP UPDATE message from bytes."""
        if len(data) < 19:
            raise ValueError("BGP message too short")
        
        # Check marker
        marker = data[:16]
        if marker != b'\xff' * 16:
            raise ValueError("Invalid BGP marker")
        
        # Read length and type
        msg_length, msg_type = struct.unpack_from('>HB', data, 16)
        
        if msg_type != BGP_MSG_UPDATE:
            raise ValueError(f"Not an UPDATE message: type {msg_type}")
        
        if len(data) < msg_length:
            raise ValueError(f"Message truncated: got {len(data)}, expected {msg_length}")
        
        # Parse body
        offset = 19  # Skip header
        
        # Withdrawn routes (variable length, ends with length prefix)
        # For simplicity, assume no withdrawn routes in this PoC
        withdrawn_routes = b''
        
        # Path attributes length
        if offset + 2 > len(data):
            raise ValueError("Insufficient data for path attributes length")
        
        attr_length, = struct.unpack_from('>H', data, offset)
        offset += 2
        
        # Path attributes
        path_attributes = []
        attr_end = offset + attr_length
        while offset < attr_end:
            # Read attribute header
            if offset + 2 > attr_end:
                break
            
            flags, attr_type = struct.unpack_from('>BB', data, offset)
            offset += 2
            
            # Read attribute length
            if flags & 0x10:  # Extended length
                if offset + 2 > attr_end:
                    break
                attr_len, = struct.unpack_from('>H', data, offset)
                offset += 2
            else:
                if offset + 1 > attr_end:
                    break
                attr_len, = struct.unpack_from('>B', data, offset)
                offset += 1
            
            # Read attribute data
            if offset + attr_len > attr_end:
                break
            
            attr_data = data[offset:offset + attr_len]
            path_attributes.append(data[offset - (2 if flags & 0x10 else 1) - 2:offset + attr_len])
            offset += attr_len
        
        # NLRI (rest of message)
        nlri = data[offset:msg_length]
        
        return cls(
            withdrawn_routes=withdrawn_routes,
            path_attributes=path_attributes,
            nlri=nlri
        )


def encode_nlri(prefixes: List[Tuple[str, int]]) -> bytes:
    """
    Encode NLRI (Network Layer Reachability Information).
    
    Args:
        prefixes: List of (prefix, prefix_length) tuples
                 e.g., [("192.0.2.0", 24), ("203.0.113.0", 24)]
    
    Returns:
        Encoded NLRI bytes
    """
    nlri = b''
    
    for prefix_str, prefix_len in prefixes:
        # Convert IP address to bytes
        parts = prefix_str.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 prefix: {prefix_str}")
        
        ip_bytes = bytes(int(p) for p in parts)
        
        # NLRI format: Length (1 byte) | Prefix (variable)
        # Length is in bits, prefix is padded to byte boundary
        prefix_bytes_needed = (prefix_len + 7) // 8
        prefix_bytes = ip_bytes[:prefix_bytes_needed]
        
        nlri += struct.pack('>B', prefix_len) + prefix_bytes
    
    return nlri


def decode_nlri(data: bytes) -> List[Tuple[str, int]]:
    """Decode NLRI from bytes."""
    prefixes = []
    offset = 0
    
    while offset < len(data):
        if offset + 1 > len(data):
            break
        
        prefix_len, = struct.unpack_from('>B', data, offset)
        offset += 1
        
        prefix_bytes_needed = (prefix_len + 7) // 8
        if offset + prefix_bytes_needed > len(data):
            break
        
        prefix_bytes = data[offset:offset + prefix_bytes_needed]
        offset += prefix_bytes_needed
        
        # Pad to 4 bytes for IPv4
        while len(prefix_bytes) < 4:
            prefix_bytes += b'\x00'
        
        prefix_str = '.'.join(str(b) for b in prefix_bytes[:4])
        prefixes.append((prefix_str, prefix_len))
    
    return prefixes

