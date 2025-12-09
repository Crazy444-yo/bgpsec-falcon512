#!/usr/bin/env python3
"""
BGPsec Core Implementation with Falcon-512

Implements BGPsec (RFC 8205) Secure_Path attribute and Signature_Block
encoding/decoding with Falcon-512 post-quantum signatures.

Author: Sam Moes
Date: December 2025
"""

import struct
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass
from oqs import Signature

# BGPsec Suite IDs (RFC 8205)
# Standard suite IDs:
BGPsec_SUITE_ECDSA_P256 = 0x01
BGPsec_SUITE_ECDSA_P384 = 0x02

# Custom suite ID for Falcon-512 (pending IETF standardization)
# Using 0x03 as temporary PoC suite ID
BGPsec_SUITE_FALCON512 = 0x03

# BGPsec Attribute Flags (RFC 8205)
BGPsec_ATTR_FLAG_OPTIONAL = 0x80
BGPsec_ATTR_FLAG_TRANSITIVE = 0x40
BGPsec_ATTR_FLAG_PARTIAL = 0x20
BGPsec_ATTR_FLAG_EXTENDED_LENGTH = 0x10

# BGPsec Attribute Type Code (RFC 8205)
BGPsec_ATTR_TYPE_CODE = 17  # Secure_Path attribute type


@dataclass
class SecurePathSegment:
    """Represents one segment in the Secure_Path attribute."""
    as_number: int  # 32-bit AS number
    p_count: int    # pCount (number of signatures in this segment)
    flags: int      # Flags (currently unused, set to 0)
    
    def encode(self) -> bytes:
        """Encode Secure_Path segment as per RFC 8205."""
        # Secure_Path segment format:
        # AS (4 bytes) | pCount (1 byte) | Flags (1 byte)
        return struct.pack('>IBB', self.as_number, self.p_count, self.flags)
    
    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> Tuple['SecurePathSegment', int]:
        """Decode Secure_Path segment from bytes."""
        if len(data) < offset + 6:
            raise ValueError("Insufficient data for Secure_Path segment")
        
        as_number, p_count, flags = struct.unpack_from('>IBB', data, offset)
        return cls(as_number=as_number, p_count=p_count, flags=flags), offset + 6


@dataclass
class SignatureBlock:
    """Represents a Signature_Block in BGPsec."""
    suite_id: int      # Cryptographic suite ID
    signature: bytes   # Signature bytes
    
    def encode(self) -> bytes:
        """Encode Signature_Block as per RFC 8205."""
        # Signature_Block format:
        # Suite ID (1 byte) | Signature Length (2 bytes) | Signature (variable)
        sig_len = len(self.signature)
        if sig_len > 65535:
            raise ValueError(f"Signature too large: {sig_len} bytes")
        
        return struct.pack('>BH', self.suite_id, sig_len) + self.signature
    
    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> Tuple['SignatureBlock', int]:
        """Decode Signature_Block from bytes."""
        if len(data) < offset + 3:
            raise ValueError("Insufficient data for Signature_Block header")
        
        suite_id, sig_len = struct.unpack_from('>BH', data, offset)
        offset += 3
        
        if len(data) < offset + sig_len:
            raise ValueError(f"Insufficient data for signature: need {sig_len} bytes")
        
        signature = data[offset:offset + sig_len]
        return cls(suite_id=suite_id, signature=signature), offset + sig_len


@dataclass
class SecurePathAttribute:
    """Complete BGPsec Secure_Path attribute."""
    segments: List[SecurePathSegment]
    signature_blocks: List[List[SignatureBlock]]  # One list per segment
    
    def encode(self) -> bytes:
        """Encode complete Secure_Path attribute as per RFC 8205."""
        # Attribute format:
        # Flags (1 byte) | Type Code (1 byte) | Length (1 or 2 bytes) | Data
        
        # Build data portion
        data = b''
        
        # Encode segments
        for segment in self.segments:
            data += segment.encode()
        
        # Encode signature blocks (one per segment)
        for sig_blocks in self.signature_blocks:
            for sig_block in sig_blocks:
                data += sig_block.encode()
        
        # Calculate total length
        attr_length = len(data)
        
        # BGP path attributes have a maximum length of 65535 bytes (RFC 4271)
        # This is a hard limit for a single path attribute
        MAX_ATTR_LENGTH = 65535
        if attr_length > MAX_ATTR_LENGTH:
            raise ValueError(
                f"Secure_Path attribute exceeds BGP maximum attribute length: "
                f"{attr_length} bytes > {MAX_ATTR_LENGTH} bytes. "
                f"This path has {len(self.segments)} hops. "
                f"BGP specification (RFC 4271) limits single path attributes to 65535 bytes."
            )
        
        # Build attribute header
        flags = BGPsec_ATTR_FLAG_OPTIONAL | BGPsec_ATTR_FLAG_TRANSITIVE
        if attr_length > 255:
            flags |= BGPsec_ATTR_FLAG_EXTENDED_LENGTH
        
        header = struct.pack('>BB', flags, BGPsec_ATTR_TYPE_CODE)
        
        if attr_length > 255:
            # Extended length (2 bytes)
            header += struct.pack('>H', attr_length)
        else:
            # Short length (1 byte)
            header += struct.pack('>B', attr_length)
        
        return header + data
    
    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> Tuple['SecurePathAttribute', int]:
        """Decode Secure_Path attribute from bytes."""
        if len(data) < offset + 2:
            raise ValueError("Insufficient data for attribute header")
        
        flags, attr_type = struct.unpack_from('>BB', data, offset)
        offset += 2
        
        if attr_type != BGPsec_ATTR_TYPE_CODE:
            raise ValueError(f"Not a Secure_Path attribute: type {attr_type}")
        
        # Read length
        if flags & BGPsec_ATTR_FLAG_EXTENDED_LENGTH:
            if len(data) < offset + 2:
                raise ValueError("Insufficient data for extended length")
            attr_length, = struct.unpack_from('>H', data, offset)
            offset += 2
        else:
            if len(data) < offset + 1:
                raise ValueError("Insufficient data for length")
            attr_length, = struct.unpack_from('>B', data, offset)
            offset += 1
        
        # Read attribute data
        if len(data) < offset + attr_length:
            raise ValueError(f"Insufficient data for attribute: need {attr_length} bytes")
        
        attr_data = data[offset:offset + attr_length]
        offset += attr_length
        
        # Parse segments and signature blocks
        segments = []
        signature_blocks = []
        
        data_offset = 0
        # First pass: read all segments
        while data_offset < len(attr_data):
            try:
                segment, new_offset = SecurePathSegment.decode(attr_data, data_offset)
                segments.append(segment)
                data_offset = new_offset
            except (ValueError, struct.error):
                break
        
        # Second pass: read signature blocks based on pCount values
        for segment in segments:
            sig_blocks = []
            for _ in range(segment.p_count):
                try:
                    sig_block, new_offset = SignatureBlock.decode(attr_data, data_offset)
                    sig_blocks.append(sig_block)
                    data_offset = new_offset
                except (ValueError, struct.error):
                    break
            signature_blocks.append(sig_blocks)
        
        return cls(segments=segments, signature_blocks=signature_blocks), offset


class BGPsecPathSigner:
    """Signs BGPsec paths with Falcon-512."""
    
    def __init__(self):
        """Initialize BGPsec path signer."""
        self.suite_id = BGPsec_SUITE_FALCON512
    
    def create_signer_with_keypair(self) -> Tuple[Signature, bytes]:
        """
        Create a new Signature object with its own keypair.
        
        Returns:
            (signer, public_key) tuple
            Note: The signer object holds the private key internally.
        """
        signer = Signature("Falcon-512")
        keypair_result = signer.generate_keypair()
        
        # Extract public key
        if isinstance(keypair_result, tuple) and len(keypair_result) >= 1:
            public_key = keypair_result[0]
        elif isinstance(keypair_result, tuple):
            public_key = keypair_result[0]
        else:
            public_key = keypair_result
        
        return signer, public_key
    
    def sign_path_data(self, signer: Signature, data_to_sign: bytes) -> bytes:
        """
        Sign path data using a Signature object.
        
        Args:
            signer: Signature object (with internal private key)
            data_to_sign: Data to sign (Secure_Path | Signature_Block | NLRI)
        
        Returns:
            Signature bytes
        """
        # The signer object has its own internal private key from generate_keypair()
        signature = signer.sign(data_to_sign)
        return signature
    
    def verify_path_signature(self, public_key: bytes, data_signed: bytes, signature: bytes) -> bool:
        """
        Verify a path signature.
        
        Args:
            public_key: Public key
            data_signed: Data that was signed
            signature: Signature to verify
        
        Returns:
            True if signature is valid
        """
        verifier = Signature("Falcon-512")
        try:
            is_valid = verifier.verify(data_signed, signature, public_key)
            return is_valid
        except Exception as e:
            print(f"Verification error: {e}")
            return False


def compute_data_to_sign(
    secure_path: bytes,
    signature_block: bytes,
    nlri: bytes
) -> bytes:
    """
    Compute Data_To_Sign according to RFC 8205.
    
    Data_To_Sign = Secure_Path | Signature_Block | NLRI
    
    Args:
        secure_path: Encoded Secure_Path attribute (up to current hop)
        signature_block: Encoded Signature_Block (up to current hop)
        nlri: Network Layer Reachability Information
    
    Returns:
        Concatenated data to sign
    """
    return secure_path + signature_block + nlri

