#!/usr/bin/env python3
"""
BGPsec Path Signature Generation and Verification

Implements the path signature algorithm from RFC 8205 for Falcon-512.

Author: Sam Moes
Date: December 2025
"""

from typing import List, Tuple, Optional
from oqs import Signature
from .bgpsec import (
    BGPsecPathSigner,
    SecurePathSegment,
    SignatureBlock,
    SecurePathAttribute,
    compute_data_to_sign,
    BGPsec_SUITE_FALCON512
)
from .bgp_message import encode_nlri


class BGPsecPath:
    """Represents a BGPsec path with signatures."""
    
    def __init__(self, as_numbers: List[int], nlri_prefixes: List[Tuple[str, int]]):
        """
        Initialize BGPsec path.
        
        Args:
            as_numbers: List of AS numbers in path (e.g., [64512, 64513, 64514])
            nlri_prefixes: List of (prefix, length) tuples for NLRI
        """
        self.as_numbers = as_numbers
        self.nlri_prefixes = nlri_prefixes
        self.nlri_bytes = encode_nlri(nlri_prefixes)
        self.signers: List[Tuple[Signature, bytes]] = []  # (signer, public_key) per AS
        self.public_keys: List[bytes] = []  # Public keys for verification
        self.signatures: List[bytes] = []
        self.signer = BGPsecPathSigner()
    
    def generate_keypairs(self):
        """
        Generate Falcon-512 keypairs for all ASes in path.
        
        Creates one Signature object per AS, each with its own keypair.
        The private key is stored internally in the Signature object.
        """
        from oqs import Signature
        self.signers = []
        self.public_keys = []
        for as_num in self.as_numbers:
            signer, pub_key = self.signer.create_signer_with_keypair()
            self.signers.append((signer, pub_key))
            self.public_keys.append(pub_key)
    
    def sign_path(self) -> SecurePathAttribute:
        """
        Sign the entire path according to RFC 8205.
        
        Returns:
            Complete Secure_Path attribute with all signatures
        """
        if not self.signers:
            self.generate_keypairs()
        
        segments = []
        signature_blocks = []
        
        # Build path incrementally, signing at each hop
        secure_path_bytes = b''
        signature_block_bytes = b''
        
        for hop_idx, as_num in enumerate(self.as_numbers):
            # Create segment for this hop
            # pCount = 1 (one signature per hop in this PoC)
            segment = SecurePathSegment(
                as_number=as_num,
                p_count=1,
                flags=0
            )
            segments.append(segment)
            
            # Add segment to secure_path
            secure_path_bytes += segment.encode()
            
            # Compute data to sign for this hop
            # Data_To_Sign = Secure_Path (up to this hop) | Signature_Block (up to this hop) | NLRI
            data_to_sign = compute_data_to_sign(
                secure_path_bytes,
                signature_block_bytes,
                self.nlri_bytes
            )
            
            # Sign with this AS's signer (which has its own internal private key)
            signer, pub_key = self.signers[hop_idx]
            signature = self.signer.sign_path_data(signer, data_to_sign)
            self.signatures.append(signature)
            
            # Create signature block for this hop
            sig_block = SignatureBlock(
                suite_id=BGPsec_SUITE_FALCON512,
                signature=signature
            )
            signature_blocks.append([sig_block])  # One signature per segment
            
            # Add signature block to signature_block_bytes
            signature_block_bytes += sig_block.encode()
        
        # Create complete Secure_Path attribute
        return SecurePathAttribute(
            segments=segments,
            signature_blocks=signature_blocks
        )
    
    def verify_path(self, secure_path_attr: SecurePathAttribute) -> Tuple[bool, List[bool]]:
        """
        Verify all signatures in the path.
        
        Args:
            secure_path_attr: Secure_Path attribute to verify
        
        Returns:
            (all_valid, per_hop_results) tuple
        """
        if not self.public_keys:
            raise ValueError("Keypairs not generated. Call generate_keypairs() first.")
        
        per_hop_results = []
        secure_path_bytes = b''
        signature_block_bytes = b''
        
        for hop_idx, (segment, sig_blocks) in enumerate(
            zip(secure_path_attr.segments, secure_path_attr.signature_blocks)
        ):
            # Add segment to secure_path
            secure_path_bytes += segment.encode()
            
            # Get signature for this hop
            if not sig_blocks:
                per_hop_results.append(False)
                continue
            
            sig_block = sig_blocks[0]  # One signature per segment
            signature = sig_block.signature
            
            # Compute data that should have been signed
            data_signed = compute_data_to_sign(
                secure_path_bytes,
                signature_block_bytes,
                self.nlri_bytes
            )
            
            # Verify signature
            pub_key = self.public_keys[hop_idx]
            is_valid = self.signer.verify_path_signature(
                pub_key,
                data_signed,
                signature
            )
            
            per_hop_results.append(is_valid)
            
            # Add signature block to signature_block_bytes for next hop
            signature_block_bytes += sig_block.encode()
        
        all_valid = all(per_hop_results)
        return all_valid, per_hop_results
    
    def get_path_size(self, secure_path_attr: SecurePathAttribute) -> dict:
        """
        Calculate size breakdown for the path.
        
        Returns:
            Dictionary with size metrics
        """
        # Count signatures
        total_sig_size = sum(len(sig) for sig in self.signatures)
        avg_sig_size = total_sig_size / len(self.signatures) if self.signatures else 0
        
        # Count segments
        segment_size = sum(len(seg.encode()) for seg in secure_path_attr.segments)
        
        # Count signature block overhead (Suite ID (1 byte) + Length (2 bytes))
        num_blocks = sum(len(blocks) for blocks in secure_path_attr.signature_blocks)
        sig_block_overhead = num_blocks * 3
        
        # Calculate data portion size (without attribute header)
        data_size = segment_size + total_sig_size + sig_block_overhead
        
        # Calculate attribute header size
        # Flags (1 byte) + Type (1 byte) + Length (1 or 2 bytes)
        if data_size > 255:
            header_size = 4  # Extended length (2 bytes)
        else:
            header_size = 3  # Short length (1 byte)
        
        total_attr_size = header_size + data_size
        
        return {
            'total_attr_size': total_attr_size,
            'data_size': data_size,
            'num_hops': len(self.as_numbers),
            'segment_size': segment_size,
            'total_signature_size': total_sig_size,
            'avg_signature_size': avg_sig_size,
            'signature_block_overhead': sig_block_overhead,
            'nlri_size': len(self.nlri_bytes),
            'total_path_size': total_attr_size + len(self.nlri_bytes),
            'exceeds_bgp_limit': total_attr_size > 65535
        }

