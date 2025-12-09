#!/usr/bin/env python3
"""
15-Hop BGPsec Path Test with Falcon-512

Tests a complete 15-hop BGPsec path with pure Falcon-512 signatures.
Tests that 15-hop paths fit in modern network infrastructure.

Author: Sam Moes
Date: December 2025
"""

import json
import time
from pathlib import Path
from modules import SecurePathAttribute, BGPUpdateMessage, encode_nlri, BGPsecPath


def create_15hop_test_path() -> BGPsecPath:
    """
    Create a realistic 15-hop AS path.
    
    Uses real-world AS numbers from different regions to simulate
    a realistic Internet routing path.
    """
    # Real AS numbers from different regions (for realism)
    as_path = [
        64512,  # Origin AS (hypothetical)
        15169,  # Google
        3356,   # Level 3
        1299,   # Telia
        2914,   # NTT
        174,    # Cogent
        3257,   # GTT
        3491,   # PCCW
        6762,   # Telecom Italia
        64513,  # Intermediate AS
        64514,  # Intermediate AS
        64515,  # Intermediate AS
        64516,  # Intermediate AS
        64517,  # Intermediate AS
        64518,  # Destination AS
    ]
    
    # Announce a /24 prefix
    nlri_prefixes = [("192.0.2.0", 24)]
    
    return BGPsecPath(as_path, nlri_prefixes)


def main():
    """Run 15-hop BGPsec test."""
    print("=" * 80)
    print("BGPsec with Falcon-512: 15-Hop Path Test")
    print("=" * 80)
    print()
    
    # Create path
    print("Creating 15-hop AS path...")
    path = create_15hop_test_path()
    print(f"  AS Path: {' -> '.join(str(asn) for asn in path.as_numbers)}")
    print(f"  NLRI: {path.nlri_prefixes[0][0]}/{path.nlri_prefixes[0][1]}")
    print()
    
    # Generate keypairs
    print("Generating Falcon-512 keypairs for all ASes...")
    start_time = time.time()
    path.generate_keypairs()
    keypair_time = time.time() - start_time
    print(f"  Generated {len(path.public_keys)} keypairs in {keypair_time:.3f} seconds")
    print(f"  Public key size: {len(path.public_keys[0])} bytes (~897 bytes expected)")
    print()
    
    # Sign path
    print("Signing path (one signature per hop)...")
    start_time = time.time()
    secure_path_attr = path.sign_path()
    signing_time = time.time() - start_time
    print(f"  Signed {len(path.signatures)} hops in {signing_time:.3f} seconds")
    print(f"  Average signing time per hop: {signing_time / len(path.signatures) * 1000:.2f} ms")
    print()
    
    # Calculate sizes
    print("Size Analysis:")
    size_metrics = path.get_path_size(secure_path_attr)
    print(f"  Number of hops: {size_metrics['num_hops']}")
    print(f"  Average signature size: ~{size_metrics['avg_signature_size']:.0f} bytes (varies 650-690)")
    print(f"  Total signature size: ~{size_metrics['total_signature_size']} bytes")
    print(f"  Segment overhead: {size_metrics['segment_size']} bytes")
    print(f"  Signature block overhead: {size_metrics['signature_block_overhead']} bytes")
    print(f"  Secure_Path attribute size: ~{size_metrics['total_attr_size']} bytes")
    print(f"  NLRI size: {size_metrics['nlri_size']} bytes")
    print(f"  Total path size: ~{size_metrics['total_path_size']} bytes")
    print()
    
    # Build BGP UPDATE message
    print("Building BGP UPDATE message...")
    update_msg = BGPUpdateMessage(
        path_attributes=[secure_path_attr.encode()],
        nlri=path.nlri_bytes
    )
    update_bytes = update_msg.encode()
    print(f"  BGP UPDATE message size: ~{len(update_bytes)} bytes (~{len(update_bytes) / 1024:.1f} KB)")
    print(f"  BGP header: 19 bytes")
    print(f"  Path attributes length field: 2 bytes")
    print(f"  Message body: ~{len(update_bytes) - 19} bytes")
    print()
    
    # Network compatibility check
    print("Network Compatibility (2025):")
    msg_size = len(update_bytes)
    print(f"  Message size: {msg_size} bytes ({msg_size / 1024:.2f} KB)")
    
    if msg_size <= 1500:
        print(f"  Fits in standard Ethernet frame (1500 bytes)")
    elif msg_size <= 9000:
        print(f"  Fits in jumbo Ethernet frame (9000 bytes)")
    elif msg_size <= 9216:
        print(f"  Fits in maximum jumbo frame (9216 bytes)")
    else:
        print(f"  Exceeds maximum jumbo frame (9216 bytes)")
        print(f"     Would require TCP segmentation (acceptable on modern networks)")
    
    # Check against real-world limits
    print()
    print("Real-World Network Limits (2025):")
    print(f"  Ethernet jumbo frames: 9000-9216 bytes")
    print(f"  IXP/route-server MTU: 9192-9216 bytes")
    print(f"  TCP MSS for BGP: ~8900-9000 bytes")
    print(f"  Observed BGP messages: 8-15 KB")
    print()
    
    # Verify path
    print("Verifying all path signatures...")
    start_time = time.time()
    all_valid, per_hop_results = path.verify_path(secure_path_attr)
    verify_time = time.time() - start_time
    print(f"  Verified {len(per_hop_results)} signatures in {verify_time:.3f} seconds")
    print(f"  Average verification time per hop: {verify_time / len(per_hop_results) * 1000:.2f} ms")
    
    if all_valid:
        print(f"  All signatures valid!")
    else:
        print(f"  Some signatures invalid:")
        for hop_idx, is_valid in enumerate(per_hop_results):
            if not is_valid:
                print(f"    Hop {hop_idx + 1} (AS {path.as_numbers[hop_idx]}): Invalid")
    print()
    
    # Save results
    print("Saving results...")
    results_dir = Path("examples")
    results_dir.mkdir(exist_ok=True)
    
    # Save BGP UPDATE message
    update_file = results_dir / "15hop_update.bin"
    with open(update_file, 'wb') as f:
        f.write(update_bytes)
    print(f"  Saved BGP UPDATE: {update_file} ({len(update_bytes)} bytes)")
    
    # Save results JSON
    results = {
        'test_name': '15-hop BGPsec with Falcon-512',
        'as_path': path.as_numbers,
        'nlri': path.nlri_prefixes,
        'num_hops': len(path.as_numbers),
        'size_metrics': size_metrics,
        'update_message_size': len(update_bytes),
        'signing_time_seconds': signing_time,
        'verification_time_seconds': verify_time,
        'all_signatures_valid': all_valid,
        'per_hop_verification': per_hop_results,
        'network_compatibility': {
            'fits_standard_ethernet': msg_size <= 1500,
            'fits_jumbo_frame': msg_size <= 9000,
            'fits_max_jumbo': msg_size <= 9216,
            'within_observed_range': 8000 <= msg_size <= 15000
        }
    }
    
    results_file = results_dir / "validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"  Saved results: {results_file}")
    print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    # Real results
    path_created = len(path.as_numbers) == 15 and len(path.signatures) == 15
    fits_standard_ethernet = msg_size <= 1500
    fits_jumbo_frame = msg_size <= 9000
    fits_max_jumbo = msg_size <= 9216
    within_observed_range = 8000 <= msg_size <= 15000
    requires_segmentation = msg_size > 9216
    
    print(f"Path creation: {'SUCCESS' if path_created else 'FAILED'}")
    print(f"  Hops created: {len(path.as_numbers)}/{len(path.as_numbers)}")
    print(f"  Signatures generated: {len(path.signatures)}/{len(path.as_numbers)}")
    print()
    
    print(f"Message size: {msg_size} bytes ({msg_size / 1024:.2f} KB)")
    print(f"  Fits standard Ethernet (1500 bytes): {'YES' if fits_standard_ethernet else 'NO'}")
    print(f"  Fits jumbo frame (9000 bytes): {'YES' if fits_jumbo_frame else 'NO'}")
    print(f"  Fits max jumbo (9216 bytes): {'YES' if fits_max_jumbo else 'NO'}")
    print(f"  Within observed BGP range (8-15 KB): {'YES' if within_observed_range else 'NO'}")
    if requires_segmentation:
        import math
        segments_needed = math.ceil(msg_size / 9216)
        excess_bytes = msg_size - 9216
        print(f"  Requires TCP segmentation: YES ({segments_needed} segments, {excess_bytes} bytes over limit, acceptable on modern networks)")
    print()
    
    print(f"Signature verification: {'PASS' if all_valid else 'FAIL'}")
    print(f"  Valid signatures: {sum(per_hop_results)}/{len(per_hop_results)}")
    if not all_valid:
        invalid_hops = [i+1 for i, valid in enumerate(per_hop_results) if not valid]
        print(f"  Invalid at hops: {invalid_hops}")
    print(f"  Average verification time: {verify_time / len(per_hop_results) * 1000:.2f} ms/hop")
    print()
    
    print(f"Performance:")
    print(f"  Keypair generation: {keypair_time:.3f}s ({keypair_time/len(path.as_numbers)*1000:.2f} ms/keypair)")
    print(f"  Path signing: {signing_time:.3f}s ({signing_time/len(path.signatures)*1000:.2f} ms/signature)")
    print(f"  Path verification: {verify_time:.3f}s ({verify_time/len(per_hop_results)*1000:.2f} ms/verification)")
    print()
    
    # Overall status
    overall_success = path_created and all_valid
    network_compatible = fits_max_jumbo or within_observed_range
    
    print(f"Overall status: {'SUCCESS' if overall_success else 'FAILED'}")
    print(f"Network compatibility: {'COMPATIBLE' if network_compatible else 'MAY REQUIRE SEGMENTATION'}")
    print("=" * 80)


if __name__ == "__main__":
    main()

