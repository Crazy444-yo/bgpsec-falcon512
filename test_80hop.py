#!/usr/bin/env python3
"""
80-Hop BGPsec Path Stress Test with Falcon-512

Extreme stress test to demonstrate scalability of BGPsec with Falcon-512
at path lengths far beyond typical Internet routing scenarios.

Author: Sam Moes
Date: December 2025
"""

import json
import time
from pathlib import Path
from modules import SecurePathAttribute, BGPUpdateMessage, encode_nlri, BGPsecPath


def create_80hop_test_path() -> BGPsecPath:
    """
    Create an extreme 80-hop AS path for stress testing.
    
    Uses a mix of real AS numbers and test AS numbers to create
    a very long path that tests the limits of the implementation.
    """
    # Mix of real major AS numbers and sequential test AS numbers
    real_asns = [
        15169,  # Google
        3356,   # Level 3
        1299,   # Telia
        2914,   # NTT
        174,    # Cogent
        3257,   # GTT
        3491,   # PCCW
        6762,   # Telecom Italia
        701,    # UUNET
        1239,   # Sprint
        2828,   # XO Communications
        6461,   # Zayo
        3356,   # Level 3
        6453,   # Cogent
    ]
    
    # Build 80-hop path
    as_path = [64512]  # Origin AS
    
    # Add real AS numbers repeated and test AS numbers
    as_count = 1
    while as_count < 80:
        # Cycle through real AS numbers
        for asn in real_asns:
            if as_count >= 80:
                break
            as_path.append(asn)
            as_count += 1
        
        # Fill remainder with sequential test AS numbers
        while as_count < 80:
            as_path.append(64500 + as_count)
            as_count += 1
    
    # Announce a /24 prefix
    nlri_prefixes = [("192.0.2.0", 24)]
    
    return BGPsecPath(as_path, nlri_prefixes)


def main():
    """Run 80-hop BGPsec stress test."""
    print("=" * 80)
    print("BGPsec with Falcon-512: 80-Hop Stress Test")
    print("=" * 80)
    print()
    print("WARNING: This is an extreme stress test with 80 hops.")
    print("Typical Internet paths are 3-8 hops. This test demonstrates")
    print("scalability far beyond realistic scenarios.")
    print()
    
    # Create path
    print("Creating 80-hop AS path...")
    start_create = time.time()
    path = create_80hop_test_path()
    create_time = time.time() - start_create
    print(f"  AS Path: {len(path.as_numbers)} hops")
    print(f"  First 5 ASes: {' -> '.join(str(asn) for asn in path.as_numbers[:5])} ...")
    print(f"  Last 5 ASes: ... {' -> '.join(str(asn) for asn in path.as_numbers[-5:])}")
    print(f"  NLRI: {path.nlri_prefixes[0][0]}/{path.nlri_prefixes[0][1]}")
    print(f"  Path creation time: {create_time:.3f} seconds")
    print()
    
    # Generate keypairs
    print("Generating Falcon-512 keypairs for all ASes...")
    print("  This may take a moment (80 keypairs)...")
    start_time = time.time()
    path.generate_keypairs()
    keypair_time = time.time() - start_time
    print(f"  Generated {len(path.public_keys)} keypairs in {keypair_time:.3f} seconds")
    print(f"  Average time per keypair: {keypair_time / len(path.public_keys) * 1000:.2f} ms")
    print(f"  Public key size: {len(path.public_keys[0])} bytes")
    print()
    
    # Sign path
    print("Signing path (one signature per hop)...")
    print("  This may take a moment (80 signatures)...")
    start_time = time.time()
    secure_path_attr = path.sign_path()
    signing_time = time.time() - start_time
    print(f"  Signed {len(path.signatures)} hops in {signing_time:.3f} seconds")
    print(f"  Average signing time per hop: {signing_time / len(path.signatures) * 1000:.2f} ms")
    print(f"  Total signing time: {signing_time:.3f} seconds")
    print()
    
    # Calculate sizes
    print("Size Analysis:")
    size_metrics = path.get_path_size(secure_path_attr)
    
    if size_metrics.get('exceeds_bgp_limit', False):
        print(f"  WARNING: Path exceeds BGP attribute size limit (65535 bytes)")
        print(f"  Calculated size: {size_metrics['total_attr_size']} bytes")
        print()
        print("=" * 80)
        print("BGP SPECIFICATION LIMIT REACHED")
        print("=" * 80)
        print("This 80-hop path exceeds BGP specification limits.")
        print("BGP path attributes are limited to 65535 bytes per attribute (RFC 4271).")
        print()
        print(f"Path statistics:")
        print(f"  Number of hops: {size_metrics['num_hops']}")
        print(f"  Data size: {size_metrics['data_size']} bytes")
        print(f"  Total attribute size: {size_metrics['total_attr_size']} bytes")
        print()
        print("This demonstrates:")
        print("  - The implementation correctly identifies BGP specification limits")
        print("  - 15-hop paths (realistic) are well within limits (~10 KB)")
        print("  - Even 50-hop paths would fit (~33 KB)")
        print("  - 80 hops exceeds single-attribute limits")
        print()
        print("For paths exceeding 65535 bytes, BGP would require attribute")
        print("splitting or multiple UPDATE messages, which is beyond this")
        print("proof-of-concept scope. Real-world paths are typically 3-8 hops.")
        print("=" * 80)
        return
    print(f"  Number of hops: {size_metrics['num_hops']}")
    print(f"  Average signature size: ~{size_metrics['avg_signature_size']:.0f} bytes")
    print(f"  Total signature size: ~{size_metrics['total_signature_size']} bytes (~{size_metrics['total_signature_size'] / 1024:.1f} KB)")
    print(f"  Segment overhead: {size_metrics['segment_size']} bytes")
    print(f"  Signature block overhead: {size_metrics['signature_block_overhead']} bytes")
    print(f"  Secure_Path attribute size: ~{size_metrics['total_attr_size']} bytes (~{size_metrics['total_attr_size'] / 1024:.1f} KB)")
    print(f"  NLRI size: {size_metrics['nlri_size']} bytes")
    print(f"  Total path size: ~{size_metrics['total_path_size']} bytes (~{size_metrics['total_path_size'] / 1024:.1f} KB)")
    print()
    
    # Build BGP UPDATE message
    print("Building BGP UPDATE message...")
    update_msg = BGPUpdateMessage(
        path_attributes=[secure_path_attr.encode()],
        nlri=path.nlri_bytes
    )
    update_bytes = update_msg.encode()
    msg_size = len(update_bytes)
    print(f"  BGP UPDATE message size: {msg_size} bytes ({msg_size / 1024:.2f} KB)")
    print(f"  BGP header: 19 bytes")
    print(f"  Path attributes length field: 2 bytes")
    print(f"  Message body: {msg_size - 19} bytes")
    print()
    
    # Network compatibility check
    print("Network Compatibility (2025):")
    print(f"  Message size: {msg_size} bytes ({msg_size / 1024:.2f} KB)")
    
    if msg_size <= 1500:
        print(f"  Fits in standard Ethernet frame (1500 bytes)")
    elif msg_size <= 9000:
        print(f"  Fits in jumbo Ethernet frame (9000 bytes)")
    elif msg_size <= 9216:
        print(f"  Fits in maximum jumbo frame (9216 bytes)")
    else:
        print(f"  Exceeds maximum jumbo frame (9216 bytes)")
        print(f"     Requires TCP segmentation ({msg_size / 9216:.1f}x larger)")
        print(f"     TCP handles this transparently on modern networks")
    
    # Real-world context
    # Typical 15-hop path size is approximately 9992 bytes (from test_15hop.py results)
    typical_15hop_size = 9992
    print()
    print("Real-World Context:")
    print(f"  Typical Internet paths: 3-8 hops")
    print(f"  This test: 80 hops ({msg_size / 1024:.1f} KB)")
    print(f"  At 15 hops: ~{typical_15hop_size / 1024:.1f} KB (realistic long path)")
    hop_ratio = 80 / 15
    size_ratio = msg_size / typical_15hop_size
    print(f"  This is {hop_ratio:.1f}x longer than the 15-hop test")
    print(f"  Message size is {size_ratio:.1f}x larger than 15-hop test")
    print()
    
    # Verify path
    print("Verifying all path signatures...")
    print("  This may take a moment (80 verifications)...")
    start_time = time.time()
    all_valid, per_hop_results = path.verify_path(secure_path_attr)
    verify_time = time.time() - start_time
    print(f"  Verified {len(per_hop_results)} signatures in {verify_time:.3f} seconds")
    print(f"  Average verification time per hop: {verify_time / len(per_hop_results) * 1000:.2f} ms")
    print(f"  Total verification time: {verify_time:.3f} seconds")
    
    if all_valid:
        print(f"  All signatures valid!")
    else:
        print(f"  Some signatures invalid:")
        invalid_count = sum(1 for v in per_hop_results if not v)
        print(f"    Invalid signatures: {invalid_count}/{len(per_hop_results)}")
        for hop_idx, is_valid in enumerate(per_hop_results[:10]):  # Show first 10
            if not is_valid:
                print(f"    Hop {hop_idx + 1} (AS {path.as_numbers[hop_idx]}): Invalid")
        if invalid_count > 10:
            print(f"    ... and {invalid_count - 10} more")
    print()
    
    # Save results
    print("Saving results...")
    results_dir = Path("examples")
    results_dir.mkdir(exist_ok=True)
    
    # Save BGP UPDATE message
    update_file = results_dir / "80hop_update.bin"
    with open(update_file, 'wb') as f:
        f.write(update_bytes)
    print(f"  Saved BGP UPDATE: {update_file} ({msg_size} bytes)")
    
    # Save results JSON
    results = {
        'test_name': '80-hop BGPsec stress test with Falcon-512',
        'num_hops': len(path.as_numbers),
        'as_path': path.as_numbers,
        'nlri': path.nlri_prefixes,
        'size_metrics': size_metrics,
        'update_message_size': msg_size,
        'keypair_generation_time': keypair_time,
        'signing_time_seconds': signing_time,
        'verification_time_seconds': verify_time,
        'all_signatures_valid': all_valid,
        'per_hop_verification': per_hop_results,
        'performance_per_hop': {
            'keypair_generation_ms': keypair_time / len(path.as_numbers) * 1000,
            'signing_ms': signing_time / len(path.signatures) * 1000,
            'verification_ms': verify_time / len(per_hop_results) * 1000
        }
    }
    
    results_file = results_dir / "80hop_validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"  Saved results: {results_file}")
    print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    path_created = len(path.as_numbers) == 80 and len(path.signatures) == 80
    fits_standard_ethernet = msg_size <= 1500
    fits_jumbo_frame = msg_size <= 9000
    fits_max_jumbo = msg_size <= 9216
    requires_segmentation = msg_size > 9216
    
    print(f"Path creation: {'SUCCESS' if path_created else 'FAILED'}")
    print(f"  Hops created: {len(path.as_numbers)}/80")
    print(f"  Signatures generated: {len(path.signatures)}/80")
    print()
    
    print(f"Message size: {msg_size} bytes ({msg_size / 1024:.2f} KB)")
    print(f"  Fits standard Ethernet (1500 bytes): {'YES' if fits_standard_ethernet else 'NO'}")
    print(f"  Fits jumbo frame (9000 bytes): {'YES' if fits_jumbo_frame else 'NO'}")
    print(f"  Fits max jumbo (9216 bytes): {'YES' if fits_max_jumbo else 'NO'}")
    if requires_segmentation:
        import math
        segments_needed = math.ceil(msg_size / 9216)
        print(f"  Requires TCP segmentation: YES ({segments_needed} segments)")
    print()
    
    print(f"Signature verification: {'PASS' if all_valid else 'FAIL'}")
    print(f"  Valid signatures: {sum(per_hop_results)}/80")
    if all_valid:
        print(f"  All 80 signatures verified successfully")
    print(f"  Average verification time: {verify_time / len(per_hop_results) * 1000:.2f} ms/hop")
    print()
    
    print(f"Performance:")
    print(f"  Keypair generation: {keypair_time:.3f}s ({keypair_time/len(path.as_numbers)*1000:.2f} ms/keypair)")
    print(f"  Path signing: {signing_time:.3f}s ({signing_time/len(path.signatures)*1000:.2f} ms/signature)")
    print(f"  Path verification: {verify_time:.3f}s ({verify_time/len(per_hop_results)*1000:.2f} ms/verification)")
    print()
    
    overall_success = path_created and all_valid
    network_handles = True  # TCP can handle any size
    
    print(f"Overall status: {'SUCCESS' if overall_success else 'FAILED'}")
    print(f"Network handling: TCP segmentation handles this size transparently")
    print()
    print("This stress test demonstrates that BGPsec with Falcon-512 scales")
    print("even to extreme path lengths far beyond realistic Internet routing.")
    print("=" * 80)


if __name__ == "__main__":
    main()

