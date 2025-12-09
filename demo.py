#!/usr/bin/env python3
"""
Interactive BGPsec Demo with Falcon-512

Interactive demonstration of BGPsec path signing and verification.

Author: Sam Moes
Date: December 2025
"""

import sys
from modules import BGPsecPath, BGPUpdateMessage, SecurePathAttribute


def interactive_demo():
    """Run interactive demo."""
    print("=" * 80)
    print("BGPsec with Falcon-512 - Interactive Demo")
    print("=" * 80)
    print()
    
    # Get AS path from user
    print("Enter AS path (comma-separated AS numbers):")
    print("Example: 64512,15169,3356,1299,2914")
    as_input = input("AS Path: ").strip()
    
    if not as_input:
        print("Using default 5-hop path: 64512,15169,3356,1299,2914")
        as_numbers = [64512, 15169, 3356, 1299, 2914]
    else:
        try:
            as_numbers = [int(asn.strip()) for asn in as_input.split(',')]
        except ValueError:
            print("Error: Invalid AS numbers. Using default.")
            as_numbers = [64512, 15169, 3356, 1299, 2914]
    
    # Get NLRI
    print()
    print("Enter NLRI prefix (e.g., 192.0.2.0/24):")
    nlri_input = input("NLRI: ").strip()
    
    if not nlri_input or '/' not in nlri_input:
        print("Using default: 192.0.2.0/24")
        nlri_prefixes = [("192.0.2.0", 24)]
    else:
        try:
            prefix_str, prefix_len_str = nlri_input.split('/')
            prefix_len = int(prefix_len_str)
            nlri_prefixes = [(prefix_str, prefix_len)]
        except ValueError:
            print("Error: Invalid NLRI. Using default.")
            nlri_prefixes = [("192.0.2.0", 24)]
    
    print()
    print(f"AS Path: {' -> '.join(str(asn) for asn in as_numbers)}")
    print(f"NLRI: {nlri_prefixes[0][0]}/{nlri_prefixes[0][1]}")
    print()
    
    # Create path
    print("Creating BGPsec path...")
    path = BGPsecPath(as_numbers, nlri_prefixes)
    
    # Generate keypairs
    print("Generating Falcon-512 keypairs...")
    path.generate_keypairs()
    print(f"  Generated {len(path.public_keys)} keypairs")
    
    # Sign path
    print("Signing path...")
    secure_path_attr = path.sign_path()
    print(f"  Signed {len(path.signatures)} hops")
    
    # Show sizes
    size_metrics = path.get_path_size(secure_path_attr)
    print()
    print("Size Metrics:")
    print(f"  Hops: {size_metrics['num_hops']}")
    print(f"  Avg signature size: {size_metrics['avg_signature_size']:.1f} bytes")
    print(f"  Total path size: {size_metrics['total_path_size']} bytes")
    
    # Build UPDATE
    update_msg = BGPUpdateMessage(
        path_attributes=[secure_path_attr.encode()],
        nlri=path.nlri_bytes
    )
    update_bytes = update_msg.encode()
    print(f"  BGP UPDATE size: {len(update_bytes)} bytes")
    print()
    
    # Verify
    print("Verifying signatures...")
    all_valid, per_hop_results = path.verify_path(secure_path_attr)
    
    if all_valid:
        print("  All signatures valid!")
    else:
        print("  Some signatures invalid")
        for hop_idx, is_valid in enumerate(per_hop_results):
            status = "Valid" if is_valid else "Invalid"
            print(f"    Hop {hop_idx + 1} (AS {as_numbers[hop_idx]}): {status}")
    
    print()
    print("Demo complete!")


if __name__ == "__main__":
    try:
        interactive_demo()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

