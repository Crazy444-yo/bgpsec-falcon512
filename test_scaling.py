#!/usr/bin/env python3
"""
BGPsec Scaling Analysis with Falcon-512

Tests performance and size scaling across different hop counts to analyze
how BGPsec with Falcon-512 scales from short to long paths.

Author: Sam Moes
Date: December 2025
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Tuple
from modules import SecurePathAttribute, BGPUpdateMessage, encode_nlri, BGPsecPath


def create_test_path(num_hops: int) -> BGPsecPath:
    """
    Create a test AS path with specified number of hops.
    
    Uses a mix of real AS numbers and test AS numbers.
    """
    # Real AS numbers from major network operators
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
    ]
    
    as_path = [64512]  # Origin AS
    
    # Build path by cycling through real AS numbers and adding test AS numbers
    for i in range(1, num_hops):
        if i <= len(real_asns):
            as_path.append(real_asns[i - 1])
        else:
            # Use sequential test AS numbers
            as_path.append(64500 + i)
    
    nlri_prefixes = [("192.0.2.0", 24)]
    return BGPsecPath(as_path, nlri_prefixes)


def test_path(num_hops: int) -> Dict:
    """
    Test a single path and collect all metrics.
    
    Returns dictionary with performance and size metrics.
    """
    print(f"  Testing {num_hops}-hop path...", end='', flush=True)
    
    # Create path
    path = create_test_path(num_hops)
    
    # Generate keypairs
    start_time = time.time()
    path.generate_keypairs()
    keypair_time = time.time() - start_time
    
    # Sign path
    start_time = time.time()
    secure_path_attr = path.sign_path()
    signing_time = time.time() - start_time
    
    # Get size metrics
    size_metrics = path.get_path_size(secure_path_attr)
    
    # Build UPDATE message
    update_msg = BGPUpdateMessage(
        path_attributes=[secure_path_attr.encode()],
        nlri=path.nlri_bytes
    )
    update_bytes = update_msg.encode()
    msg_size = len(update_bytes)
    
    # Verify path
    start_time = time.time()
    all_valid, per_hop_results = path.verify_path(secure_path_attr)
    verify_time = time.time() - start_time
    
    print(f" ✓")
    
    return {
        'num_hops': num_hops,
        'keypair_time': keypair_time,
        'keypair_time_per_as': keypair_time / num_hops,
        'signing_time': signing_time,
        'signing_time_per_hop': signing_time / num_hops,
        'verification_time': verify_time,
        'verification_time_per_hop': verify_time / num_hops,
        'all_signatures_valid': all_valid,
        'valid_signatures': sum(per_hop_results),
        'message_size': msg_size,
        'message_size_kb': msg_size / 1024,
        'avg_signature_size': size_metrics.get('avg_signature_size', 0),
        'total_signature_size': size_metrics.get('total_signature_size', 0),
        'attribute_size': size_metrics.get('total_attr_size', 0),
        'bytes_per_hop': msg_size / num_hops,
        'signature_bytes_per_hop': size_metrics.get('avg_signature_size', 0),
        'exceeds_bgp_limit': size_metrics.get('exceeds_bgp_limit', False)
    }


def analyze_scaling(results: List[Dict]) -> Dict:
    """
    Analyze scaling behavior from results.
    
    Calculates scaling factors and determines if relationships are linear.
    """
    if len(results) < 2:
        return {}
    
    # Compare smallest to largest
    smallest = results[0]
    largest = results[-1]
    
    hop_ratio = largest['num_hops'] / smallest['num_hops']
    size_ratio = largest['message_size'] / smallest['message_size']
    signing_ratio = largest['signing_time'] / smallest['signing_time']
    verify_ratio = largest['verification_time'] / smallest['verification_time']
    
    # Check linearity (within 5% tolerance)
    size_linearity = abs(size_ratio - hop_ratio) / hop_ratio < 0.05
    signing_linearity = abs(signing_ratio - hop_ratio) / hop_ratio < 0.05
    verify_linearity = abs(verify_ratio - hop_ratio) / hop_ratio < 0.05
    
    # Calculate average per-hop values
    avg_bytes_per_hop = sum(r['bytes_per_hop'] for r in results) / len(results)
    avg_signing_per_hop = sum(r['signing_time_per_hop'] for r in results) / len(results)
    avg_verify_per_hop = sum(r['verification_time_per_hop'] for r in results) / len(results)
    
    return {
        'hop_ratio': hop_ratio,
        'size_ratio': size_ratio,
        'signing_ratio': signing_ratio,
        'verify_ratio': verify_ratio,
        'size_scales_linearly': size_linearity,
        'signing_scales_linearly': signing_linearity,
        'verification_scales_linearly': verify_linearity,
        'avg_bytes_per_hop': avg_bytes_per_hop,
        'avg_signing_time_per_hop_ms': avg_signing_per_hop * 1000,
        'avg_verification_time_per_hop_ms': avg_verify_per_hop * 1000,
    }


def main():
    """Run scaling analysis across multiple hop counts."""
    print("=" * 80)
    print("BGPsec with Falcon-512: Realistic Path Scaling Analysis")
    print("=" * 80)
    print()
    print("Testing performance and size scaling across realistic hop counts (1-15 hops).")
    print("Typical Internet paths are 3-8 hops. This analysis focuses on real-world scenarios.")
    print()
    
    # Test hop counts: 1 to 15 (realistic Internet routing range)
    hop_counts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15]
    
    print(f"Testing hop counts: {', '.join(str(h) for h in hop_counts)}")
    print()
    
    results = []
    
    for num_hops in hop_counts:
        try:
            result = test_path(num_hops)
            results.append(result)
        except Exception as e:
            print(f" ✗ Error: {e}")
            continue
    
    if not results:
        print("No successful tests completed.")
        return
    
    print()
    print("=" * 80)
    print("CRITICAL REAL-WORLD METRICS")
    print("=" * 80)
    print()
    
    # Most important metrics for real deployment
    print("Message Size Analysis:")
    print(f"{'Hops':<6} {'Size (KB)':<12} {'Bytes/Hop':<12} {'Fits Jumbo?':<15} {'Network Status':<20}")
    print("-" * 75)
    
    for r in results:
        size_kb = r['message_size_kb']
        bytes_per_hop = r['bytes_per_hop']
        fits_jumbo = "YES" if r['message_size'] <= 9216 else "NO"
        
        # Network status
        if r['message_size'] <= 1500:
            status = "Standard Ethernet"
        elif r['message_size'] <= 9216:
            status = "Jumbo Frame OK"
        elif r['message_size'] <= 65535:
            import math
            segments = math.ceil(r['message_size'] / 9216)
            status = f"TCP seg ({segments}x)"
        else:
            status = "EXCEEDS BGP LIMIT"
        
        print(f"{r['num_hops']:<6} {size_kb:<12.2f} {bytes_per_hop:<12.1f} {fits_jumbo:<15} {status:<20}")
    
    print()
    print("=" * 80)
    print("PERFORMANCE METRICS (Critical for Router Deployment)")
    print("=" * 80)
    print()
    
    print("Signing Performance (Time to generate signature at each AS):")
    print(f"{'Hops':<6} {'Total (ms)':<12} {'Per-Hop (ms)':<15} {'Per-Hop (μs)':<15}")
    print("-" * 50)
    
    for r in results:
        sign_total = r['signing_time'] * 1000
        sign_per_hop_ms = r['signing_time_per_hop'] * 1000
        sign_per_hop_us = sign_per_hop_ms * 1000
        
        print(f"{r['num_hops']:<6} {sign_total:<12.2f} {sign_per_hop_ms:<15.2f} {sign_per_hop_us:<15.0f}")
    
    print()
    print("Verification Performance (Time to verify at receiving router):")
    print(f"{'Hops':<6} {'Total (ms)':<12} {'Per-Hop (ms)':<15} {'Per-Hop (μs)':<15}")
    print("-" * 50)
    
    for r in results:
        verify_total = r['verification_time'] * 1000
        verify_per_hop_ms = r['verification_time_per_hop'] * 1000
        verify_per_hop_us = verify_per_hop_ms * 1000
        
        print(f"{r['num_hops']:<6} {verify_total:<12.2f} {verify_per_hop_ms:<15.2f} {verify_per_hop_us:<15.0f}")
    
    print()
    print("Total Processing Time (Signing + Verification):")
    print(f"{'Hops':<6} {'Total (ms)':<12} {'Per-Hop (ms)':<15} {'Throughput':<20}")
    print("-" * 55)
    
    for r in results:
        total_time = (r['signing_time'] + r['verification_time']) * 1000
        per_hop_time = (r['signing_time_per_hop'] + r['verification_time_per_hop']) * 1000
        # Throughput: paths per second
        throughput = 1000 / total_time if total_time > 0 else 0
        
        print(f"{r['num_hops']:<6} {total_time:<12.2f} {per_hop_time:<15.2f} {throughput:<20.1f} paths/sec")
    
    print()
    print("=" * 80)
    print("OVERHEAD ANALYSIS")
    print("=" * 80)
    print()
    
    print(f"{'Hops':<6} {'Sig Size':<12} {'Overhead':<12} {'Total Size':<12} {'Variable/Hop':<15}")
    print("-" * 65)
    
    for r in results:
        sig_size = r['avg_signature_size']
        overhead = r['message_size'] - (r['signature_bytes_per_hop'] * r['num_hops'])
        total_size = r['message_size']
        variable = r['bytes_per_hop']
        
        print(f"{r['num_hops']:<6} {sig_size:<12.1f} {overhead:<12.1f} {total_size:<12.1f} {variable:<15.1f}")
    
    print()
    print("=" * 80)
    print("REAL-WORLD DEPLOYMENT INSIGHTS")
    print("=" * 80)
    print()
    
    analysis = analyze_scaling(results)
    
    # Focus on typical Internet paths (3-8 hops)
    typical_paths = [r for r in results if 3 <= r['num_hops'] <= 8]
    long_paths = [r for r in results if 9 <= r['num_hops'] <= 15]
    
    if typical_paths:
        print("Typical Internet Paths (3-8 hops):")
        avg_size = sum(r['message_size_kb'] for r in typical_paths) / len(typical_paths)
        avg_sign_time = sum(r['signing_time_per_hop'] * 1000 for r in typical_paths) / len(typical_paths)
        avg_verify_time = sum(r['verification_time_per_hop'] * 1000 for r in typical_paths) / len(typical_paths)
        avg_total_time = sum((r['signing_time'] + r['verification_time']) * 1000 for r in typical_paths) / len(typical_paths)
        
        print(f"  Average message size: {avg_size:.2f} KB")
        print(f"  Average signing time per hop: {avg_sign_time:.2f} ms ({avg_sign_time*1000:.0f} μs)")
        print(f"  Average verification time per hop: {avg_verify_time:.2f} ms ({avg_verify_time*1000:.0f} μs)")
        print(f"  Average total processing time: {avg_total_time:.2f} ms")
        print()
    
    if long_paths:
        print("Long Paths (9-15 hops):")
        avg_size = sum(r['message_size_kb'] for r in long_paths) / len(long_paths)
        avg_sign_time = sum(r['signing_time_per_hop'] * 1000 for r in long_paths) / len(long_paths)
        avg_verify_time = sum(r['verification_time_per_hop'] * 1000 for r in long_paths) / len(long_paths)
        avg_total_time = sum((r['signing_time'] + r['verification_time']) * 1000 for r in long_paths) / len(long_paths)
        
        print(f"  Average message size: {avg_size:.2f} KB")
        print(f"  Average signing time per hop: {avg_sign_time:.2f} ms ({avg_sign_time*1000:.0f} μs)")
        print(f"  Average verification time per hop: {avg_verify_time:.2f} ms ({avg_verify_time*1000:.0f} μs)")
        print(f"  Average total processing time: {avg_total_time:.2f} ms")
        print()
    
    if analysis:
        print("Scaling Behavior:")
        print(f"  Message size scales linearly: {'YES ✓' if analysis['size_scales_linearly'] else 'NO ✗'}")
        print(f"  Signing scales linearly: {'YES ✓' if analysis['signing_scales_linearly'] else 'NO ✗'}")
        print(f"  Verification scales linearly: {'YES ✓' if analysis['verification_scales_linearly'] else 'NO ✗'}")
        print()
        print(f"  Average bytes per hop: {analysis['avg_bytes_per_hop']:.1f} bytes")
        print(f"  Average signing time per hop: {analysis['avg_signing_time_per_hop_ms']:.2f} ms")
        print(f"  Average verification time per hop: {analysis['avg_verification_time_per_hop_ms']:.2f} ms")
        print()
    
    # Network compatibility summary
    print("Network Compatibility Summary:")
    jumbo_compatible = [r for r in results if r['message_size'] <= 9216]
    tcp_seg_needed = [r for r in results if 9216 < r['message_size'] <= 65535]
    exceeds_limit = [r for r in results if r['message_size'] > 65535]
    
    if jumbo_compatible:
        max_jumbo = max(jumbo_compatible, key=lambda x: x['num_hops'])
        print(f"  Fits in jumbo frame: up to {max_jumbo['num_hops']} hops ({max_jumbo['message_size_kb']:.2f} KB)")
    
    if tcp_seg_needed:
        max_tcp = max(tcp_seg_needed, key=lambda x: x['num_hops'])
        import math
        segments = math.ceil(max_tcp['message_size'] / 9216)
        print(f"  Requires TCP segmentation: {min(r['num_hops'] for r in tcp_seg_needed)}-{max_tcp['num_hops']} hops (up to {segments} segments)")
    
    if exceeds_limit:
        print(f"  Exceeds BGP limit: {[r['num_hops'] for r in exceeds_limit]} hops")
    
    print()
    print("=" * 80)
    print("KEY FINDINGS FOR REAL-WORLD DEPLOYMENT")
    print("=" * 80)
    print()
    
    # Most important takeaways
    if typical_paths:
        typical_avg = typical_paths[len(typical_paths)//2]  # Middle of typical range
        print(f"1. Typical path (3-8 hops): ~{typical_avg['message_size_kb']:.1f} KB message")
        print(f"   - Processing time: ~{(typical_avg['signing_time'] + typical_avg['verification_time'])*1000:.1f} ms")
        print(f"   - Per-hop overhead: ~{typical_avg['bytes_per_hop']:.0f} bytes")
        print()
    
    if analysis:
        print(f"2. Performance is consistent: ~{analysis['avg_signing_time_per_hop_ms']*1000:.0f} μs signing, ~{analysis['avg_verification_time_per_hop_ms']*1000:.0f} μs verification per hop")
        print()
    
    all_valid = all(r['all_signatures_valid'] for r in results)
    print(f"3. All signatures valid: {'YES ✓' if all_valid else 'NO ✗'}")
    print()
    
    # Router performance estimate
    if typical_paths:
        avg_5hop = next((r for r in typical_paths if r['num_hops'] == 5), typical_paths[0])
        total_time_ms = (avg_5hop['signing_time'] + avg_5hop['verification_time']) * 1000
        routes_per_sec = 1000 / total_time_ms if total_time_ms > 0 else 0
        print(f"4. Router throughput estimate (5-hop path):")
        print(f"   - ~{routes_per_sec:.0f} BGPsec routes/second")
        print(f"   - ~{routes_per_sec * 60:.0f} routes/minute")
        print()
    
    print()
    
    # Save results
    results_dir = Path("examples")
    results_dir.mkdir(exist_ok=True)
    
    output = {
        'test_name': 'BGPsec scaling analysis with Falcon-512',
        'hop_counts_tested': hop_counts,
        'results': results,
        'scaling_analysis': analysis
    }
    
    results_file = results_dir / "scaling_analysis.json"
    with open(results_file, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Saved detailed results: {results_file}")
    print()
    print("=" * 80)


if __name__ == "__main__":
    main()

