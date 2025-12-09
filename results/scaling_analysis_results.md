# BGPsec with Falcon-512: Realistic Path Scaling Analysis

Testing performance and size scaling across realistic hop counts (1-15 hops).

Typical Internet paths are 3-8 hops. This analysis focuses on real-world scenarios.

Testing hop counts: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15

## CRITICAL REAL-WORLD METRICS

### Message Size Analysis

| Hops | Size (KB) | Bytes/Hop | Fits Jumbo? | Network Status |
|------|-----------|-----------|-------------|----------------|
| 1    | 0.67      | 690.0     | YES         | Standard Ethernet |
| 2    | 1.32      | 678.0     | YES         | Standard Ethernet |
| 3    | 1.98      | 676.3     | YES         | Jumbo Frame OK |
| 4    | 2.62      | 670.5     | YES         | Jumbo Frame OK |
| 5    | 3.28      | 671.4     | YES         | Jumbo Frame OK |
| 6    | 3.92      | 668.7     | YES         | Jumbo Frame OK |
| 7    | 4.57      | 667.9     | YES         | Jumbo Frame OK |
| 8    | 5.22      | 668.5     | YES         | Jumbo Frame OK |
| 9    | 5.88      | 669.4     | YES         | Jumbo Frame OK |
| 10   | 6.51      | 666.4     | YES         | Jumbo Frame OK |
| 12   | 7.80      | 665.8     | YES         | Jumbo Frame OK |
| 15   | 9.76      | 666.0     | NO          | TCP seg (2x) |

### PERFORMANCE METRICS (Critical for Router Deployment)

#### Signing Performance (Time to generate signature at each AS)

| Hops | Total (ms) | Per-Hop (ms) | Per-Hop (μs) |
|------|------------|--------------|--------------|
| 1    | 0.37       | 0.37         | 373          |
| 2    | 0.54       | 0.27         | 268          |
| 3    | 0.78       | 0.26         | 262          |
| 4    | 1.09       | 0.27         | 271          |
| 5    | 1.31       | 0.26         | 261          |
| 6    | 1.54       | 0.26         | 257          |
| 7    | 1.92       | 0.27         | 275          |
| 8    | 2.27       | 0.28         | 283          |
| 9    | 2.33       | 0.26         | 259          |
| 10   | 2.56       | 0.26         | 256          |
| 12   | 3.17       | 0.26         | 264          |
| 15   | 3.98       | 0.27         | 265          |

#### Verification Performance (Time to verify at receiving router)

| Hops | Total (ms) | Per-Hop (ms) | Per-Hop (μs) |
|------|------------|--------------|--------------|
| 1    | 0.12       | 0.12         | 124          |
| 2    | 0.15       | 0.08         | 76           |
| 3    | 0.23       | 0.08         | 77           |
| 4    | 0.29       | 0.07         | 73           |
| 5    | 0.36       | 0.07         | 72           |
| 6    | 0.43       | 0.07         | 71           |
| 7    | 0.46       | 0.07         | 66           |
| 8    | 0.54       | 0.07         | 67           |
| 9    | 0.58       | 0.06         | 64           |
| 10   | 0.80       | 0.08         | 80           |
| 12   | 1.00       | 0.08         | 83           |
| 15   | 1.14       | 0.08         | 76           |

#### Total Processing Time (Signing + Verification)

| Hops | Total (ms) | Per-Hop (ms) | Throughput (paths/sec) |
|------|------------|--------------|------------------------|
| 1    | 0.50       | 0.50         | 2010.7                 |
| 2    | 0.69       | 0.34         | 1454.8                 |
| 3    | 1.02       | 0.34         | 983.9                  |
| 4    | 1.38       | 0.34         | 726.7                  |
| 5    | 1.67       | 0.33         | 600.1                  |
| 6    | 1.97       | 0.33         | 508.3                  |
| 7    | 2.38       | 0.34         | 420.1                  |
| 8    | 2.80       | 0.35         | 356.6                  |
| 9    | 2.91       | 0.32         | 343.7                  |
| 10   | 3.37       | 0.34         | 297.1                  |
| 12   | 4.17       | 0.35         | 239.9                  |
| 15   | 5.12       | 0.34         | 195.4                  |

### OVERHEAD ANALYSIS

| Hops | Sig Size | Overhead | Total Size | Variable/Hop |
|------|----------|----------|------------|--------------|
| 1    | 652.0    | 38.0     | 690.0      | 690.0        |
| 2    | 654.5    | 47.0     | 1356.0     | 678.0        |
| 3    | 657.7    | 56.0     | 2029.0     | 676.3        |
| 4    | 654.2    | 65.0     | 2682.0     | 670.5        |
| 5    | 656.6    | 74.0     | 3357.0     | 671.4        |
| 6    | 654.8    | 83.0     | 4012.0     | 668.7        |
| 7    | 654.7    | 92.0     | 4675.0     | 667.9        |
| 8    | 655.9    | 101.0    | 5348.0     | 668.5        |
| 9    | 657.2    | 110.0    | 6025.0     | 669.4        |
| 10   | 654.5    | 119.0    | 6664.0     | 666.4        |
| 12   | 654.4    | 137.0    | 7990.0     | 665.8        |
| 15   | 655.1    | 164.0    | 9990.0     | 666.0        |

## REAL-WORLD DEPLOYMENT INSIGHTS

### Typical Internet Paths (3-8 hops)

- Average message size: 3.60 KB
- Average signing time per hop: 0.27 ms (268 μs)
- Average verification time per hop: 0.07 ms (71 μs)
- Average total processing time: 1.87 ms

### Long Paths (9-15 hops)

- Average message size: 7.49 KB
- Average signing time per hop: 0.26 ms (261 μs)
- Average verification time per hop: 0.08 ms (76 μs)
- Average total processing time: 3.89 ms

### Scaling Behavior

- Message size scales linearly: YES ✓
- Signing scales linearly: NO ✗
- Verification scales linearly: NO ✗
- Average bytes per hop: 671.6 bytes
- Average signing time per hop: 0.27 ms
- Average verification time per hop: 0.08 ms

### Network Compatibility Summary

- Fits in jumbo frame: up to 12 hops (7.80 KB)
- Requires TCP segmentation: 15-15 hops (up to 2 segments)

## KEY FINDINGS FOR REAL-WORLD DEPLOYMENT

1. Typical path (3-8 hops): ~3.9 KB message
   - Processing time: ~2.0 ms
   - Per-hop overhead: ~669 bytes

2. Performance is consistent: ~275 μs signing, ~77 μs verification per hop

3. All signatures valid: YES ✓

4. Router throughput estimate (5-hop path):
   - ~600 BGPsec routes/second
   - ~36008 routes/minute

---

Generated by test_scaling.py  
Author: Sam Moes  
Date: December 2025

