# BGPsec with Falcon-512: A Working Post-Quantum Implementation

This repository contains a working implementation of BGPsec (RFC 8205) using pure Falcon-512 post-quantum signatures. The implementation demonstrates that 15-hop BGPsec paths with Falcon-512 are technically feasible.

## What This Proves

Theres been a lot of discussion about whether post-quantum cryptography can work for BGP security. People have claimed that signature sizes would be too large, that performance would be too slow, or that the messages wouldn't fit in network infrastructure. This implementation proves otherwise.

I've successfully created and verified 15-hop BGPsec paths (and 80-hop) with Falcon-512 signatures. The total message size is around 10 KB, which fits comfortably in modern network infrastructure. Signing takes about 0.3 milliseconds per hop, and verification takes about 0.1 milliseconds per hop. All signatures verify correctly, and the implementation follows RFC 8205 precisely.

The research impact is clear: this demonstrates that post-quantum BGPsec with Falcon-512 is not only possible but also practical. 

The takeaway: this work proves the technical feasibility. Deployment challenges are separate issues involving coordination, economics, and policy decisions. But the underlying protocol and cryptography work, and they work well.

## Technical Results

### 15-Hop Realistic Test

This represents a realistic long path scenario (typical Internet paths are 3-8 hops):


![15hop_log](results/15hop_log.png)

The message exceeds standard jumbo frame limits (9216 bytes) but fits within observed real-world BGP message sizes (8-15 KB range). TCP segmentation handles this transparently on modern networks.

### 80-Hop Extreme Stress Test

This stress test demonstrates scalability far beyond realistic scenarios:


![80hop_log](results/80hop_log.png)

The 80-hop test is included to demonstrate that even at unrealistic path lengths, the protocol and cryptography remain functional. Real-world deployment would typically see paths of 3-8 hops, making this an extreme demonstration.

## Project Structure

```
bgpsec-falcon512/
├── README.md                 # This file
├── modules/                  # Core implementation modules
│   ├── __init__.py           # Package exports
│   ├── bgpsec.py             # BGPsec protocol implementation
│   ├── bgp_message.py        # BGP UPDATE message encoding
│   └── path_signature.py     # Path signature generation/verification
├── test_15hop.py             # 15-hop realistic path test
├── test_80hop.py             # 80-hop extreme stress test
├── demo.py                   # Interactive demonstration tool
├── requirements.txt          # Python dependencies
├── Dockerfile                # Docker build configuration
├── docker-compose.yml        # Docker Compose setup
├── docker-entrypoint.sh      # Container entrypoint script
└── examples/                 # Generated output files
    ├── 15hop_update.bin      # Binary BGP UPDATE message
    └── validation_results.json  # Test results
```

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose (recommended for Windows users)

### Docker Setup (Recommended)

The easiest way to run this, especially on Windows, is using Docker. The Docker setup handles all the dependencies including building liboqs from source.

First, build the Docker image:

```bash
docker-compose build
```

To run the 15-hop realistic test:

```bash
docker-compose run --rm bgpsec python test_15hop.py
```

To run the 80-hop extreme stress test:

```bash
docker-compose run --rm bgpsec python test_80hop.py
```


The Docker container automatically verifies that liboqs is properly installed.

### Native Installation

If you prefer to run this natively, you'll need to install liboqs and liboqs-python. On Linux, this typically requires:

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install build-essential python3-dev git cmake ninja-build libssl-dev

# Install Python dependencies
pip install -r requirements.txt
```

On Windows, the liboqs build process can be challenging. Docker is STRONGLY recommended for Windows users.
(I've only tested it on Docker and developed it using Docker)

Once dependencies are installed, run the tests:

```bash
# Realistic 15-hop test
python test_15hop.py

# Extreme 80-hop stress test
python test_80hop.py
```

## Reproducibility

All results are reproducible. The test script generates deterministic outputs based on the AS path and NLRI prefixes you provide. The example 15-hop path uses real AS numbers from major network operators (Google, Level 3, Telia, NTT, Cogent, etc.) combined with some test AS numbers.

To reproduce our exact results:

1. Use the same AS path as in `test_15hop.py` (lines 26-42)
2. Use the same NLRI prefix: 192.0.2.0/24
3. Run the test and compare outputs

The cryptographic signatures will differ each run because keypairs are generated fresh, but the message sizes, performance metrics, and verification results should be consistent. The signature sizes vary slightly (650-690 bytes) as this is inherent to Falcon-512, but the averages should match.

All output is saved to the `examples/` directory:
- `15hop_update.bin`: The complete BGP UPDATE message in binary format
- `validation_results.json`: Detailed test results including sizes, timings, and verification status

## Implementation Details

### BGPsec Suite ID

I used a temporary suite ID of 0x03 for Falcon-512. This is a proof-of-concept value pending IETF standardization of a Falcon-512 suite ID for BGPsec.

### Path Signature Algorithm

The implementation follows RFC 8205 precisely. Each AS in the path signs:

```
Data_To_Sign = Secure_Path | Signature_Block | NLRI
Signature = Sign(SK_i, Data_To_Sign)
```

Where:
- SK_i is the private key of AS i
- Secure_Path contains all AS path segments up to this hop
- Signature_Block contains all signatures from previous hops
- NLRI is the Network Layer Reachability Information

Each hop builds incrementally on the previous hops, creating a chain of signatures that proves the entire path.

### Cryptographic Library

This implementation uses liboqs (Open Quantum Safe library) via the liboqs-python bindings. Falcon-512 is provided by liboqs, which implements the algorithm.

## Validation

The implementation includes complete validation:

- Path signature generation: Each hop generates a Falcon-512 signature
- Path signature verification: All signatures are verified using their corresponding public keys
- BGP UPDATE message encoding: Messages are encoded according to RFC 4271
- Secure_Path attribute encoding: Attributes follow RFC 8205 format
- Signature_Block encoding: Signature blocks are properly structured

The test script performs end-to-end validation and reports detailed results including which signatures passed or failed verification.

## Citation

If you use this code or reference this work, please cite:

```bibtex
@software{bgpsec_falcon512_2025,
  author = {Moes, Sam},
  title = {BGPsec Implementation with Falcon-512 Post-Quantum Signatures},
  year = {2025},
  month = {December},
  url = {https://github.com/daemon-tech/bgpsec-falcon512},
}
```

## License

MIT License. See LICENSE file for details.

## Acknowledgments

This implementation builds on:

- liboqs (https://github.com/open-quantum-safe/liboqs) - The Open Quantum Safe cryptography library
- RFC 8205 - The BGPsec Protocol Specification
- RFC 4271 - The BGP-4 Protocol Specification

## Author

Sam Moes  
December 2025
