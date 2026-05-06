# 🔍 EVM Security Toolkit

> Automated smart contract vulnerability detection framework for EVM-based blockchains.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Immunefi](https://img.shields.io/badge/Bug%20Bounty-Immunefi-purple.svg)](https://immunefi.com/)

## Overview

EVM Security Toolkit is a modular Python framework designed for **automated vulnerability detection** in Solidity smart contracts. It analyzes bytecode patterns, ABI structures, and contract state to identify critical security flaws before they become exploits.

Built by a security researcher for security researchers.

## Features

| Module | Description |
|--------|-------------|
| **Bytecode Analyzer** | Detects dangerous opcode patterns (DELEGATECALL, SELFDESTRUCT, unprotected SSTORE) |
| **ABI Parser** | Extracts and analyzes function signatures, access control patterns, and state mutability |
| **Vulnerability Detector** | Pattern-matching engine for reentrancy, oracle manipulation, flash loan vectors |
| **Storage Analyzer** | Maps storage slots, detects uninitialized proxies and slot collisions |
| **Contract Scanner** | Full pipeline: fetches verified source → analyzes → reports findings |

## Architecture

```
evm-security-toolkit/
├── src/
│   ├── analyzers/          # Bytecode & storage analysis engines
│   │   ├── bytecode.py     # Opcode pattern detection
│   │   └── storage.py      # Storage layout analysis
│   ├── parsers/            # ABI & source code parsers
│   │   └── abi_parser.py   # ABI extraction & function analysis
│   ├── detectors/          # Vulnerability detection modules
│   │   ├── reentrancy.py   # Cross-function & cross-contract reentrancy
│   │   ├── access.py       # Missing access control checks
│   │   ├── oracle.py       # Oracle manipulation vectors
│   │   └── arithmetic.py   # Precision loss & overflow patterns
│   └── utils/              # Shared utilities
│       ├── config.py       # Configuration management
│       ├── rpc.py          # EVM RPC client
│       └── reporter.py     # Finding report generator
├── tests/                  # Test suite
├── examples/               # Example usage & sample contracts
└── scanner.py              # CLI entry point
```

## Quick Start

### Installation

```bash
git clone https://github.com/eawhitehat/evm-security-toolkit.git
cd evm-security-toolkit
pip install -r requirements.txt
```

### Scan a Contract

```bash
# Scan a verified contract on Etherscan
python scanner.py --address 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D --chain ethereum

# Scan from local Solidity source
python scanner.py --file ./contracts/Vault.sol

# Scan bytecode directly
python scanner.py --bytecode 0x6080604052...

# Output JSON report
python scanner.py --address 0x... --chain bsc --output report.json
```

### Python API

```python
from src.analyzers.bytecode import BytecodeAnalyzer
from src.detectors.reentrancy import ReentrancyDetector
from src.parsers.abi_parser import ABIParser

# Analyze bytecode for dangerous patterns
analyzer = BytecodeAnalyzer(bytecode="0x6080604052...")
findings = analyzer.scan()

# Parse ABI for unprotected functions
parser = ABIParser.from_address("0x...", chain="ethereum")
unprotected = parser.detect_unprotected_externals()

# Run reentrancy detection
detector = ReentrancyDetector(source_code=solidity_source)
vulns = detector.analyze()
```

## Supported Chains

| Chain | RPC | Explorer |
|-------|-----|----------|
| Ethereum | ✅ | Etherscan |
| BNB Chain | ✅ | BscScan |
| Polygon | ✅ | PolygonScan |
| Arbitrum | ✅ | Arbiscan |
| Base | ✅ | BaseScan |

## Detection Categories

### Critical
- **Reentrancy** — Cross-function, cross-contract, and read-only reentrancy patterns
- **Oracle Manipulation** — Spot price reliance, TWAP manipulation windows
- **Flash Loan Vectors** — Invariant violations exploitable within single transaction
- **Proxy Vulnerabilities** — Uninitialized UUPS/Transparent proxies, storage collisions

### High
- **Access Control** — Missing `onlyOwner`, unprotected `selfdestruct`, open initializers
- **Arithmetic** — Precision loss in division-before-multiplication, unchecked downcasts
- **MEV Exposure** — Sandwich-vulnerable swap paths, front-runnable liquidations

### Medium
- **State Inconsistency** — Missing CEI pattern, cross-function state leaks
- **Input Validation** — Unchecked return values, missing zero-address checks

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b detector/new-vuln-type`)
3. Add tests for your detector
4. Submit a PR with a clear description of the vulnerability pattern detected

## Disclaimer

This tool is designed for **authorized security assessments only**. Always obtain proper authorization before scanning smart contracts. The authors are not responsible for misuse of this software.

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Author:** [@eawhitehat](https://github.com/eawhitehat) — Web3 Security Researcher & Bug Bounty Hunter
