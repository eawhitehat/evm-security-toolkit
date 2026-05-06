"""
ERC-4626 Vault Detector — Identifies vault inflation and share manipulation attacks.

Detects the "first depositor" inflation attack vector where an attacker
can manipulate the exchange rate between shares and assets to steal
funds from subsequent depositors.
"""

import re
from dataclasses import dataclass, field
from src.analyzers.bytecode import Severity, Finding


@dataclass
class VaultAnalysis:
    """Analysis results for ERC-4626 vault patterns."""

    is_erc4626: bool = False
    has_virtual_offset: bool = False
    has_min_deposit: bool = False
    has_dead_shares: bool = False
    findings: list[Finding] = field(default_factory=list)


class VaultDetector:
    """
    Detects ERC-4626 vault vulnerabilities.

    The primary attack vector is vault share inflation:
    1. Attacker deposits 1 wei to mint 1 share
    2. Attacker donates large amount directly to vault (transfer, not deposit)
    3. Exchange rate is now inflated (1 share = huge assets)
    4. Victim deposits → gets 0 shares due to rounding → attacker steals funds

    Mitigations detected:
    - Virtual offset (OpenZeppelin _decimalsOffset)
    - Minimum deposit enforcement
    - Dead shares (initial shares minted to zero address)
    """

    # Patterns indicating ERC-4626 implementation
    ERC4626_PATTERNS = [
        re.compile(r"ERC4626", re.I),
        re.compile(r"function\s+deposit\s*\(\s*uint\d*\s+assets", re.I),
        re.compile(r"function\s+redeem\s*\(\s*uint\d*\s+shares", re.I),
        re.compile(r"function\s+convertToShares", re.I),
        re.compile(r"function\s+convertToAssets", re.I),
        re.compile(r"function\s+totalAssets", re.I),
        re.compile(r"function\s+previewDeposit", re.I),
    ]

    # Patterns indicating inflation protection
    VIRTUAL_OFFSET_PATTERNS = [
        re.compile(r"_decimalsOffset", re.I),
        re.compile(r"virtualAssets", re.I),
        re.compile(r"virtualShares", re.I),
        re.compile(r"\+\s*1\b.*totalAssets|totalAssets.*\+\s*1\b", re.I),
        re.compile(r"\+\s*1e\d", re.I),
        re.compile(r"10\s*\*\*\s*_decimalsOffset", re.I),
    ]

    MIN_DEPOSIT_PATTERNS = [
        re.compile(r"require\(.*assets\s*>=?\s*\w*[Mm]in", re.I),
        re.compile(r"require\(.*shares\s*>=?\s*\w*[Mm]in", re.I),
        re.compile(r"if\s*\(.*assets\s*<\s*\w*[Mm]in", re.I),
        re.compile(r"MIN_DEPOSIT", re.I),
        re.compile(r"minDeposit", re.I),
    ]

    DEAD_SHARES_PATTERNS = [
        re.compile(r"_mint\(\s*address\(0\)", re.I),
        re.compile(r"_mint\(\s*address\(0xdead\)", re.I),
        re.compile(r"DEAD_SHARES", re.I),
        re.compile(r"_mint\(\s*address\(0\)\s*,\s*\d+", re.I),
    ]

    # Dangerous patterns: raw division without offset
    DANGEROUS_CONVERSION = [
        # shares = assets * totalSupply / totalAssets — vulnerable without +1
        re.compile(r"assets\s*\*\s*totalSupply.*\/.*totalAssets(?!\s*\+)", re.I),
        re.compile(r"mulDiv\s*\(.*totalSupply.*totalAssets\s*\)", re.I),
    ]

    def __init__(self, source_code: str):
        self.source = source_code

    def _matches_any(self, patterns: list[re.Pattern]) -> bool:
        return any(p.search(self.source) for p in patterns)

    def _find_line(self, pattern: re.Pattern) -> int:
        for i, line in enumerate(self.source.split("\n"), 1):
            if pattern.search(line):
                return i
        return 0

    def analyze(self) -> VaultAnalysis:
        """Run ERC-4626 vault vulnerability analysis."""
        is_4626 = sum(1 for p in self.ERC4626_PATTERNS if p.search(self.source)) >= 3
        if not is_4626:
            return VaultAnalysis(is_erc4626=False)

        has_virtual = self._matches_any(self.VIRTUAL_OFFSET_PATTERNS)
        has_min_dep = self._matches_any(self.MIN_DEPOSIT_PATTERNS)
        has_dead = self._matches_any(self.DEAD_SHARES_PATTERNS)
        findings: list[Finding] = []

        # Check for inflation attack vulnerability
        if not has_virtual and not has_dead:
            findings.append(Finding(
                title="ERC-4626 Vault Inflation Attack",
                description=(
                    "This ERC-4626 vault has no protection against the first depositor "
                    "inflation attack. An attacker can:\n"
                    "  1. Deposit 1 wei to mint 1 share\n"
                    "  2. Transfer a large amount directly to the vault\n"
                    "  3. Inflate the exchange rate (1 share = huge assets)\n"
                    "  4. Subsequent depositors lose funds due to rounding to 0 shares\n"
                    "No virtual offset (_decimalsOffset) or dead shares detected."
                ),
                severity=Severity.CRITICAL,
                offset=0,
                opcode="ERC4626",
                recommendation=(
                    "Use OpenZeppelin's ERC4626 with _decimalsOffset() override "
                    "(recommended: 3-6), or mint dead shares to address(0) on initialization, "
                    "or enforce a minimum deposit amount."
                ),
            ))

        # Check for missing minimum deposit
        if not has_min_dep and not has_virtual:
            findings.append(Finding(
                title="No Minimum Deposit Enforcement",
                description=(
                    "The vault does not enforce a minimum deposit amount. "
                    "Combined with potential rounding issues, small deposits "
                    "may result in 0 shares minted, causing silent fund loss."
                ),
                severity=Severity.MEDIUM,
                offset=0,
                opcode="ERC4626",
                recommendation="Add require(shares > 0) in deposit() or enforce a minimum deposit.",
            ))

        # Check for dangerous share calculation without offset
        for pattern in self.DANGEROUS_CONVERSION:
            if pattern.search(self.source):
                line = self._find_line(pattern)
                findings.append(Finding(
                    title="Vault Share Calculation Without Virtual Offset",
                    description=(
                        f"Share/asset conversion at line {line} divides without "
                        f"a virtual offset (+1 or _decimalsOffset). This makes the "
                        f"exchange rate manipulable via direct token transfers."
                    ),
                    severity=Severity.HIGH,
                    offset=line,
                    opcode="ERC4626",
                    recommendation="Add virtual offset: (assets * (totalSupply + 1)) / (totalAssets + 1).",
                ))
                break

        return VaultAnalysis(
            is_erc4626=True,
            has_virtual_offset=has_virtual,
            has_min_deposit=has_min_dep,
            has_dead_shares=has_dead,
            findings=findings,
        )
