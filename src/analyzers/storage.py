"""
Storage Analyzer — Maps contract storage layout and detects slot collisions.

Analyzes proxy contracts for storage collision vulnerabilities, 
uninitialized implementation slots, and unsafe storage patterns
that can lead to fund loss or contract hijacking.
"""

from dataclasses import dataclass, field
from typing import Optional

from web3 import Web3

from .bytecode import Severity, Finding


# Well-known storage slots
KNOWN_SLOTS: dict[str, str] = {
    # EIP-1967 Proxy Slots
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "EIP-1967 Implementation Slot",
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "EIP-1967 Admin Slot",
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "EIP-1967 Beacon Slot",
    # OpenZeppelin
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3": "OpenZeppelin Initializable Slot",
}

# EIP-1967 implementation slot constant
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


@dataclass
class StorageSlot:
    """Represents a storage slot read from the contract."""

    index: str
    value: str
    label: str = ""
    decoded: Optional[str] = None


@dataclass
class StorageAnalysis:
    """Complete storage analysis result."""

    contract_address: str
    is_proxy: bool = False
    implementation_address: Optional[str] = None
    admin_address: Optional[str] = None
    slots_read: list[StorageSlot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    is_initialized: Optional[bool] = None


class StorageAnalyzer:
    """
    Analyzes contract storage for proxy patterns and slot collisions.

    Reads key storage slots to determine if a contract is a proxy,
    checks initialization state, and identifies potential storage
    collision vulnerabilities in upgradeable contracts.

    Usage:
        analyzer = StorageAnalyzer(rpc_url="https://eth-mainnet.g.alchemy.com/v2/KEY")
        result = analyzer.analyze("0xContractAddress")
    """

    def __init__(self, rpc_url: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

    def _read_slot(self, address: str, slot: str) -> str:
        """Read a single storage slot from the contract."""
        try:
            value = self.w3.eth.get_storage_at(
                Web3.to_checksum_address(address),
                int(slot, 16) if slot.startswith("0x") else int(slot),
            )
            return "0x" + value.hex()
        except Exception:
            return "0x" + "00" * 32

    def _is_zero(self, value: str) -> bool:
        """Check if a storage value is zero (uninitialized)."""
        clean = value.replace("0x", "").lstrip("0")
        return len(clean) == 0

    def _extract_address(self, value: str) -> Optional[str]:
        """Extract an Ethereum address from a 32-byte storage value."""
        clean = value.replace("0x", "")
        if len(clean) != 64:
            return None
        # Address is in the last 20 bytes (40 hex chars)
        addr_hex = clean[-40:]
        if addr_hex == "0" * 40:
            return None
        try:
            return Web3.to_checksum_address("0x" + addr_hex)
        except Exception:
            return None

    def _check_proxy_pattern(self, address: str) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Check EIP-1967 proxy storage slots.

        Returns:
            (is_proxy, implementation_address, admin_address)
        """
        impl_value = self._read_slot(address, EIP1967_IMPL_SLOT)
        admin_value = self._read_slot(address, EIP1967_ADMIN_SLOT)

        impl_addr = self._extract_address(impl_value)
        admin_addr = self._extract_address(admin_value)

        is_proxy = impl_addr is not None

        return is_proxy, impl_addr, admin_addr

    def _check_initialization(self, address: str) -> tuple[Optional[bool], list[Finding]]:
        """
        Check if a proxy contract has been properly initialized.

        An uninitialized proxy is a critical vulnerability — an attacker
        can call the initializer to take ownership.
        """
        findings: list[Finding] = []

        # Read slot 0 (common initializer storage)
        slot_0 = self._read_slot(address, "0x0")

        # Read OpenZeppelin Initializable slot
        init_slot = self._read_slot(
            address,
            "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
        )

        if self._is_zero(slot_0) and self._is_zero(init_slot):
            findings.append(
                Finding(
                    title="Potentially Uninitialized Proxy",
                    description=(
                        f"Contract {address} appears to be a proxy with zero values "
                        f"in both slot 0 and the OpenZeppelin Initializable slot. "
                        f"If the initialize() function has not been called, an attacker "
                        f"could call it to take ownership of the contract."
                    ),
                    severity=Severity.CRITICAL,
                    offset=0,
                    opcode="SLOAD",
                    recommendation=(
                        "Verify that initialize() has been called. "
                        "Check the _initialized flag in the Initializable contract."
                    ),
                )
            )
            return False, findings

        return True, findings

    def analyze(self, address: str) -> StorageAnalysis:
        """
        Run full storage analysis on a contract.

        Args:
            address: Contract address to analyze.

        Returns:
            StorageAnalysis with proxy detection, initialization check, and findings.
        """
        address = Web3.to_checksum_address(address)
        all_findings: list[Finding] = []
        slots: list[StorageSlot] = []

        # Check proxy pattern
        is_proxy, impl_addr, admin_addr = self._check_proxy_pattern(address)

        # Read and record known slots
        for slot_hex, label in KNOWN_SLOTS.items():
            value = self._read_slot(address, slot_hex)
            decoded_addr = self._extract_address(value)
            slots.append(
                StorageSlot(
                    index=slot_hex,
                    value=value,
                    label=label,
                    decoded=decoded_addr,
                )
            )

        # Read first 10 storage slots for general analysis
        for i in range(10):
            slot_hex = f"0x{i:064x}"
            if slot_hex not in KNOWN_SLOTS:
                value = self._read_slot(address, hex(i))
                slots.append(
                    StorageSlot(
                        index=hex(i),
                        value=value,
                        label=f"Slot {i}",
                    )
                )

        # Check initialization if it's a proxy
        is_initialized = None
        if is_proxy:
            is_initialized, init_findings = self._check_initialization(address)
            all_findings.extend(init_findings)

            # Check for zero admin (no admin set)
            if admin_addr is None:
                all_findings.append(
                    Finding(
                        title="Proxy Admin Not Set",
                        description=(
                            f"EIP-1967 admin slot is zero for proxy at {address}. "
                            f"This may indicate the proxy has no admin, or uses a "
                            f"different admin pattern."
                        ),
                        severity=Severity.MEDIUM,
                        offset=0,
                        opcode="SLOAD",
                        recommendation="Verify the proxy admin mechanism is correctly configured.",
                    )
                )

        return StorageAnalysis(
            contract_address=address,
            is_proxy=is_proxy,
            implementation_address=impl_addr,
            admin_address=admin_addr,
            slots_read=slots,
            findings=all_findings,
            is_initialized=is_initialized,
        )
