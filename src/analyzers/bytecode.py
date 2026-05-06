"""
Bytecode Analyzer — Detects dangerous opcode patterns in EVM bytecode.

Scans compiled smart contract bytecode for suspicious instruction sequences
that may indicate vulnerabilities such as unprotected DELEGATECALL, 
SELFDESTRUCT without access control, or dangerous storage patterns.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OpcodeCategory(str, Enum):
    DELEGATE_CALL = "DELEGATECALL"
    SELF_DESTRUCT = "SELFDESTRUCT"
    CALL = "CALL"
    STATICCALL = "STATICCALL"
    CREATE = "CREATE"
    CREATE2 = "CREATE2"
    SSTORE = "SSTORE"
    SLOAD = "SLOAD"
    CALLVALUE = "CALLVALUE"
    CALLDATALOAD = "CALLDATALOAD"


# EVM opcode mapping (relevant subset for security analysis)
OPCODES: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x10: "LT",
    0x11: "GT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x20: "SHA3",
    0x31: "BALANCE",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x5B: "JUMPDEST",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

# Dangerous patterns: opcode sequences that indicate potential vulnerabilities
DANGEROUS_PATTERNS: dict[str, dict] = {
    "unprotected_delegatecall": {
        "description": "DELEGATECALL without CALLER check — potential proxy hijack",
        "severity": Severity.CRITICAL,
        "opcodes": ["DELEGATECALL"],
        "requires_absence": ["CALLER", "EQ", "JUMPI"],  # No access control before DELEGATECALL
    },
    "unprotected_selfdestruct": {
        "description": "SELFDESTRUCT without access control — contract can be destroyed by anyone",
        "severity": Severity.CRITICAL,
        "opcodes": ["SELFDESTRUCT"],
        "requires_absence": ["CALLER", "EQ"],
    },
    "unchecked_call_return": {
        "description": "CALL without return value check — silent failure on external call",
        "severity": Severity.HIGH,
        "opcodes": ["CALL", "POP"],  # CALL followed by POP = discarding return value
        "requires_absence": [],
    },
    "tx_origin_auth": {
        "description": "tx.origin used for authentication — phishing vector",
        "severity": Severity.HIGH,
        "opcodes": ["ORIGIN", "EQ"],
        "requires_absence": [],
    },
    "timestamp_dependency": {
        "description": "TIMESTAMP used in conditional logic — miner-manipulable",
        "severity": Severity.MEDIUM,
        "opcodes": ["TIMESTAMP", "LT"],
        "requires_absence": [],
    },
    "block_hash_randomness": {
        "description": "BLOCKHASH used for randomness — predictable by miners",
        "severity": Severity.MEDIUM,
        "opcodes": ["BLOCKHASH"],
        "requires_absence": [],
    },
}


@dataclass
class Finding:
    """Represents a single security finding in the bytecode."""

    title: str
    description: str
    severity: Severity
    offset: int
    opcode: str
    context: str = ""
    recommendation: str = ""


@dataclass
class BytecodeAnalysis:
    """Complete analysis result for a bytecode scan."""

    contract_address: Optional[str] = None
    bytecode_length: int = 0
    opcode_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    opcode_frequency: dict[str, int] = field(default_factory=dict)
    has_delegatecall: bool = False
    has_selfdestruct: bool = False
    has_create2: bool = False
    external_call_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def risk_score(self) -> float:
        """Weighted risk score: critical=10, high=5, medium=2, low=1."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return sum(weights.get(f.severity, 0) for f in self.findings)


class BytecodeAnalyzer:
    """
    Analyzes EVM bytecode for dangerous opcode patterns.

    Disassembles raw bytecode into opcodes and scans for known
    vulnerability patterns including unprotected DELEGATECALL,
    SELFDESTRUCT without access control, and unchecked external calls.

    Usage:
        analyzer = BytecodeAnalyzer(bytecode="0x6080604052...")
        result = analyzer.scan()
        for finding in result.findings:
            print(f"[{finding.severity}] {finding.title}")
    """

    def __init__(self, bytecode: str, address: str | None = None):
        self.raw_bytecode = bytecode.replace("0x", "")
        self.address = address
        self._opcodes: list[tuple[int, str, str]] = []  # (offset, opcode_name, raw_hex)

    def disassemble(self) -> list[tuple[int, str, str]]:
        """Disassemble raw bytecode into (offset, opcode_name, raw_bytes) tuples."""
        bytecode = bytes.fromhex(self.raw_bytecode)
        opcodes: list[tuple[int, str, str]] = []
        i = 0

        while i < len(bytecode):
            op = bytecode[i]
            name = OPCODES.get(op, f"UNKNOWN(0x{op:02x})")

            # Handle PUSH1-PUSH32 (0x60-0x7f)
            if 0x60 <= op <= 0x7F:
                push_size = op - 0x5F
                push_data = bytecode[i + 1 : i + 1 + push_size]
                name = f"PUSH{push_size}"
                raw = f"0x{push_data.hex()}"
                opcodes.append((i, name, raw))
                i += 1 + push_size
            else:
                opcodes.append((i, name, f"0x{op:02x}"))
                i += 1

        self._opcodes = opcodes
        return opcodes

    def _count_opcodes(self) -> dict[str, int]:
        """Count frequency of each opcode in the bytecode."""
        freq: dict[str, int] = {}
        for _, name, _ in self._opcodes:
            base_name = name.split("(")[0]  # Strip UNKNOWN args
            freq[base_name] = freq.get(base_name, 0) + 1
        return freq

    def _detect_unprotected_delegatecall(self) -> list[Finding]:
        """
        Detect DELEGATECALL instructions without preceding CALLER check.

        A DELEGATECALL without access control allows any external account
        to execute arbitrary code in the context of the contract, potentially
        taking ownership of proxy contracts or draining funds.
        """
        findings: list[Finding] = []
        opcode_names = [name for _, name, _ in self._opcodes]

        for idx, (offset, name, _) in enumerate(self._opcodes):
            if name != "DELEGATECALL":
                continue

            # Look back up to 30 opcodes for a CALLER check
            window_start = max(0, idx - 30)
            preceding = opcode_names[window_start:idx]

            has_caller_check = "CALLER" in preceding and "EQ" in preceding
            has_jumpi_guard = "JUMPI" in preceding

            if not (has_caller_check and has_jumpi_guard):
                findings.append(
                    Finding(
                        title="Unprotected DELEGATECALL",
                        description=(
                            f"DELEGATECALL at offset {offset} (0x{offset:04x}) "
                            f"has no preceding CALLER/EQ/JUMPI access control pattern. "
                            f"An attacker may be able to hijack the contract's execution context."
                        ),
                        severity=Severity.CRITICAL,
                        offset=offset,
                        opcode="DELEGATECALL",
                        recommendation=(
                            "Add msg.sender validation before DELEGATECALL. "
                            "For proxies, ensure the implementation slot is correctly initialized."
                        ),
                    )
                )

        return findings

    def _detect_unprotected_selfdestruct(self) -> list[Finding]:
        """Detect SELFDESTRUCT without preceding access control."""
        findings: list[Finding] = []
        opcode_names = [name for _, name, _ in self._opcodes]

        for idx, (offset, name, _) in enumerate(self._opcodes):
            if name != "SELFDESTRUCT":
                continue

            window_start = max(0, idx - 30)
            preceding = opcode_names[window_start:idx]

            has_caller_check = "CALLER" in preceding and "EQ" in preceding

            if not has_caller_check:
                findings.append(
                    Finding(
                        title="Unprotected SELFDESTRUCT",
                        description=(
                            f"SELFDESTRUCT at offset {offset} (0x{offset:04x}) "
                            f"has no access control. Anyone can destroy this contract "
                            f"and redirect remaining ETH balance."
                        ),
                        severity=Severity.CRITICAL,
                        offset=offset,
                        opcode="SELFDESTRUCT",
                        recommendation="Restrict SELFDESTRUCT to contract owner with onlyOwner modifier.",
                    )
                )

        return findings

    def _detect_unchecked_calls(self) -> list[Finding]:
        """Detect CALL instructions whose return value is immediately POPped (discarded)."""
        findings: list[Finding] = []

        for idx, (offset, name, _) in enumerate(self._opcodes):
            if name != "CALL":
                continue

            # Check if next opcode is POP (discarding return value)
            if idx + 1 < len(self._opcodes) and self._opcodes[idx + 1][1] == "POP":
                findings.append(
                    Finding(
                        title="Unchecked External Call Return Value",
                        description=(
                            f"CALL at offset {offset} (0x{offset:04x}) — "
                            f"return value is discarded (POP). If the external call fails, "
                            f"execution continues silently, potentially leaving state inconsistent."
                        ),
                        severity=Severity.HIGH,
                        offset=offset,
                        opcode="CALL",
                        recommendation="Check the return value of external calls: require(success, '...').",
                    )
                )

        return findings

    def _detect_tx_origin(self) -> list[Finding]:
        """Detect tx.origin usage in authentication context."""
        findings: list[Finding] = []
        opcode_names = [name for _, name, _ in self._opcodes]

        for idx, (offset, name, _) in enumerate(self._opcodes):
            if name != "ORIGIN":
                continue

            # Check if followed by EQ within 5 opcodes (comparison for auth)
            window_end = min(len(opcode_names), idx + 5)
            following = opcode_names[idx:window_end]

            if "EQ" in following:
                findings.append(
                    Finding(
                        title="tx.origin Authentication",
                        description=(
                            f"ORIGIN at offset {offset} (0x{offset:04x}) used in equality check. "
                            f"tx.origin-based authentication is vulnerable to phishing attacks "
                            f"where a malicious contract calls the victim contract on behalf of the user."
                        ),
                        severity=Severity.HIGH,
                        offset=offset,
                        opcode="ORIGIN",
                        recommendation="Replace tx.origin with msg.sender for authentication.",
                    )
                )

        return findings

    def _detect_timestamp_dependency(self) -> list[Finding]:
        """Detect block.timestamp in conditional logic."""
        findings: list[Finding] = []
        opcode_names = [name for _, name, _ in self._opcodes]

        for idx, (offset, name, _) in enumerate(self._opcodes):
            if name != "TIMESTAMP":
                continue

            window_end = min(len(opcode_names), idx + 10)
            following = opcode_names[idx:window_end]

            comparisons = {"LT", "GT", "EQ", "SLT", "SGT"}
            if comparisons.intersection(following):
                findings.append(
                    Finding(
                        title="Timestamp Dependency",
                        description=(
                            f"TIMESTAMP at offset {offset} (0x{offset:04x}) used in comparison. "
                            f"block.timestamp can be manipulated by miners within a ~15 second window."
                        ),
                        severity=Severity.MEDIUM,
                        offset=offset,
                        opcode="TIMESTAMP",
                        recommendation="Avoid using block.timestamp for critical logic. Use block.number or an oracle.",
                    )
                )

        return findings

    def scan(self) -> BytecodeAnalysis:
        """
        Run full bytecode analysis pipeline.

        Returns:
            BytecodeAnalysis with all findings, opcode stats, and risk score.
        """
        if not self.raw_bytecode:
            return BytecodeAnalysis(contract_address=self.address)

        self.disassemble()
        freq = self._count_opcodes()

        # Collect all findings
        all_findings: list[Finding] = []
        all_findings.extend(self._detect_unprotected_delegatecall())
        all_findings.extend(self._detect_unprotected_selfdestruct())
        all_findings.extend(self._detect_unchecked_calls())
        all_findings.extend(self._detect_tx_origin())
        all_findings.extend(self._detect_timestamp_dependency())

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        return BytecodeAnalysis(
            contract_address=self.address,
            bytecode_length=len(self.raw_bytecode) // 2,
            opcode_count=len(self._opcodes),
            findings=all_findings,
            opcode_frequency=freq,
            has_delegatecall=freq.get("DELEGATECALL", 0) > 0,
            has_selfdestruct=freq.get("SELFDESTRUCT", 0) > 0,
            has_create2=freq.get("CREATE2", 0) > 0,
            external_call_count=(
                freq.get("CALL", 0) + freq.get("DELEGATECALL", 0) + freq.get("STATICCALL", 0)
            ),
        )
