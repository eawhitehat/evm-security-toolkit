"""
Transient Storage Detector — EIP-1153 TLOAD/TSTORE analysis.

Detects patterns related to EIP-1153 transient storage opcodes
introduced in the Cancun upgrade. Identifies:
- Reentrancy guards using transient storage
- Misuse of TSTORE/TLOAD that may not persist across call frames
- Missing TSTORE cleanup leading to stale transient state
"""

from dataclasses import dataclass, field
from typing import Optional
from src.analyzers.bytecode import Severity, Finding, OPCODES

# EIP-1153 opcodes (Cancun upgrade)
TLOAD_OPCODE = 0x5C
TSTORE_OPCODE = 0x5D

# Extend the opcode map
OPCODES[TLOAD_OPCODE] = "TLOAD"
OPCODES[TSTORE_OPCODE] = "TSTORE"


@dataclass
class TransientStorageAnalysis:
    """Analysis results for transient storage usage."""

    has_tload: bool = False
    has_tstore: bool = False
    tload_count: int = 0
    tstore_count: int = 0
    is_reentrancy_guard: bool = False
    findings: list[Finding] = field(default_factory=list)


class TransientStorageDetector:
    """
    Detects EIP-1153 transient storage patterns in bytecode and source.

    Transient storage (TLOAD/TSTORE) persists only for the duration of
    a transaction. It is commonly used for:
    - Gas-efficient reentrancy guards
    - Temporary callback locks
    - Cross-function communication within a single tx

    Pitfalls:
    - TSTORE values are NOT cleared between internal calls in the same tx
    - Using transient storage for persistent state is a bug
    - Missing TSTORE reset after use can cause logic errors
    """

    def __init__(self, bytecode: str = "", source_code: str = ""):
        self.bytecode = bytecode.replace("0x", "")
        self.source = source_code

    def _analyze_bytecode(self) -> TransientStorageAnalysis:
        """Scan bytecode for TLOAD/TSTORE opcodes."""
        if not self.bytecode:
            return TransientStorageAnalysis()

        raw = bytes.fromhex(self.bytecode)
        tload_count = 0
        tstore_count = 0
        tload_offsets: list[int] = []
        tstore_offsets: list[int] = []
        findings: list[Finding] = []

        i = 0
        while i < len(raw):
            op = raw[i]

            if op == TLOAD_OPCODE:
                tload_count += 1
                tload_offsets.append(i)
            elif op == TSTORE_OPCODE:
                tstore_count += 1
                tstore_offsets.append(i)

            # Skip PUSH data
            if 0x60 <= op <= 0x7F:
                i += (op - 0x5F) + 1
            else:
                i += 1

        # Detect reentrancy guard pattern: TLOAD → check → TSTORE(1) → ... → TSTORE(0)
        is_guard = tload_count >= 1 and tstore_count >= 2

        # Check for TLOAD without preceding TSTORE (reading uninitialized transient)
        if tload_count > 0 and tstore_count == 0:
            findings.append(Finding(
                title="TLOAD Without TSTORE",
                description=(
                    f"Contract uses TLOAD ({tload_count}x) but never TSTORE. "
                    f"Reading transient storage that was never written returns 0 — "
                    f"this may indicate a logic error or reliance on external TSTORE."
                ),
                severity=Severity.MEDIUM,
                offset=tload_offsets[0] if tload_offsets else 0,
                opcode="TLOAD",
                recommendation="Verify that transient storage is written before being read.",
            ))

        # Check for TSTORE without TLOAD (writing but never reading)
        if tstore_count > 0 and tload_count == 0:
            findings.append(Finding(
                title="TSTORE Without TLOAD",
                description=(
                    f"Contract uses TSTORE ({tstore_count}x) but never TLOAD. "
                    f"Writing transient storage without reading it is dead code "
                    f"or indicates the value is consumed by a sub-call."
                ),
                severity=Severity.LOW,
                offset=tstore_offsets[0] if tstore_offsets else 0,
                opcode="TSTORE",
                recommendation="Verify transient storage writes are intentional.",
            ))

        # Warn about single TSTORE (no cleanup)
        if tstore_count == 1 and tload_count >= 1:
            findings.append(Finding(
                title="Transient Storage Not Reset",
                description=(
                    f"Only 1 TSTORE detected with {tload_count} TLOAD(s). "
                    f"Reentrancy guards require TSTORE(1) before the call and "
                    f"TSTORE(0) after. A missing reset may leave the lock permanently "
                    f"engaged or fail to protect against reentrant calls."
                ),
                severity=Severity.HIGH,
                offset=tstore_offsets[0],
                opcode="TSTORE",
                recommendation="Ensure TSTORE resets to 0 after the protected call completes.",
            ))

        return TransientStorageAnalysis(
            has_tload=tload_count > 0,
            has_tstore=tstore_count > 0,
            tload_count=tload_count,
            tstore_count=tstore_count,
            is_reentrancy_guard=is_guard,
            findings=findings,
        )

    def _analyze_source(self) -> list[Finding]:
        """Scan Solidity source for transient storage patterns."""
        findings: list[Finding] = []
        if not self.source:
            return findings

        lines = self.source.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Detect assembly TSTORE/TLOAD usage
            if "tstore(" in stripped.lower() or "tload(" in stripped.lower():
                # Check if inside assembly block (expected)
                pass  # Valid usage

            # Detect Solidity 0.8.24+ transient keyword
            if "transient " in stripped and "=" in stripped:
                # Check for missing reset
                var_name = stripped.split("transient")[1].split("=")[0].strip().split()[-1]
                # Search rest of function for reset
                reset_found = False
                for j in range(i, min(i + 50, len(lines))):
                    if f"{var_name} = false" in lines[j] or f"{var_name} = 0" in lines[j]:
                        reset_found = True
                        break

                if not reset_found:
                    findings.append(Finding(
                        title=f"Transient Variable '{var_name}' May Not Reset",
                        description=(
                            f"Transient variable '{var_name}' at line {i} is set but "
                            f"no reset to default value found within 50 lines. "
                            f"Transient storage persists for the entire transaction — "
                            f"if not reset, subsequent internal calls may read stale state."
                        ),
                        severity=Severity.MEDIUM,
                        offset=i,
                        opcode="TSTORE",
                        recommendation=f"Reset '{var_name}' after the protected operation completes.",
                    ))

        return findings

    def analyze(self) -> TransientStorageAnalysis:
        """Run full transient storage analysis."""
        result = self._analyze_bytecode()
        source_findings = self._analyze_source()
        result.findings.extend(source_findings)
        return result
