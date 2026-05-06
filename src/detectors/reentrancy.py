"""
Reentrancy Detector — Identifies reentrancy vulnerability patterns.

Detects cross-function and cross-contract reentrancy vectors by analyzing
the order of external calls relative to state changes (CEI pattern violations).
"""

from dataclasses import dataclass, field
import re
from typing import Optional

from src.analyzers.bytecode import Severity, Finding


@dataclass
class StateChange:
    """A state-changing operation in the source code."""

    line: int
    code: str
    variable: str


@dataclass
class ExternalCall:
    """An external call in the source code."""

    line: int
    code: str
    target: str
    call_type: str  # call, transfer, send, delegatecall


@dataclass
class ReentrancyVector:
    """A potential reentrancy attack vector."""

    function_name: str
    external_call: ExternalCall
    state_change_after: StateChange
    severity: Severity
    description: str


@dataclass
class ReentrancyAnalysis:
    """Complete reentrancy analysis result."""

    vectors: list[ReentrancyVector] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    functions_analyzed: int = 0
    cei_violations: int = 0


class ReentrancyDetector:
    """
    Detects reentrancy vulnerabilities in Solidity source code.

    Analyzes the ordering of external calls and state changes within
    functions to identify violations of the Checks-Effects-Interactions
    (CEI) pattern.

    Usage:
        detector = ReentrancyDetector(source_code=solidity_source)
        result = detector.analyze()
        for vector in result.vectors:
            print(f"[{vector.severity}] {vector.function_name}: {vector.description}")
    """

    # Patterns that indicate external calls
    EXTERNAL_CALL_PATTERNS = [
        # .call{value: ...}(...)
        re.compile(r"\.call\{?\s*value\s*:", re.MULTILINE),
        # .call(...)
        re.compile(r"\.call\(", re.MULTILINE),
        # .transfer(...)
        re.compile(r"\.transfer\(", re.MULTILINE),
        # .send(...)
        re.compile(r"\.send\(", re.MULTILINE),
        # .delegatecall(...)
        re.compile(r"\.delegatecall\(", re.MULTILINE),
        # Interface calls: ISomeContract(addr).someFunc(...)
        re.compile(r"I\w+\([^)]+\)\.\w+\(", re.MULTILINE),
        # IERC20 token transfers
        re.compile(r"\.safeTransfer\(", re.MULTILINE),
        re.compile(r"\.safeTransferFrom\(", re.MULTILINE),
    ]

    # Patterns that indicate state changes
    STATE_CHANGE_PATTERNS = [
        # Direct storage writes: variable = value
        re.compile(r"^\s+(\w+(?:\[\w+\])?(?:\.\w+)*)\s*=\s*[^=]", re.MULTILINE),
        # Mapping writes: mapping[key] = value
        re.compile(r"(\w+\[.*?\])\s*=\s*[^=]", re.MULTILINE),
        # += -= *= /=
        re.compile(r"(\w+(?:\[\w+\])?)\s*[+\-*/]?=\s*", re.MULTILINE),
        # delete
        re.compile(r"delete\s+(\w+)", re.MULTILINE),
    ]

    # Known reentrancy guard patterns
    GUARD_PATTERNS = [
        re.compile(r"nonReentrant", re.MULTILINE),
        re.compile(r"ReentrancyGuard", re.MULTILINE),
        re.compile(r"_locked\s*=\s*true", re.MULTILINE),
        re.compile(r"require\(!_locked", re.MULTILINE),
        re.compile(r"_status\s*==\s*_NOT_ENTERED", re.MULTILINE),
    ]

    def __init__(self, source_code: str):
        self.source = source_code
        self.lines = source_code.split("\n")

    def _extract_functions(self) -> list[tuple[str, int, int, str]]:
        """
        Extract function boundaries from source code.

        Returns list of (function_name, start_line, end_line, body).
        """
        functions: list[tuple[str, int, int, str]] = []
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\([^)]*\)[^{]*\{", re.MULTILINE
        )

        for match in func_pattern.finditer(self.source):
            name = match.group(1)
            start_pos = match.start()
            start_line = self.source[:start_pos].count("\n") + 1

            # Find matching closing brace
            brace_count = 0
            pos = match.end() - 1  # Start at opening brace
            while pos < len(self.source):
                if self.source[pos] == "{":
                    brace_count += 1
                elif self.source[pos] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        break
                pos += 1

            end_line = self.source[:pos].count("\n") + 1
            body = self.source[match.end() : pos]

            functions.append((name, start_line, end_line, body))

        return functions

    def _find_external_calls(self, body: str, base_line: int) -> list[ExternalCall]:
        """Find all external calls within a function body."""
        calls: list[ExternalCall] = []

        for line_idx, line in enumerate(body.split("\n")):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern in self.EXTERNAL_CALL_PATTERNS:
                if pattern.search(line):
                    call_type = "call"
                    if ".transfer(" in line:
                        call_type = "transfer"
                    elif ".send(" in line:
                        call_type = "send"
                    elif ".delegatecall(" in line:
                        call_type = "delegatecall"
                    elif ".safeTransfer" in line:
                        call_type = "safeTransfer"

                    calls.append(
                        ExternalCall(
                            line=base_line + line_idx,
                            code=stripped,
                            target=stripped.split(".")[0].strip() if "." in stripped else "unknown",
                            call_type=call_type,
                        )
                    )
                    break  # One match per line is enough

        return calls

    def _find_state_changes(self, body: str, base_line: int) -> list[StateChange]:
        """Find all state-changing operations within a function body."""
        changes: list[StateChange] = []
        local_vars: set[str] = set()

        # First pass: identify local variable declarations
        for line in body.split("\n"):
            stripped = line.strip()
            # Match: uint256 localVar = ...
            local_match = re.match(
                r"(uint\d*|int\d*|address|bool|bytes\d*|string)\s+(\w+)", stripped
            )
            if local_match:
                local_vars.add(local_match.group(2))

        # Second pass: find state changes (exclude local vars)
        for line_idx, line in enumerate(body.split("\n")):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue

            # Skip local variable declarations
            if re.match(r"(uint\d*|int\d*|address|bool|bytes\d*|string|memory|storage)\s+", stripped):
                continue

            # Check for state-modifying assignments
            assign_match = re.match(r"(\w+(?:\[.*?\])?(?:\.\w+)*)\s*[+\-*/]?=\s*[^=]", stripped)
            if assign_match:
                var_name = assign_match.group(1).split("[")[0].split(".")[0]
                if var_name not in local_vars and var_name not in ("memory", "storage", "calldata"):
                    changes.append(
                        StateChange(
                            line=base_line + line_idx,
                            code=stripped,
                            variable=var_name,
                        )
                    )

        return changes

    def _has_reentrancy_guard(self, body: str) -> bool:
        """Check if the function has a reentrancy guard."""
        for pattern in self.GUARD_PATTERNS:
            if pattern.search(body):
                return True
        return False

    def analyze(self) -> ReentrancyAnalysis:
        """
        Run full reentrancy analysis.

        Identifies CEI pattern violations where state changes occur
        after external calls without reentrancy guards.

        Returns:
            ReentrancyAnalysis with vectors, findings, and statistics.
        """
        vectors: list[ReentrancyVector] = []
        findings: list[Finding] = []
        functions = self._extract_functions()
        cei_violations = 0

        for func_name, start_line, end_line, body in functions:
            # Skip if has reentrancy guard
            if self._has_reentrancy_guard(body):
                continue

            external_calls = self._find_external_calls(body, start_line)
            state_changes = self._find_state_changes(body, start_line)

            if not external_calls or not state_changes:
                continue

            # Check for state changes AFTER external calls (CEI violation)
            for call in external_calls:
                for change in state_changes:
                    if change.line > call.line:
                        cei_violations += 1
                        severity = Severity.CRITICAL if call.call_type in ("call", "delegatecall") else Severity.HIGH

                        vector = ReentrancyVector(
                            function_name=func_name,
                            external_call=call,
                            state_change_after=change,
                            severity=severity,
                            description=(
                                f"State variable '{change.variable}' is modified at line {change.line} "
                                f"AFTER external {call.call_type} at line {call.line}. "
                                f"This violates the Checks-Effects-Interactions pattern."
                            ),
                        )
                        vectors.append(vector)

                        findings.append(
                            Finding(
                                title=f"Reentrancy in {func_name}()",
                                description=(
                                    f"CEI violation: '{change.variable}' modified at L{change.line} "
                                    f"after {call.call_type} at L{call.line}.\n"
                                    f"  Call:   {call.code}\n"
                                    f"  State:  {change.code}\n"
                                    f"An attacker can re-enter {func_name}() before the state "
                                    f"update completes, potentially draining funds."
                                ),
                                severity=severity,
                                offset=call.line,
                                opcode=call.call_type.upper(),
                                recommendation=(
                                    f"Move state changes before external calls (CEI pattern), "
                                    f"or add a reentrancy guard (nonReentrant modifier)."
                                ),
                            )
                        )

        return ReentrancyAnalysis(
            vectors=vectors,
            findings=findings,
            functions_analyzed=len(functions),
            cei_violations=cei_violations,
        )
