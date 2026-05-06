"""
Access Control Detector — Identifies missing access control in smart contracts.
"""

import re
from dataclasses import dataclass, field
from src.analyzers.bytecode import Severity, Finding

PRIVILEGED_OPS = [
    (re.compile(r"selfdestruct\(", re.I), "SELFDESTRUCT", Severity.CRITICAL),
    (re.compile(r"delegatecall\(", re.I), "DELEGATECALL", Severity.CRITICAL),
    (re.compile(r"\.upgradeTo\(", re.I), "PROXY_UPGRADE", Severity.CRITICAL),
    (re.compile(r"_transferOwnership\(", re.I), "OWNERSHIP_TRANSFER", Severity.HIGH),
    (re.compile(r"_mint\(", re.I), "MINT", Severity.HIGH),
    (re.compile(r"_burn\(", re.I), "BURN", Severity.HIGH),
    (re.compile(r"_pause\(\)", re.I), "PAUSE", Severity.MEDIUM),
]

ACCESS_CONTROL_PATTERNS = [
    re.compile(r"onlyOwner", re.I),
    re.compile(r"onlyRole", re.I),
    re.compile(r"onlyAdmin", re.I),
    re.compile(r"require\(msg\.sender\s*==\s*owner", re.I),
    re.compile(r"require\(\s*hasRole\(", re.I),
    re.compile(r"_checkOwner\(\)", re.I),
    re.compile(r"_checkRole\(", re.I),
]


@dataclass
class AccessControlAnalysis:
    functions_analyzed: int = 0
    unprotected_functions: int = 0
    findings: list[Finding] = field(default_factory=list)


class AccessControlDetector:
    """Detects missing access control on privileged functions."""

    def __init__(self, source_code: str):
        self.source = source_code

    def _extract_functions(self) -> list[tuple[str, str, int]]:
        functions = []
        pattern = re.compile(r"function\s+(\w+)\s*\([^)]*\)([^{]*)\{", re.MULTILINE | re.DOTALL)
        for match in pattern.finditer(self.source):
            name = match.group(1)
            start_line = self.source[: match.start()].count("\n") + 1
            brace_count, pos = 0, match.end() - 1
            while pos < len(self.source):
                if self.source[pos] == "{":
                    brace_count += 1
                elif self.source[pos] == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        break
                pos += 1
            functions.append((name, self.source[match.start() : pos + 1], start_line))
        return functions

    def _has_access_control(self, text: str) -> bool:
        return any(p.search(text) for p in ACCESS_CONTROL_PATTERNS)

    def analyze(self) -> AccessControlAnalysis:
        findings, functions, unprotected = [], self._extract_functions(), 0
        for func_name, func_text, start_line in functions:
            if self._has_access_control(func_text):
                continue
            for pattern, op_type, severity in PRIVILEGED_OPS:
                if pattern.search(func_text):
                    unprotected += 1
                    findings.append(Finding(
                        title=f"Unprotected {op_type} in {func_name}()",
                        description=f"'{func_name}' at L{start_line} performs {op_type} without access control.",
                        severity=severity, offset=start_line, opcode=op_type,
                        recommendation=f"Add onlyOwner or AccessControl to '{func_name}'.",
                    ))
                    break
        return AccessControlAnalysis(len(functions), unprotected, findings)
