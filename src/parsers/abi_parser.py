"""
ABI Parser — Extracts and analyzes function signatures from contract ABI.

Parses contract ABI to identify unprotected external functions,
state-mutating operations without access control, and dangerous
function patterns that may indicate vulnerabilities.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

import requests

from src.analyzers.bytecode import Severity, Finding


# Explorer API endpoints for fetching verified ABIs
EXPLORER_APIS: dict[str, str] = {
    "ethereum": "https://api.etherscan.io/api",
    "bsc": "https://api.bscscan.com/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "base": "https://api.basescan.org/api",
}

# Function signatures that should ALWAYS have access control
PRIVILEGED_SIGNATURES: set[str] = {
    "initialize",
    "init",
    "setUp",
    "upgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "setOwner",
    "transferOwnership",
    "renounceOwnership",
    "pause",
    "unpause",
    "setAdmin",
    "setImplementation",
    "mint",
    "burn",
    "withdraw",
    "withdrawAll",
    "emergencyWithdraw",
    "sweep",
    "execute",
    "delegateCall",
    "selfDestruct",
    "destroy",
    "kill",
    "setFee",
    "setOracle",
    "setPriceOracle",
    "setRewardRate",
    "addMinter",
    "removeMinter",
    "grantRole",
    "revokeRole",
}

# Known dangerous function selectors (4-byte)
DANGEROUS_SELECTORS: dict[str, str] = {
    "0x715018a6": "renounceOwnership()",
    "0x8da5cb5b": "owner()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0x8129fc1c": "initialize()",
}


@dataclass
class FunctionInfo:
    """Parsed information about a single ABI function."""

    name: str
    selector: str
    inputs: list[dict]
    outputs: list[dict]
    state_mutability: str
    is_payable: bool
    signature: str
    requires_access_control: bool = False


@dataclass
class ABIAnalysis:
    """Complete ABI analysis result."""

    contract_address: Optional[str] = None
    chain: str = "ethereum"
    total_functions: int = 0
    external_functions: list[FunctionInfo] = field(default_factory=list)
    payable_functions: list[FunctionInfo] = field(default_factory=list)
    unprotected_privileged: list[FunctionInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class ABIParser:
    """
    Parses smart contract ABI to identify security-relevant function patterns.

    Can load ABI from a JSON file, a raw JSON string, or fetch it from
    a block explorer API for verified contracts.

    Usage:
        # From address (fetches from explorer)
        parser = ABIParser.from_address("0x...", chain="ethereum", api_key="YOUR_KEY")
        analysis = parser.analyze()

        # From JSON file
        parser = ABIParser.from_file("./abi.json")
        analysis = parser.analyze()
    """

    def __init__(self, abi: list[dict], address: str | None = None, chain: str = "ethereum"):
        self.abi = abi
        self.address = address
        self.chain = chain
        self._functions: list[FunctionInfo] = []

    @classmethod
    def from_file(cls, path: str, address: str | None = None) -> "ABIParser":
        """Load ABI from a JSON file."""
        with open(path, "r") as f:
            abi = json.load(f)
        if isinstance(abi, dict) and "abi" in abi:
            abi = abi["abi"]
        return cls(abi=abi, address=address)

    @classmethod
    def from_json(cls, abi_json: str, address: str | None = None) -> "ABIParser":
        """Load ABI from a JSON string."""
        abi = json.loads(abi_json)
        if isinstance(abi, dict) and "abi" in abi:
            abi = abi["abi"]
        return cls(abi=abi, address=address)

    @classmethod
    def from_address(
        cls, address: str, chain: str = "ethereum", api_key: str = ""
    ) -> "ABIParser":
        """Fetch verified ABI from block explorer API."""
        base_url = EXPLORER_APIS.get(chain)
        if not base_url:
            raise ValueError(f"Unsupported chain: {chain}. Supported: {list(EXPLORER_APIS.keys())}")

        params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
            "apikey": api_key,
        }

        resp = requests.get(base_url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "1":
            raise ValueError(f"Failed to fetch ABI: {data.get('message', 'Unknown error')}")

        abi = json.loads(data["result"])
        return cls(abi=abi, address=address, chain=chain)

    @staticmethod
    def compute_selector(name: str, inputs: list[dict]) -> str:
        """Compute the 4-byte function selector from name and input types."""
        input_types = ",".join(inp.get("type", "") for inp in inputs)
        signature = f"{name}({input_types})"
        selector = hashlib.sha3_256(signature.encode()).hexdigest()[:8]
        # Use keccak256 via web3 if available, fallback to approximation
        try:
            from web3 import Web3

            selector = Web3.keccak(text=signature).hex()[2:10]
        except ImportError:
            pass
        return "0x" + selector

    def _parse_functions(self) -> list[FunctionInfo]:
        """Extract all function entries from the ABI."""
        functions: list[FunctionInfo] = []

        for entry in self.abi:
            if entry.get("type") != "function":
                continue

            name = entry.get("name", "")
            inputs = entry.get("inputs", [])
            outputs = entry.get("outputs", [])
            mutability = entry.get("stateMutability", "nonpayable")

            input_types = ", ".join(
                f"{inp.get('type', '?')} {inp.get('name', '')}" for inp in inputs
            )
            signature = f"{name}({input_types})"

            selector = self.compute_selector(name, inputs)

            requires_acl = name.lower() in {s.lower() for s in PRIVILEGED_SIGNATURES}

            functions.append(
                FunctionInfo(
                    name=name,
                    selector=selector,
                    inputs=inputs,
                    outputs=outputs,
                    state_mutability=mutability,
                    is_payable=mutability == "payable",
                    signature=signature,
                    requires_access_control=requires_acl,
                )
            )

        self._functions = functions
        return functions

    def detect_unprotected_externals(self) -> list[FunctionInfo]:
        """
        Identify external functions that should have access control but don't
        appear to (based on naming heuristics).

        Note: This is a static analysis heuristic. Runtime verification
        (checking for modifiers in source code) provides higher accuracy.
        """
        if not self._functions:
            self._parse_functions()

        return [f for f in self._functions if f.requires_access_control]

    def analyze(self) -> ABIAnalysis:
        """
        Run full ABI analysis pipeline.

        Returns:
            ABIAnalysis with function categorization and findings.
        """
        if not self._functions:
            self._parse_functions()

        findings: list[Finding] = []
        payable_fns = [f for f in self._functions if f.is_payable]
        unprotected = self.detect_unprotected_externals()

        # Flag privileged functions that lack obvious access control
        for fn in unprotected:
            if fn.state_mutability in ("nonpayable", "payable"):
                findings.append(
                    Finding(
                        title=f"Privileged Function: {fn.name}",
                        description=(
                            f"Function '{fn.signature}' (selector: {fn.selector}) "
                            f"is a privileged operation that typically requires access control. "
                            f"Verify that appropriate modifiers (onlyOwner, onlyRole, etc.) "
                            f"are applied in the source code."
                        ),
                        severity=Severity.HIGH,
                        offset=0,
                        opcode="ABI",
                        recommendation=(
                            f"Review the source code for '{fn.name}' and confirm access control "
                            f"is properly implemented. Check for onlyOwner, onlyRole, or similar modifiers."
                        ),
                    )
                )

        # Flag payable functions
        for fn in payable_fns:
            findings.append(
                Finding(
                    title=f"Payable Function: {fn.name}",
                    description=(
                        f"Function '{fn.signature}' accepts ETH. "
                        f"Verify that received funds are properly accounted for "
                        f"and that the function cannot be used to lock ETH permanently."
                    ),
                    severity=Severity.INFO,
                    offset=0,
                    opcode="ABI",
                    recommendation="Ensure ETH handling logic is correct and funds can be recovered.",
                )
            )

        return ABIAnalysis(
            contract_address=self.address,
            chain=self.chain,
            total_functions=len(self._functions),
            external_functions=self._functions,
            payable_functions=payable_fns,
            unprotected_privileged=unprotected,
            findings=findings,
        )
