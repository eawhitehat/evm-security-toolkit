#!/usr/bin/env python3
"""
EVM Security Toolkit — CLI Scanner

Usage:
    python scanner.py --address 0x... --chain ethereum
    python scanner.py --bytecode 0x6080604052...
    python scanner.py --file ./contracts/Vault.sol
"""

import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from src.analyzers.bytecode import BytecodeAnalyzer, Severity
from src.utils.config import Config
from src.utils.reporter import to_markdown, to_json

console = Console()

BANNER = """
╔═══════════════════════════════════════════════╗
║       🔍 EVM Security Toolkit v0.1.0          ║
║       Smart Contract Vulnerability Scanner     ║
║       github.com/eawhitehat                    ║
╚═══════════════════════════════════════════════╝
"""

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "white",
}


def fetch_bytecode(address: str, chain: str, config: Config) -> str:
    """Fetch contract bytecode from RPC."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(config.get_rpc(chain)))
    code = w3.eth.get_code(Web3.to_checksum_address(address))
    return "0x" + code.hex()


def scan_bytecode(bytecode: str, address: str | None = None) -> None:
    """Run bytecode analysis and display results."""
    analyzer = BytecodeAnalyzer(bytecode=bytecode, address=address)
    result = analyzer.scan()

    # Summary panel
    summary = Table(show_header=False, box=None)
    summary.add_row("Contract", address or "N/A")
    summary.add_row("Bytecode Size", f"{result.bytecode_length} bytes")
    summary.add_row("Total Opcodes", str(result.opcode_count))
    summary.add_row("External Calls", str(result.external_call_count))
    summary.add_row("Has DELEGATECALL", "⚠️  YES" if result.has_delegatecall else "✅ NO")
    summary.add_row("Has SELFDESTRUCT", "⚠️  YES" if result.has_selfdestruct else "✅ NO")
    summary.add_row("Has CREATE2", "ℹ️  YES" if result.has_create2 else "NO")
    summary.add_row("Risk Score", f"{'🔴' if result.risk_score > 20 else '🟡' if result.risk_score > 5 else '🟢'} {result.risk_score}")
    console.print(Panel(summary, title="📊 Contract Summary", border_style="cyan"))

    if not result.findings:
        console.print("\n[green]✅ No vulnerabilities detected in bytecode analysis.[/green]")
        return

    # Findings table
    table = Table(title="🔍 Vulnerability Findings", show_lines=True)
    table.add_column("#", style="bold", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=30)
    table.add_column("Offset", width=10)
    table.add_column("Description", width=60)

    for i, finding in enumerate(result.findings, 1):
        color = SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            str(i),
            Text(finding.severity.value.upper(), style=f"bold {color}"),
            finding.title,
            f"0x{finding.offset:04x}",
            finding.description[:120] + "..." if len(finding.description) > 120 else finding.description,
        )

    console.print(table)
    console.print(f"\n[bold]Total: {len(result.findings)} findings "
                  f"({result.critical_count} Critical, {result.high_count} High)[/bold]")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="EVM Security Toolkit — Smart Contract Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--address", "-a", help="Contract address to scan")
    parser.add_argument("--chain", "-c", default="ethereum",
                       choices=["ethereum", "bsc", "polygon", "arbitrum", "base"])
    parser.add_argument("--bytecode", "-b", help="Raw bytecode hex string")
    parser.add_argument("--file", "-f", help="Solidity source file to analyze")
    parser.add_argument("--output", "-o", help="Output file path (supports .md and .json)")
    parser.add_argument("--format", default="table", choices=["table", "markdown", "json"])

    args = parser.parse_args()
    console.print(BANNER, style="bold cyan")

    if not any([args.address, args.bytecode, args.file]):
        parser.print_help()
        sys.exit(1)

    config = Config()

    if args.address:
        console.print(f"[cyan]Fetching bytecode for {args.address} on {args.chain}...[/cyan]")
        bytecode = fetch_bytecode(args.address, args.chain, config)
        if bytecode == "0x" or len(bytecode) <= 2:
            console.print("[red]❌ No bytecode found. Is this an EOA?[/red]")
            sys.exit(1)
        result = scan_bytecode(bytecode, args.address)

    elif args.bytecode:
        result = scan_bytecode(args.bytecode)

    elif args.file:
        console.print(f"[cyan]Analyzing source file: {args.file}[/cyan]")
        with open(args.file, "r") as f:
            source = f.read()

        from src.detectors.reentrancy import ReentrancyDetector
        from src.detectors.access import AccessControlDetector

        reentrancy = ReentrancyDetector(source).analyze()
        access = AccessControlDetector(source).analyze()

        all_findings = reentrancy.findings + access.findings
        if all_findings:
            for f in all_findings:
                color = SEVERITY_COLORS.get(f.severity, "white")
                console.print(f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title}")
                console.print(f"    {f.description}")
                console.print()
        else:
            console.print("[green]✅ No issues detected in source analysis.[/green]")

    # Output to file
    if args.output and result:
        all_findings = result.findings if hasattr(result, "findings") else []
        if args.output.endswith(".json"):
            content = to_json(all_findings)
        else:
            content = to_markdown(all_findings)
        with open(args.output, "w") as f:
            f.write(content)
        console.print(f"\n[green]📄 Report saved to {args.output}[/green]")


if __name__ == "__main__":
    main()
