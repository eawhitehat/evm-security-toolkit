"""
Reporter — Generates formatted security findings reports.
"""

import json
from datetime import datetime, timezone
from src.analyzers.bytecode import BytecodeAnalysis, Finding, Severity


SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def to_markdown(findings: list[Finding], title: str = "Security Report") -> str:
    """Generate a markdown report from findings."""
    lines = [
        f"# {title}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {len(findings)}",
        "",
    ]

    # Summary table
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if sev in counts:
            lines.append(f"| {SEVERITY_ICONS[sev]} {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    # Individual findings
    for i, f in enumerate(findings, 1):
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        lines.append(f"## {icon} [{f.severity.value.upper()}] Finding #{i}: {f.title}")
        lines.append(f"**Offset:** `0x{f.offset:04x}` | **Opcode:** `{f.opcode}`")
        lines.append("")
        lines.append(f.description)
        if f.recommendation:
            lines.append("")
            lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    """Generate a JSON report from findings."""
    data = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "offset": f.offset,
                "opcode": f.opcode,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2)
