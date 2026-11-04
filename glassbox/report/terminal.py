"""Terminal rendering with Rich."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..schema import Case, Severity, VerdictLabel
from ..utils import human_size

LABEL_STYLE = {
    VerdictLabel.CLEAN: ("green", "CLEAN"),
    VerdictLabel.SUSPICIOUS: ("yellow", "SUSPICIOUS"),
    VerdictLabel.MALICIOUS: ("red", "LIKELY MALICIOUS"),
    VerdictLabel.INCONCLUSIVE: ("magenta", "INCONCLUSIVE"),
}

SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def _cell(value: str) -> str:
    return escape(str(value))


def render_case(case: Case, console: Console | None = None, case_path: str | None = None) -> None:
    console = console or Console()

    console.print()
    console.rule("[bold cyan]GlassBox PE[/bold cyan]")
    console.print(f"[dim]case[/dim] {case.case_id}")
    console.print()

    file_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    file_table.add_column("field", style="dim", width=12)
    file_table.add_column("value")
    file_table.add_row("file", _cell(case.file_name))
    file_table.add_row("size", human_size(case.size))
    file_table.add_row("type", case.file_type)
    file_table.add_row("sha256", case.hashes.get("sha256", ""))
    file_table.add_row("created", case.created_at)
    console.print(file_table)

    verdict = case.verdict
    if verdict:
        color, label = LABEL_STYLE.get(verdict.label, ("white", verdict.label.value.upper()))
        body = Text()
        body.append(f"{label}\n", style=f"bold {color}")
        body.append(f"score {verdict.score}/100   confidence {verdict.confidence:.2f}   ")
        body.append(f"sneakiness {verdict.sneakiness}/100\n")
        if verdict.sneakiness_reasons:
            body.append("  " + ", ".join(verdict.sneakiness_reasons) + "\n")
        body.append("\n")
        body.append(verdict.summary)
        console.print(Panel(body, title="verdict", border_style=color))
    else:
        console.print(Panel("no verdict available", border_style="yellow"))

    unpack = case.artifacts.get("unpack")
    if isinstance(unpack, dict):
        table = Table(title="unpack", box=box.SIMPLE, show_header=False, pad_edge=False)
        table.add_column("field", style="dim", width=14)
        table.add_column("value")
        packer = unpack.get("packer") or {}
        table.add_row("status", _cell(unpack.get("status", "?")))
        table.add_row(
            "packer",
            _cell(f"{packer.get('name') or 'unknown'} ({packer.get('confidence', 'none')})"),
        )
        table.add_row("method", _cell(unpack.get("method") or "-"))
        table.add_row("output", _cell(unpack.get("output_path") or "-"))
        diff = unpack.get("diff") or {}
        if diff:
            table.add_row("child case", _cell(diff.get("child_case_id") or "-"))
            table.add_row("verdict", _cell(f"{diff.get('parent_verdict')} -> {diff.get('child_verdict')}"))
            table.add_row("new imports", str(len(diff.get("new_imports") or [])))
            table.add_row("new findings", _cell(", ".join(diff.get("new_findings") or []) or "-"))
        console.print(table)

    if case.findings:
        findings = Table(title="findings", box=box.SIMPLE_HEAD, show_lines=False)
        findings.add_column("id", style="dim", no_wrap=True)
        findings.add_column("sev", no_wrap=True)
        findings.add_column("title")
        findings.add_column("evidence", justify="right", no_wrap=True)
        findings.add_column("techniques", no_wrap=True)
        for finding in case.findings:
            findings.add_row(
                finding.id,
                Text(finding.severity.value, style=SEVERITY_STYLE.get(finding.severity, "")),
                _cell(finding.title),
                str(len(finding.evidence)),
                ", ".join(finding.techniques) or "-",
            )
        console.print(findings)
    else:
        console.print("[dim]no findings[/dim]")

    if case.events:
        evidence = Table(title="evidence", box=box.SIMPLE_HEAD)
        evidence.add_column("id", style="dim", no_wrap=True)
        evidence.add_column("strength", no_wrap=True)
        evidence.add_column("category", no_wrap=True)
        evidence.add_column("action", no_wrap=True)
        evidence.add_column("target")
        for event in case.events[:14]:
            evidence.add_row(
                event.id,
                event.strength.value,
                event.category.value,
                _cell(event.action),
                _cell(event.target[:90]),
            )
        if len(case.events) > 14:
            evidence.add_row("...", "", "", "", f"{len(case.events) - 14} more")
        console.print(evidence)

    if verdict and verdict.counterfactuals:
        cf = Table(title="counterfactuals (what if?)", box=box.SIMPLE_HEAD)
        cf.add_column("finding", style="dim", no_wrap=True)
        cf.add_column("remove", no_wrap=True)
        cf.add_column("risk without", justify="right", no_wrap=True)
        cf.add_column("drop", justify="right", no_wrap=True)
        for item in verdict.counterfactuals:
            cf.add_row(
                item.get("finding_id", ""),
                _cell(item.get("title", "")),
                str(item.get("risk_without", item.get("score_without", ""))),
                f"-{item.get('delta', '')}",
            )
        console.print(cf)

    if verdict and verdict.techniques:
        console.print("[bold]techniques[/bold] " + ", ".join(verdict.techniques))

    if verdict and verdict.next_steps:
        console.print("[bold]next steps[/bold]")
        for step in verdict.next_steps:
            console.print(f"  - {_cell(step)}")

    if case.errors:
        console.print("[yellow]errors[/yellow]")
        for error in case.errors:
            console.print(f"  - {_cell(error)}")

    console.print()
    console.print(f"[dim]case file[/dim] {_cell(case_path or f'cases/{case.case_id}/case.json')}")
    console.print()


def render_quiet(case: Case) -> None:
    verdict = case.verdict
    if not verdict:
        print(f"{case.file_name}: inconclusive")
        return
    print(
        f"{case.file_name}: {verdict.label.value} "
        f"(score {verdict.score}, confidence {verdict.confidence:.2f})"
    )
