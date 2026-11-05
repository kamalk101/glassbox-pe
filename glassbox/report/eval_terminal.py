"""Terminal rendering for corpus evaluation results."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..evaluation import ACTUAL_LABELS


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_evaluation(result: dict) -> None:
    console = Console()
    metrics = result["metrics"]
    binary = metrics["binary"]
    techniques = metrics["techniques"]

    console.print()
    console.rule("[bold cyan]GlassBox PE · evaluation[/bold cyan]")
    console.print(f"[dim]corpus[/dim] {escape(result['corpus'])}")
    console.print(f"[dim]manifest[/dim] {escape(result['manifest'])}")
    console.print()

    summary = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    summary.add_column("metric", style="dim", width=22)
    summary.add_column("value")
    summary.add_row("samples evaluated", str(metrics["samples"]))
    summary.add_row("3-class accuracy", _percent(metrics["accuracy"]))
    summary.add_row("macro F1", f"{metrics['macro_f1']:.3f}")
    summary.add_row("binary precision", _percent(binary["precision"]))
    summary.add_row("binary recall", _percent(binary["recall"]))
    summary.add_row("binary F1", _percent(binary["f1"]))
    summary.add_row("PR-AUC", "n/a" if binary.get("pr_auc") is None else f"{binary['pr_auc']:.3f}")
    summary.add_row(
        "binary confusion",
        f"TP {binary['tp']} · FP {binary['fp']} · TN {binary['tn']} · FN {binary['fn']}",
    )
    summary.add_row("technique recall", f"{_percent(techniques['recall'])} ({techniques['matched']}/{techniques['expected']})")
    console.print(Panel(summary, title="metrics", border_style="cyan"))

    per_class = Table(title="per-class", box=box.SIMPLE_HEAD)
    per_class.add_column("class")
    per_class.add_column("support", justify="right")
    per_class.add_column("precision", justify="right")
    per_class.add_column("recall", justify="right")
    per_class.add_column("f1", justify="right")
    for label in ACTUAL_LABELS:
        row = metrics["per_class"][label]
        per_class.add_row(
            label,
            str(row["support"]),
            _percent(row["precision"]),
            _percent(row["recall"]),
            f"{row['f1']:.3f}",
        )
    console.print(per_class)

    predicted_labels = ("clean", "suspicious", "malicious", "inconclusive")
    confusion = Table(title="confusion matrix (rows: actual, columns: predicted)", box=box.SIMPLE_HEAD)
    confusion.add_column("actual")
    for predicted in predicted_labels:
        confusion.add_column(predicted, justify="right")
    for actual in ACTUAL_LABELS:
        row = metrics["confusion"][actual]
        values = []
        for predicted in predicted_labels:
            count = row.get(predicted, 0)
            values.append(f"[green]{count}[/green]" if actual == predicted and count else str(count))
        confusion.add_row(actual, *values)
    console.print(confusion)

    if techniques["per_technique"]:
        technique_table = Table(title="technique recall", box=box.SIMPLE_HEAD)
        technique_table.add_column("technique", style="dim")
        technique_table.add_column("expected", justify="right")
        technique_table.add_column("detected", justify="right")
        technique_table.add_column("recall", justify="right")
        for technique, row in techniques["per_technique"].items():
            technique_table.add_row(
                escape(technique),
                str(row["expected"]),
                str(row["detected"]),
                _percent(row["recall"]),
            )
        console.print(technique_table)

    samples = Table(title="samples", box=box.SIMPLE_HEAD)
    samples.add_column("file")
    samples.add_column("actual")
    samples.add_column("predicted")
    samples.add_column("score", justify="right")
    samples.add_column("ok", justify="center")
    samples.add_column("missing techniques")
    for sample in result["samples"]:
        ok = "[green]yes[/green]" if sample["correct"] else "[red]no[/red]"
        samples.add_row(
            escape(sample["path"]),
            sample["actual"],
            sample["predicted"],
            str(sample["score"]),
            ok,
            escape(", ".join(sample["missing_techniques"]) or "-"),
        )
    console.print(samples)

    if result["errors"] or metrics["samples"] == 0:
        console.print("[yellow]errors[/yellow]")
        for error in result["errors"]:
            console.print(f"  - {escape(error['path'])}: {escape(error['error'])}")
        if metrics["samples"] == 0:
            console.print("  - no samples were evaluated")
    console.print()
