"""GlassBox PE command line interface."""

from __future__ import annotations

from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

from .analyzer import analyze_static
from .cases import CaseStore
from .config import resolve_cases_dir
from .ingest import ingest
from .report import render_case, render_json, render_quiet
from .schema import TOOL_VERSION, Case, VerdictLabel
from .static.rules import RULE_CATALOG
from .utils import human_size

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=TOOL_VERSION, prog_name="glassbox")
def cli() -> None:
    """GlassBox PE — offline, evidence-first triage for Windows executables."""


def _exit_code(case: Case) -> int:
    if not case.verdict:
        return 3
    return {
        VerdictLabel.CLEAN: 0,
        VerdictLabel.SUSPICIOUS: 1,
        VerdictLabel.MALICIOUS: 2,
        VerdictLabel.INCONCLUSIVE: 3,
    }[case.verdict.label]


def _scan(path: Path, cases_dir: str | None, force: bool) -> tuple[Case, bool, CaseStore]:
    intake = ingest(path)
    store = CaseStore(resolve_cases_dir(cases_dir))
    if store.exists(intake.case_id) and not force:
        return store.load(intake.case_id), True, store
    case = analyze_static(intake)
    store.save(case)
    return case, False, store


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cases-dir", default=None, help="Where to store cases (default: ./cases).")
@click.option("--json", "as_json", is_flag=True, help="Print the full case as JSON.")
@click.option("--quiet", is_flag=True, help="Print only the verdict line.")
@click.option("--force", is_flag=True, help="Re-analyze even if a cached case exists.")
@click.pass_context
def scan(ctx: click.Context, path: Path, cases_dir: str | None, as_json: bool, quiet: bool, force: bool) -> None:
    """Statically analyze one Windows executable."""
    try:
        case, cached, store = _scan(path, cases_dir, force)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)

    if as_json:
        click.echo(render_json(case))
    elif quiet:
        render_quiet(case)
    else:
        if cached:
            click.echo(f"cached case {case.case_id} (use --force to re-analyze)", err=True)
        render_case(case, case_path=str(store.case_path(case.case_id)))
    ctx.exit(_exit_code(case))


@cli.group()
def cases() -> None:
    """Inspect stored cases."""


@cases.command("list")
@click.option("--cases-dir", default=None)
def list_cases(cases_dir: str | None) -> None:
    """List stored cases."""
    rows = CaseStore(resolve_cases_dir(cases_dir)).list()
    console = Console()
    if not rows:
        console.print("[dim]no cases yet. run: glassbox scan <file.exe>[/dim]")
        return
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("case", style="dim", no_wrap=True)
    table.add_column("file")
    table.add_column("size", justify="right", no_wrap=True)
    table.add_column("verdict", no_wrap=True)
    table.add_column("score", justify="right", no_wrap=True)
    table.add_column("created", no_wrap=True)
    for row in rows:
        color = {"clean": "green", "suspicious": "yellow", "malicious": "red"}.get(row["label"], "magenta")
        table.add_row(
            row["case_id"][:12],
            row["file_name"],
            human_size(row["size"]),
            f"[{color}]{row['label']}[/{color}]",
            str(row["score"]),
            row["created_at"][:19],
        )
    console.print(table)


def _resolve_case(store: CaseStore, case_id: str) -> Case:
    if store.exists(case_id):
        return store.load(case_id)
    matches = [row["case_id"] for row in store.list() if row["case_id"].startswith(case_id)]
    if len(matches) == 1:
        return store.load(matches[0])
    if not matches:
        raise FileNotFoundError(f"case not found: {case_id}")
    raise ValueError(f"ambiguous case prefix {case_id}: {len(matches)} matches")


@cases.command("show")
@click.argument("case_id")
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def show_case(ctx: click.Context, case_id: str, cases_dir: str | None, as_json: bool) -> None:
    """Show one stored case (full id or unique prefix)."""
    store = CaseStore(resolve_cases_dir(cases_dir))
    try:
        case = _resolve_case(store, case_id)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))


@cases.command("delete")
@click.argument("case_id")
@click.option("--cases-dir", default=None)
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_context
def delete_case(ctx: click.Context, case_id: str, cases_dir: str | None, yes: bool) -> None:
    """Delete a stored case."""
    store = CaseStore(resolve_cases_dir(cases_dir))
    try:
        case = _resolve_case(store, case_id)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if not yes:
        click.confirm(f"Delete case {case.case_id} ({case.file_name})?", abort=True)
    store.delete(case.case_id)
    click.echo(f"deleted {case.case_id}")


@cli.command()
@click.argument("case_id")
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--html", is_flag=True)
@click.pass_context
def report(ctx: click.Context, case_id: str, cases_dir: str | None, as_json: bool, html: bool) -> None:
    """Re-emit a stored report."""
    store = CaseStore(resolve_cases_dir(cases_dir))
    try:
        case = _resolve_case(store, case_id)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if html:
        click.echo("HTML reporting is planned for Phase 5.", err=True)
        ctx.exit(3)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def analyze(ctx: click.Context, path: Path, cases_dir: str | None, as_json: bool) -> None:
    """Full pipeline (static + unpack + emulation). Planned for Phase 5."""
    click.echo(
        "deep analysis is planned for Phase 5. For now run:\n"
        f"  glassbox scan {path}",
        err=True,
    )
    ctx.exit(3)


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def unpack(ctx: click.Context, path: Path) -> None:
    """Detect and unpack packers. Planned for Phase 3."""
    click.echo(f"unpacking is planned for Phase 3 (input: {path}).", err=True)
    ctx.exit(3)


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def emu(ctx: click.Context, path: Path) -> None:
    """Emulate the sample and collect behaviour. Planned for Phase 4."""
    click.echo(f"emulation is planned for Phase 4 (input: {path}).", err=True)
    ctx.exit(3)


@cli.group()
def rules() -> None:
    """Inspect the static rule set."""


@rules.command("list")
def list_rules() -> None:
    """List built-in static rules."""
    console = Console()
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("rule", style="dim", no_wrap=True)
    table.add_column("title")
    for rule_id, title in RULE_CATALOG:
        table.add_row(rule_id, title)
    console.print(table)


@rules.command("test")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def test_rules(ctx: click.Context, path: Path, as_json: bool) -> None:
    """Run static rules against one file (no cached case reused)."""
    try:
        case, _, store = _scan(path, None, True)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))
    ctx.exit(_exit_code(case))


if __name__ == "__main__":
    cli()
