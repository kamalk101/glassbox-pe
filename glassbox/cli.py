"""GlassBox PE command line interface."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.table import Table

from . import score
from .analyzer import analyze_static
from .cases import CaseStore
from .config import resolve_cases_dir
from .emu import EmulationOutcome, apply_emulation, run_emulation
from .evaluation import evaluate_corpus
from .ingest import ingest
from .report import render_case, render_html, render_json, render_quiet
from .report.dashboard import render_dashboard, write_case_reports
from .report.eval_terminal import render_evaluation
from .schema import TOOL_VERSION, Case, Category, Severity, Source, VerdictLabel
from .observed import attach_observed, load_report
from .static.rules import RULE_CATALOG
from .static.yara import load_rules as load_yara_rules
from .unpack import diff_cases, unpack_sample
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


def _deep_scan(
    path: Path,
    cases_dir: str | None,
    timeout: int,
    force: bool,
) -> tuple[Case, EmulationOutcome, CaseStore]:
    case, _, store = _scan(path, cases_dir, force)
    workdir = store.case_dir(case.case_id) / "emulation"
    outcome = run_emulation(path, timeout=timeout, workdir=workdir)
    apply_emulation(case, outcome)
    store.save(case)
    return case, outcome, store


def _recompute_verdict(case: Case) -> None:
    if not case.verdict or case.verdict.label is VerdictLabel.INCONCLUSIVE:
        return
    case.verdict = score.build_verdict(
        case.findings,
        static_only=case.verdict.static_only,
        sneakiness=case.verdict.sneakiness,
        sneakiness_reasons=case.verdict.sneakiness_reasons,
        signed=bool((case.artifacts.get("pe") or {}).get("signed")),
    )
    case.verdict.techniques = case.techniques()


def _forget_previous_unpack(case: Case) -> None:
    previous = case.artifacts.pop("unpack", None)
    if isinstance(previous, dict) and previous.get("event_id"):
        event_id = previous["event_id"]
        case.events = [event for event in case.events if event.id != event_id]
    case.findings = [finding for finding in case.findings if finding.rule_id != "GB-UNP-001"]


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
@click.option("--html", is_flag=True, help="Write a standalone HTML report.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.pass_context
def report(
    ctx: click.Context,
    case_id: str,
    cases_dir: str | None,
    as_json: bool,
    html: bool,
    output: Path | None,
) -> None:
    """Re-emit a stored report."""
    store = CaseStore(resolve_cases_dir(cases_dir))
    try:
        case = _resolve_case(store, case_id)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if html and as_json:
        click.echo("error: choose --html or --json, not both", err=True)
        ctx.exit(3)
    if html:
        target = (output or (store.case_dir(case.case_id) / "report.html")).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_html(case), encoding="utf-8")
        click.echo(str(target))
    elif as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))


@cli.command()
@click.option("--cases-dir", default=None)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option("--reports", is_flag=True, help="Generate a standalone HTML report for every case.")
def dashboard(
    cases_dir: str | None,
    output: Path | None,
    reports: bool,
) -> None:
    """Write an offline dashboard for all stored cases."""
    store = CaseStore(resolve_cases_dir(cases_dir))
    rows = store.list()
    written = []
    if reports and rows:
        written = write_case_reports(store, rows)
        rows = store.list()

    target = (output or (store.root / "index.html")).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_dashboard(rows), encoding="utf-8")
    click.echo(str(target))
    if reports:
        click.echo(f"wrote {len(written)} case report(s)")


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--timeout", default=60, type=click.IntRange(1, 600), show_default=True)
@click.option("--force", is_flag=True, help="Re-run static analysis before emulating.")
@click.pass_context
def analyze(
    ctx: click.Context,
    path: Path,
    cases_dir: str | None,
    as_json: bool,
    timeout: int,
    force: bool,
) -> None:
    """Static analysis plus emulation (deep triage)."""
    try:
        case, outcome, store = _deep_scan(path, cases_dir, timeout, force)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))
    if not getattr(outcome, "ran", False):
        click.echo(f"emulation failed: {getattr(outcome, 'error', 'unknown error')}", err=True)
        ctx.exit(3)
    ctx.exit(_exit_code(case))


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option("--no-analyze", is_flag=True, help="Unpack only; do not analyze the result.")
@click.option("--force", is_flag=True, help="Re-run static analysis before unpacking.")
@click.pass_context
def unpack(
    ctx: click.Context,
    path: Path,
    cases_dir: str | None,
    as_json: bool,
    output: Path | None,
    no_analyze: bool,
    force: bool,
) -> None:
    """Detect a packer, unpack UPX, and diff the unpacked result."""
    try:
        case, _, store = _scan(path, cases_dir, force)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)

    workdir = store.case_dir(case.case_id) / "unpacked"
    output_path = output or (workdir / f"{path.stem}.unpacked{path.suffix or '.exe'}")
    result = unpack_sample(path, output_path)

    if result.status == "not_packed":
        click.echo("no known packer detected; nothing to unpack.", err=True)
        ctx.exit(0)

    _forget_previous_unpack(case)

    if not result.success:
        case.errors.append(f"unpack: {result.error}")
        case.artifacts["unpack"] = result.to_dict()
        _recompute_verdict(case)
        store.save(case)
        click.echo(f"unpack failed: {result.error}", err=True)
        if as_json:
            click.echo(render_json(case))
        ctx.exit(3)

    event = case.add_event(
        Category.PE,
        "unpacked",
        target=result.method or "unknown",
        data=result.to_dict(),
    )

    child_case: Case | None = None
    diff: dict | None = None
    if not no_analyze:
        try:
            child_case = analyze_static(ingest(result.output_path))
        except (OSError, ValueError) as exc:
            case.errors.append(f"unpack child analysis: {exc}")
        else:
            if child_case.case_id == case.case_id:
                case.errors.append("unpack produced an identical file; child analysis skipped")
                child_case = None
            else:
                store.save(child_case)
                diff = diff_cases(case, child_case)
                new_findings = set(diff.get("new_findings") or [])
                new_high = [
                    finding
                    for finding in child_case.findings
                    if finding.rule_id in new_findings
                    and finding.severity in (Severity.HIGH, Severity.CRITICAL)
                ]
                score_delta = (diff.get("child_score") or 0) - (diff.get("parent_score") or 0)
                has_new = bool(
                    new_findings
                    or diff.get("new_imports")
                    or diff.get("new_sections")
                )
                if new_high or score_delta >= 20:
                    severity = Severity.HIGH
                elif has_new:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.INFO

                if has_new or abs(score_delta) >= 10 or new_high:
                    techniques = sorted(
                        {
                            technique
                            for finding in child_case.findings
                            if finding.rule_id in new_findings
                            for technique in finding.techniques
                        }
                    )
                    case.add_finding(
                        rule_id="GB-UNP-001",
                        title="Hidden capabilities revealed by unpacking",
                        severity=severity,
                        description=(
                            f"Unpacking with {result.method} exposed "
                            f"{len(diff.get('new_imports') or [])} new import(s), "
                            f"{len(diff.get('new_findings') or [])} new finding(s), and "
                            f"{len(diff.get('new_sections') or [])} new section(s). "
                            f"Child case: {child_case.case_id}."
                        ),
                        category=Category.PE,
                        evidence=[event.id],
                        techniques=techniques,
                        source=Source.STATIC,
                        confidence=0.8,
                        data=diff,
                    )

    case.artifacts["unpack"] = {
        **result.to_dict(),
        "event_id": event.id,
        "child_case_id": child_case.case_id if child_case else None,
        "diff": diff,
    }

    _recompute_verdict(case)

    store.save(case)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))
    ctx.exit(_exit_code(case))


@cli.group()
def observe() -> None:
    """Attach an isolated VM observation report to a case."""


@observe.command("ingest")
@click.option("--report", "report_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Observed-run JSON report produced in the Windows lab.")
@click.option("--sample", default=None, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Sample to statically scan before attaching the observation.")
@click.option("--case-id", default=None, help="Existing case id or unique prefix.")
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--force", is_flag=True, help="Re-scan the sample before attaching the report.")
@click.pass_context
def observed_ingest(ctx, report_path, sample, case_id, cases_dir, as_json, force):
    """Merge an observed-run report into a case."""
    try:
        report = load_report(report_path)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)

    store = CaseStore(resolve_cases_dir(cases_dir))
    if sample and case_id:
        click.echo("error: choose --sample or --case-id, not both", err=True)
        ctx.exit(3)
    try:
        if sample:
            case, _, store = _scan(sample, cases_dir, force)
        elif case_id:
            case = _resolve_case(store, case_id)
        else:
            click.echo("error: provide --sample or --case-id", err=True)
            ctx.exit(3)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)

    if report.sample_sha256 and case.hashes.get("sha256", "").lower() != report.sample_sha256:
        click.echo("error: observed report does not match the selected sample", err=True)
        ctx.exit(3)

    attach_observed(case, report)
    if case.verdict:
        case.verdict.static_only = False
    _recompute_verdict(case)
    store.save(case)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--cases-dir", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--timeout", default=60, type=click.IntRange(1, 600), show_default=True)
@click.option("--force", is_flag=True, help="Re-run static analysis before emulating.")
@click.pass_context
def emu(
    ctx: click.Context,
    path: Path,
    cases_dir: str | None,
    as_json: bool,
    timeout: int,
    force: bool,
) -> None:
    """Emulate the sample and collect attempted behaviour."""
    try:
        case, outcome, store = _deep_scan(path, cases_dir, timeout, force)
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)
    if as_json:
        click.echo(render_json(case))
    else:
        render_case(case, case_path=str(store.case_path(case.case_id)))
    if not getattr(outcome, "ran", False):
        click.echo(f"emulation failed: {getattr(outcome, 'error', 'unknown error')}", err=True)
        ctx.exit(3)
    ctx.exit(_exit_code(case))


@cli.command("eval")
@click.argument("corpus", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Print the evaluation result as JSON.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@click.option(
    "--mode",
    type=click.Choice(["static", "unpack", "emulation"], case_sensitive=False),
    default="static",
    show_default=True,
    help="Ablation: static only, static+unpack, or static+emulation.",
)
@click.option("--timeout", default=30, type=click.IntRange(1, 600), show_default=True)
@click.option("--limit", default=None, type=click.IntRange(1), help="Evaluate only the first N manifest entries.")
@click.option(
    "--yara-rules",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Extra YARA file or directory (repeatable). Defaults to built-in rules.",
)
@click.pass_context
def evaluate_command(
    ctx: click.Context,
    corpus: Path,
    as_json: bool,
    output: Path | None,
    mode: str,
    timeout: int,
    limit: int | None,
    yara_rules: tuple[Path, ...],
) -> None:
    """Evaluate triage against a labelled corpus manifest."""
    try:
        result = evaluate_corpus(
            corpus,
            mode=mode.lower(),
            timeout=timeout,
            limit=limit,
            yara_rules=yara_rules or None,
        )
    except (OSError, ValueError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(3)

    payload = json.dumps(result, indent=2)
    if output:
        target = output.expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
        if not as_json:
            click.echo(f"wrote {target}")

    if as_json:
        click.echo(payload)
    else:
        render_evaluation(result)
    if result["metrics"]["samples"] == 0:
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


@rules.command("yara")
def list_yara() -> None:
    """Show YARA availability and built-in rule files."""
    compiled, error = load_yara_rules()
    console = Console()
    if compiled is None:
        console.print(f"[yellow]YARA unavailable:[/yellow] {error}")
        return
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("rule file", style="dim")
    for path in compiled.files:
        table.add_row(path)
    console.print(table)
    console.print(f"[dim]{compiled.count} YARA rule(s) from {len(compiled.files)} file(s)[/dim]")


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
