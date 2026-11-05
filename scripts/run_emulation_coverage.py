#!/usr/bin/env python3
"""Run Speakeasy emulation across a corpus, one sample per subprocess.

The worker mode isolates each sample so that a misbehaving emulator cannot kill
the reporting process. It never runs a sample natively; it only parses it and
invokes the user-mode Speakeasy backend.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.static.pe import parse_pe
from glassbox.emu import apply_emulation, run_emulation
from glassbox.evaluation import load_manifest


def _worker(sample: Path, output: Path, timeout: int) -> int:
    result = {
        "path": str(sample),
        "ran": False,
        "api_calls": 0,
        "behaviours": {},
        "categories": [],
        "resources": {"file": [], "network": [], "registry": []},
        "dropped_files": 0,
        "dynamic_segments": 0,
        "error": None,
        "static_score": None,
        "final_score": None,
        "findings": [],
    }
    try:
        info = parse_pe(sample.read_bytes())
        if info.is_pe and info.machine_name not in {"x86", "x86-64"}:
            result["error"] = f"unsupported architecture: {info.machine_name}"
            output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            return 0
        case = analyze_static(ingest(sample))
        result["static_score"] = case.verdict.score if case.verdict else None
        outcome = run_emulation(sample, timeout=timeout, workdir=tempfile.mkdtemp(prefix="glassbox-cov-"))
        apply_emulation(case, outcome)
        artifacts = case.artifacts.get("emulation") or {}
        result.update(
            {
                "ran": bool(outcome.ran),
                "api_calls": int(artifacts.get("api_calls") or 0),
                "behaviours": artifacts.get("behaviours") or {},
                "categories": sorted({e.category.value for e in case.events if e.source.value == "emulation"}),
                "resources": artifacts.get("resources") or {"file": [], "network": [], "registry": []},
                "dropped_files": len(outcome.dropped_files),
                "dynamic_segments": int(artifacts.get("dynamic_segments") or 0),
                "error": outcome.error,
                "final_score": case.verdict.score if case.verdict else None,
                "findings": [finding.rule_id for finding in case.findings],
            }
        )
    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = str(exc)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def _summarize(results: list[dict]) -> dict:
    from collections import Counter

    categories = Counter()
    behaviours = Counter()
    category_events = Counter()
    for result in results:
        if not result.get("ran"):
            continue
        for category in result.get("categories") or []:
            categories[category] += 1
        for behaviour, count in (result.get("behaviours") or {}).items():
            behaviours[behaviour] += int(count)
        # category_events is not available from per-sample worker output; use
        # category sample counts as the coverage matrix.
    return {
        "sample_count": len(results),
        "ran": sum(1 for r in results if r.get("ran")),
        "failed": sum(1 for r in results if not r.get("ran")),
        "api_calls": sum(int(r.get("api_calls") or 0) for r in results),
        "samples_with_api_events": sum(1 for r in results if int(r.get("api_calls") or 0)),
        "categories": dict(sorted(categories.items())),
        "behaviours": dict(sorted(behaviours.items())),
        "errors": [r for r in results if r.get("error")],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--sample", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("corpus", nargs="?")
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    if args.worker:
        if args.sample is None or args.output is None:
            print("worker mode requires --sample and --output", file=sys.stderr)
            return 2
        return _worker(args.sample.resolve(), args.output.resolve(), args.timeout)

    if args.corpus is None:
        print("error: corpus is required", file=sys.stderr)
        return 2
    corpus = Path(args.corpus).expanduser().resolve()
    base, manifest_path, entries = load_manifest(corpus)
    if args.limit is not None:
        entries = entries[: max(0, args.limit)]

    output_dir = args.output_dir or (ROOT / "reports" / "emulation-coverage")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    results_path = output_dir / "emulation-coverage.json"
    if results_path.exists():
        results = json.loads(results_path.read_text(encoding="utf-8")).get("samples", [])
    else:
        results = []
    seen = {r["path"] for r in results}

    env = dict(os.environ)
    env.setdefault("PYTHONWARNINGS", "ignore")

    for entry in entries:
        path = Path(entry["path"])
        if not path.is_absolute():
            path = base / path
        path = path.expanduser().resolve()
        if str(path) in seen:
            continue
        if not path.is_file():
            results.append({"path": str(path), "ran": False, "api_calls": 0, "error": "file not found"})
            _write_results(output_dir, results)
            continue

        worker_output = output_dir / f".{path.name}.json"
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            "--sample",
            str(path),
            "--output",
            str(worker_output),
            "--timeout",
            str(args.timeout),
        ]
        print(f"emulating {path.name}...", flush=True)
        try:
            completed = subprocess.run(command, env=env, text=True, capture_output=True, timeout=args.timeout + 90)
            if completed.returncode != 0:
                print(f"  worker failed: {completed.stderr.strip() or completed.stdout.strip()}", flush=True)
                result = {"path": str(path), "ran": False, "api_calls": 0, "error": f"worker failed: {completed.stderr.strip() or completed.stdout.strip()}"}
            elif not worker_output.is_file():
                result = {"path": str(path), "ran": False, "api_calls": 0, "error": "worker produced no output"}
            else:
                result = json.loads(worker_output.read_text(encoding="utf-8"))
        except subprocess.TimeoutExpired:
            result = {"path": str(path), "ran": False, "api_calls": 0, "error": "worker timed out"}
        except Exception as exc:  # pragma: no cover
            result = {"path": str(path), "ran": False, "api_calls": 0, "error": str(exc)}
        finally:
            try:
                worker_output.unlink(missing_ok=True)
            except OSError:
                pass
        results.append(result)
        seen.add(str(path))
        _write_results(output_dir, results)
        print(f"  ran={result.get('ran')} apis={result.get('api_calls')} categories={result.get('categories')} error={result.get('error')}")

    _write_markdown(output_dir, results, corpus)
    print(f"coverage report: {output_dir / 'EMULATION_COVERAGE.md'}")
    return 0


def _write_results(output_dir: Path, results: list[dict]) -> None:
    summary = _summarize(results)
    payload = {"corpus": str(output_dir), "samples": results, **summary}
    (output_dir / "emulation-coverage.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (output_dir / "emulation-coverage.json").chmod(0o600)


def _write_markdown(output_dir: Path, results: list[dict], corpus: Path) -> None:
    summary = _summarize(results)
    lines = [
        "# Emulation coverage matrix",
        "",
        f"- corpus: `{corpus}`",
        f"- samples: {summary['sample_count']}",
        f"- ran: {summary['ran']} · failed: {summary['failed']}",
        f"- API calls: {summary['api_calls']}",
        f"- samples with API events: {summary['samples_with_api_events']}",
        f"- categories: {summary['categories']}",
        f"- behaviours: {summary['behaviours']}",
        "",
        "| sample | ran | APIs | categories | behaviours |",
        "|---|---|---:|---|---|",
    ]
    for result in results:
        categories = ", ".join(result.get("categories") or []) or "-"
        behaviours = ", ".join(f"{k}:{v}" for k, v in sorted((result.get("behaviours") or {}).items())) or "-"
        lines.append(
            f"| `{result['path']}` | {'yes' if result.get('ran') else 'no'} | {result.get('api_calls', 0)} | {categories} | {behaviours} |"
        )
    if summary["errors"]:
        lines.extend(["", "## Errors", ""])
        for error in summary["errors"]:
            lines.append(f"- `{error['path']}`: {error['error']}")
    (output_dir / "EMULATION_COVERAGE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output_dir / "EMULATION_COVERAGE.md").chmod(0o600)


if __name__ == "__main__":
    raise SystemExit(main())
