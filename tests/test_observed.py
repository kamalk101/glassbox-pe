import json
from pathlib import Path

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.observed import attach_observed, load_report
from glassbox.schema import Source
from tests.fixtures.make_pe import build_pe


def test_observed_ingest_replaces_and_links_evidence(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    case = analyze_static(ingest(sample))
    sha256 = case.hashes["sha256"]
    report_path = tmp_path / "observed.json"
    report_path.write_text(
        json.dumps(
            {
                "schema_version": "0.1",
                "sample": {
                    "file_name": "sample.exe",
                    "sha256": sha256,
                    "path": str(sample),
                },
                "environment": {
                    "vm_name": "tiny",
                    "isolated": True,
                    "os": "Windows 10",
                },
                "started_at": "2026-11-06T00:00:00+00:00",
                "ended_at": "2026-11-06T00:00:01+00:00",
                "exit_code": 0,
                "events": [
                    {
                        "id": 1,
                        "provider": "Microsoft-Windows-Sysmon",
                        "target": "process create",
                        "action": "process_start",
                        "category": "process",
                        "process_id": "1234",
                    },
                    {
                        "id": 3,
                        "provider": "Microsoft-Windows-Sysmon",
                        "target": "connect 192.0.2.1:443",
                        "action": "network_connect",
                        "category": "network",
                        "process_id": "1234",
                        "technique": "T1071.001",
                    },
                    {
                        "id": 11,
                        "provider": "Microsoft-Windows-Sysmon",
                        "target": "C:\\Users\\Public\\dropped.exe",
                        "action": "file_create",
                        "category": "file",
                        "process_id": "1234",
                    },
                ],
                "dropped_files": [
                    {"path": "C:\\Users\\Public\\dropped.exe", "size": 12, "sha256": "abc123"},
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    report = load_report(report_path)
    attach_observed(case, report)

    observed = [event for event in case.events if event.source is Source.VM]
    assert any(event.action == "process_start" for event in observed)
    assert any(event.action == "network_connect" for event in observed)
    assert any(event.action == "file_create" for event in observed)

    dropped = [event for event in observed if event.action == "dropped_file"]
    assert len(dropped) == 1

    assert case.artifacts["observed"]["events"] == 3
    assert case.artifacts["observed"]["dropped_files"] == 1
    assert any(finding.rule_id == "GB-OBS-001" for finding in case.findings)
