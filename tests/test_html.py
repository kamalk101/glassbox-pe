from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.report.html_report import build_html_view, render_html
from glassbox.schema import Category
from tests.fixtures.make_pe import build_pe


def _analyzed(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe(strings=["<script>alert('x')</script>"]))
    return analyze_static(ingest(sample))


def test_html_report_has_offline_structure_and_evidence(tmp_path):
    case = _analyzed(tmp_path)
    case.add_event(Category.OTHER, "test", target="<script>alert('x')</script>")

    html = render_html(case, generated_at="2026-01-01 00:00 UTC")

    assert html.startswith("<!doctype html>")
    assert case.case_id in html
    assert "Evidence events" in html
    assert 'id="evt-0001"' in html
    assert "Correlation and ATT&amp;CK techniques" in html
    assert "T1055" in html
    assert "2026-01-01 00:00 UTC" in html
    # Offline report: one intentional inline module, no CDN assets.
    assert html.count("<script>") == 1
    assert "<script src" not in html.lower()
    assert "https://" not in html.lower()
    assert 'id="evidence-graph"' in html
    assert 'id="event-timeline"' in html
    assert "graph-node" in html
    assert "Events timeline" in html
    # Event targets are escaped by the template, not injected as markup.
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_html_report_renders_observed_evidence(tmp_path):
    from glassbox.observed import attach_observed, load_report
    import json

    case = _analyzed(tmp_path)
    report_path = tmp_path / "observed.json"
    report_path.write_text(
        json.dumps(
            {
                "sample": {"sha256": case.hashes["sha256"], "file_name": case.file_name},
                "environment": {"vm_name": "tiny", "isolated": True},
                "started_at": "2026-11-06T00:00:00+00:00",
                "ended_at": "2026-11-06T00:00:01+00:00",
                "events": [{"action": "process_start", "category": "process", "target": "sample.exe"}],
                "dropped_files": [],
            }
        ),
        encoding="utf-8",
    )

    attach_observed(case, load_report(report_path))
    html = render_html(case, generated_at="2026-01-01 00:00 UTC")

    assert "Observed evidence" in html
    assert "tiny" in html


def test_html_view_includes_static_and_correlation_sections(tmp_path):
    case = _analyzed(tmp_path)

    view = build_html_view(case)

    assert view["pe"]["machine"] in {"x86", "x86-64"}
    assert view["sections"]
    assert view["import_groups"]
    assert view["correlation"]["findings"] == len(case.findings)
    assert view["correlation"]["events"] == len(case.events)
    assert len(view["event_graph"]["nodes"]) == len(case.events) + len(case.findings)


def test_html_report_renders_unpack_diff_viewer(tmp_path):
    case = _analyzed(tmp_path)
    case.artifacts["unpack"] = {
        "status": "unpacked",
        "method": "upx",
        "packer": {"name": "UPX", "confidence": "high", "evidence": ["upx0"]},
        "tool": "upx",
        "child_case_id": "child-001",
        "new_imports": ["CreateFileA", "WSAConnect"],
        "removed_imports": [],
        "new_sections": [".upx"],
        "resolved_findings": [],
        "new_findings": ["GB-PROC-001"],
        "diff": {
            "child_case_id": "child-001",
            "size_delta": 12,
            "new_imports": ["CreateFileA", "WSAConnect"],
            "removed_imports": [],
            "new_sections": [".upx"],
            "removed_sections": [],
            "new_findings": ["GB-PROC-001"],
            "resolved_findings": [],
            "parent_verdict": "clean",
            "child_verdict": "malicious",
            "parent_score": 20,
            "child_score": 55,
            "parent_confidence": 0.5,
            "child_confidence": 0.8,
        },
    }

    html = render_html(case, generated_at="2026-01-01 00:00 UTC")

    assert 'id="unpack-diff"' in html
    assert "Changed only" in html
    assert "CreateFileA" in html
    assert "GB-PROC-001" in html
    assert "55</td>" in html or "risk score" in html
