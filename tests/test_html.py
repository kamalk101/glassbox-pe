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
    # The report is a single offline document: no script blocks or CDN assets.
    assert "<script" not in html.lower()
    assert "https://" not in html.lower()
    # Event targets are escaped by the template, not injected as markup.
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_html_view_includes_static_and_correlation_sections(tmp_path):
    case = _analyzed(tmp_path)

    view = build_html_view(case)

    assert view["pe"]["machine"] in {"x86", "x86-64"}
    assert view["sections"]
    assert view["import_groups"]
    assert view["correlation"]["findings"] == len(case.findings)
    assert view["correlation"]["events"] == len(case.events)
