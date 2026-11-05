"""YARA matching for static evidence.

The built-in rules live in ``yara_rules/`` next to this file. They are compiled
once per process and matched against the raw sample bytes. A match becomes an
evidence event and a finding, just like a Python rule, so the report can link
the conclusion back to a concrete rule and byte offset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..schema import Case, Category, Severity, Source

BUILTIN_RULE_DIR = Path(__file__).resolve().parent / "yara_rules"
CATEGORY_FALLBACK = Category.OTHER
VALID_CATEGORIES = {category.value for category in Category}
SEVERITY_NAMES = {severity.value for severity in Severity}
RULE_DEFINITION_RE = re.compile(r"^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*", re.MULTILINE)


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "strings": self.strings,
        }


@dataclass
class YaraScanResult:
    available: bool
    matches: list[YaraMatch] = field(default_factory=list)
    rule_files: list[str] = field(default_factory=list)
    rules_compiled: int = 0
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "rules": self.rules_compiled,
            "rule_files": self.rule_files,
            "matches": len(self.matches),
            "error": self.error,
        }


@dataclass
class _CompiledRules:
    rules: Any
    files: list[str]
    count: int


def _resolve_files(rule_paths: Sequence[str | Path] | None) -> list[Path]:
    if rule_paths is None:
        return sorted(BUILTIN_RULE_DIR.glob("*.yar")) + sorted(BUILTIN_RULE_DIR.glob("*.yara"))
    files: list[Path] = []
    for raw in rule_paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            files.extend(sorted(path.glob("*.yar")))
            files.extend(sorted(path.glob("*.yara")))
        elif path.is_file():
            files.append(path)
    return files


@lru_cache(maxsize=8)
def _compile_cached(signature: tuple[tuple[str, int], ...]) -> _CompiledRules:
    import yara

    filepaths = {f"glassbox_{index}": str(path) for index, (path, _mtime) in enumerate(signature)}
    rules = yara.compile(filepaths=filepaths)
    rule_count = 0
    for path, _mtime in signature:
        try:
            rule_count += len(RULE_DEFINITION_RE.findall(Path(path).read_text(encoding="utf-8")))
        except OSError:
            rule_count += 0
    return _CompiledRules(
        rules=rules,
        files=[path for path, _mtime in signature],
        count=rule_count,
    )


def load_rules(rule_paths: Sequence[str | Path] | None = None) -> tuple[_CompiledRules | None, str | None]:
    try:
        import yara  # noqa: F401
    except ImportError:
        return None, "yara-python is not installed; install glassbox-pe to enable YARA"

    files = _resolve_files(rule_paths)
    if not files:
        return None, "no YARA rule files found"

    try:
        signature = tuple((str(path.resolve()), path.stat().st_mtime_ns) for path in files)
        return _compile_cached(signature), None
    except OSError as exc:
        return None, f"could not read YARA rules: {exc}"
    except Exception as exc:  # yara.Error is not available when the import is optional
        return None, f"could not compile YARA rules: {exc}"


def _string_matches(yara_match: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for string_match in getattr(yara_match, "strings", []) or []:
        identifier = getattr(string_match, "identifier", "")
        for instance in getattr(string_match, "instances", []) or []:
            raw = getattr(instance, "matched_data", b"") or b""
            try:
                preview = raw.decode("utf-8", "replace")
            except Exception:
                preview = repr(raw)
            found.append(
                {
                    "identifier": identifier,
                    "offset": int(getattr(instance, "offset", 0)),
                    "length": len(raw),
                    "preview": preview[:200],
                }
            )
            if len(found) >= 25:
                return found
    return found


def scan_bytes(data: bytes, rule_paths: Sequence[str | Path] | None = None) -> YaraScanResult:
    compiled, error = load_rules(rule_paths)
    if compiled is None:
        return YaraScanResult(available=False, error=error)

    try:
        matches = compiled.rules.match(data=data)
    except Exception as exc:
        return YaraScanResult(
            available=True,
            rule_files=compiled.files,
            rules_compiled=compiled.count,
            error=f"YARA scan failed: {exc}",
        )

    results = [
        YaraMatch(
            rule=getattr(match, "rule", ""),
            namespace=getattr(match, "namespace", "default"),
            tags=sorted(getattr(match, "tags", []) or []),
            meta=dict(getattr(match, "meta", {}) or {}),
            strings=_string_matches(match),
        )
        for match in matches
    ]
    return YaraScanResult(
        available=True,
        matches=results,
        rule_files=compiled.files,
        rules_compiled=compiled.count,
    )


def _severity(meta: dict[str, Any]) -> Severity:
    value = str(meta.get("severity", "medium")).lower()
    if value in SEVERITY_NAMES:
        return Severity(value)
    return Severity.MEDIUM


def _category(meta: dict[str, Any]) -> Category:
    value = str(meta.get("category", "other")).lower()
    if value in VALID_CATEGORIES:
        return Category(value)
    return CATEGORY_FALLBACK


def _techniques(meta: dict[str, Any], tags: Iterable[str]) -> list[str]:
    raw = str(meta.get("technique") or meta.get("techniques") or "").replace(",", " ")
    found = {item.strip().upper() for item in raw.split() if item.strip()}
    for tag in tags:
        candidate = str(tag).strip().upper()
        if candidate.startswith("T") and candidate[1:5].isdigit():
            found.add(candidate)
    return sorted(found)


def apply_to_case(case: Case, result: YaraScanResult) -> None:
    """Attach one evidence event and one finding per YARA match."""
    if result.error:
        case.errors.append(f"yara: {result.error}")

    for match in result.matches:
        meta = match.meta
        category = _category(meta)
        techniques = _techniques(meta, match.tags)
        rule_id = str(meta.get("gb_rule_id") or f"GB-YARA-{match.rule}")
        title = str(meta.get("title") or match.rule.replace("_", " ").title())
        description = str(
            meta.get("description")
            or f"YARA rule {match.rule} matched {len(match.strings)} string instance(s)."
        )
        event = case.add_event(
            category,
            "yara_match",
            target=match.rule,
            data={
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": meta,
                "strings": match.strings,
            },
            technique=techniques[0] if techniques else None,
        )
        case.add_finding(
            rule_id=rule_id,
            title=title,
            severity=_severity(meta),
            description=description,
            category=category,
            evidence=[event.id],
            techniques=techniques,
            source=Source.STATIC,
            confidence=float(meta.get("confidence", 0.8)),
            data={
                "yara_rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "matches": match.strings,
            },
        )
