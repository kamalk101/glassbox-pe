#!/usr/bin/env sh
# Class-demo walkthrough: static triage, HTML report, and corpus evaluation.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

GLASSBOX="${GLASSBOX:-$ROOT/.venv/bin/glassbox}"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="${GLASSBOX_DEMO_DIR:-/tmp/opencode/glassbox-demo}"

if [ ! -x "$GLASSBOX" ]; then
  echo "missing $GLASSBOX; run: make install" >&2
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

echo "== build synthetic packed sample =="
"$PYTHON" tests/fixtures/make_pe.py "$WORK/demo-packed.exe" --packed

echo
echo "== static triage =="
# The sample is intentionally suspicious, so scan exits non-zero; keep the JSON.
"$GLASSBOX" scan "$WORK/demo-packed.exe" --json --cases-dir "$WORK/cases" > "$WORK/case.json" || true
"$PYTHON" - "$WORK/case.json" <<'PY'
import json, sys
case = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"case: {case['case_id']}")
print(f"verdict: {case['verdict']['label']} score={case['verdict']['score']} confidence={case['verdict']['confidence']}")
print("findings:", ", ".join(f["rule_id"] for f in case["findings"]))
with open(sys.argv[1] + ".id", "w", encoding="utf-8") as fh:
    fh.write(case["case_id"])
PY

echo
echo "== standalone HTML report =="
CASE_ID="$(cat "$WORK/case.json.id")"
"$GLASSBOX" report "$CASE_ID" --cases-dir "$WORK/cases" --html

echo
echo "== synthetic corpus evaluation =="
"$PYTHON" scripts/make_corpus.py "$WORK/corpus"
"$GLASSBOX" eval "$WORK/corpus"

echo
echo "demo artefacts: $WORK"
