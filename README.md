# GlassBox PE

**Offline, evidence-first triage for Windows PE executables.**

GlassBox PE takes a single `.exe`, looks at what it *is* and what it *tries to do*,
and produces a technique-level verdict where every claim is backed by an evidence
event.

> Status: **static core + basic Speakeasy emulation + UPX unpacking +
> evidence-linked reports + labelled-corpus evaluation + offline case
> dashboard**. Real-corpus evaluation and a richer interactive UI are next. See
> `docs/PLAN.md`.

## Why

Most student malware detectors output one number. GlassBox PE outputs:

- what the sample can do (static capabilities)
- what it tried to do (emulated behaviour)
- how hard it tries to hide (analysis-resistance score)
- which ATT&CK techniques are present
- exactly which artifact supports each conclusion

Every finding carries an **evidence strength**:

| Strength | Meaning |
|---|---|
| `static` | the code has the capability |
| `attempted` | it tried during emulation |
| `observed` | it really happened (VM backend, future) |

## Safety

The static path is **offline and non-executing**: it parses bytes and extracts
strings. The emulation path runs the sample inside **Speakeasy/Unicorn**, a CPU
emulator, in a subprocess — never natively on your host. Network calls are
simulated. Do not run real malware outside an isolated environment.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,emu]"
```

On Python 3.12+ the emulation extra pins `setuptools<81` because Speakeasy's
Unicorn 1.0.2 still imports `distutils` and `pkg_resources`.

`glassbox unpack` needs a UPX binary. Fetch a standalone copy into `tools/`
(ignored by git):

```bash
sh scripts/fetch_upx.sh
# or point at an existing binary
export GLASSBOX_UPX=/path/to/upx
```

## Usage

```bash
# Static triage only (fast, safe)
glassbox scan suspicious.exe

# Static + emulation
glassbox emu suspicious.exe --timeout 60
glassbox analyze suspicious.exe --timeout 60

# Detect a packer; unpack UPX and analyze the child
glassbox unpack packed.exe
glassbox unpack packed.exe --json

# Machine-readable output
glassbox scan suspicious.exe --json
glassbox emu suspicious.exe --json
glassbox unpack packed.exe --json

# List and inspect cases
glassbox cases list
glassbox cases show <sha256>

# Re-emit a stored report
glassbox report <sha256> --json
glassbox report <sha256> --html
glassbox report <sha256> --html --output /tmp/case.html

# Offline dashboard for every stored case (with per-case HTML reports)
glassbox dashboard --reports

# Build the synthetic demo corpus and evaluate static triage
make corpus
glassbox eval corpus/demo
glassbox eval corpus/demo --json

# One-shot class demo: static scan + HTML report + corpus metrics
make demo
```

`unpack` detects UPX, ASPack, MPRESS, Themida, VMProtect, Enigma, Petite, and
NsPack by section names/markers, plus a high-entropy/low-import heuristic. UPX
is unpacked automatically; other packers are reported as unsupported. The
unpacked child gets its own case, a before/after diff (sections, imports,
findings, score), and a `GB-UNP-001` finding when hidden capabilities appear.

`glassbox eval` reads a corpus directory containing `manifest.json` (or a
manifest path directly) and reports 3-class accuracy, per-class precision/recall,
binary precision/recall/F1, PR-AUC, a confusion matrix, and technique-level
recall. A manifest entry looks like:

```json
{
  "path": "suspicious-injection.exe",
  "label": "suspicious",
  "techniques": ["T1055"],
  "family": "injector",
  "notes": "process-injection capability"
}
```

`scripts/make_corpus.py` builds a six-sample synthetic corpus for demos and
regression checks. It is intentionally small and not a real-world benchmark.

`glassbox dashboard` writes an offline `index.html` with verdict counts, a
searchable/filterable case table, and links to per-case reports. Add `--reports`
to generate a `report.html` for every case first. The dashboard uses inline CSS
and JavaScript only; no server or network access is required.

Each scan creates a case directory:

```
cases/<sha256>/
  case.json                       # events, findings, verdict, hashes
  emulation/speakeasy-report.json # raw emulator report (after `emu`)
  emulation/dropped/              # files written during emulation
  unpacked/                       # unpacked child binary (after `unpack`)
  report.html                     # standalone report (after `report --html`)

cases/index.html                  # dashboard index (after `dashboard`)
```

## Current commands

| Command | Status |
|---|---|
| `scan` | working (static) |
| `emu` | working (Speakeasy: API events, dropped files, behaviour findings) |
| `analyze` | working (static + emulation) |
| `cases list/show/delete` | working |
| `report --json` | working |
| `report --html` | working (standalone, offline, evidence-linked) |
| `dashboard` | working (offline index, search/filter, per-case reports) |
| `rules list/test` | working |
| `unpack` | working (UPX only; detects other packers) |
| `eval` | working (labelled manifest; accuracy, PR-AUC, technique recall) |

Exit codes: `0` clean, `1` suspicious, `2` malicious, `3` inconclusive/error.

## Architecture

```
glassbox/
  cli.py          command line
  schema.py       Event / Finding / Verdict / Case contract
  ingest.py       hashing and case identity
  cases.py        case store
  static/
    pe.py         PE structure and anomalies
    strings.py    ASCII/UTF-16 strings + IOC extraction
    imports.py    suspicious API grouping
    packer.py     packer detection (UPX and common packers)
    rules.py      detection rules -> findings
  unpack/
    service.py    detect -> choose unpacker -> validate output
    upx.py        UPX discovery and subprocess invocation
    diff.py       packed vs unpacked child comparison
  emu/
    speakeasy_backend.py  subprocess runner + report/dropped-file capture
    apply.py              report -> attempted events + findings
  correlate.py    cross-source technique/evidence correlation
  evaluation.py   labelled-corpus metrics and manifest loading
  score.py        sneakiness + evidence-weighted verdict
  report/         terminal, JSON, case HTML, dashboard, evaluation output
```

## Tests

```bash
.venv/bin/pytest
```

Tests build synthetic PE fixtures in `tests/fixtures/make_pe.py`; no malware is
required. Emulation tests are skipped if Speakeasy is not installed. The current
suite has 43 tests, including corpus metrics, HTML escaping, dashboard
generation, and UPX unpacking with a fake unpacker.

## Current limitations

- Emulated API arguments are logged, but pointers are not yet resolved to strings.
- Child processes are not truly executed; dropped files are captured and queued.
- Emulation can be evaded by anti-analysis samples (`GB-EMU-000` flags this).
- Only UPX unpacking is implemented; other packers are detected and marked
  unsupported. Child payloads are analyzed one level deep, not recursively.
- Correlation is a report-level summary: it shows where static capabilities and
  attempted behaviour overlap, but it does not yet build a full graph database.
- The dashboard is a static offline index. It has no server, timeline scrubber,
  or interactive evidence-graph view yet.
- Emulation remains best-effort and can be evaded by anti-analysis samples.
- The evaluation corpus is synthetic and rule-aligned. Treat the perfect demo
  scores as a smoke test, not evidence of real-world detection quality; a real
  corpus is needed for the Phase 6 numbers. `glassbox eval` currently measures
  the static path only; unpack/emulation ablations are future work.
