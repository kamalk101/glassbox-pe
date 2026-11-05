# GlassBox PE

**Offline, evidence-first triage for Windows PE executables.**

GlassBox PE takes a single `.exe`, looks at what it *is* and what it *tries to do*,
and produces a technique-level verdict where every claim is backed by an evidence
event.

> Status: **static core + built-in YARA + Speakeasy emulation + UPX unpacking +
> evidence-linked reports + labelled-corpus evaluation (static / unpack / emulation)
> + offline case dashboard**. Real local benign-corpus evaluation is in place;
> real-malware evaluation is still pending. See `docs/EVALUATION.md` and `docs/PLAN.md`.

## Why

Most student malware detectors output one number. GlassBox PE outputs:

- what the sample can do (static capabilities)
- artifact-level matches (built-in YARA rules)
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

`yara-python` is a core dependency, so a C compiler is needed to build it on
Linux (wheels are available on most platforms). `dnfile` is pure Python and
enables metadata-level .NET analysis. On Python 3.12+ the emulation
extra pins `setuptools<81` because Speakeasy's Unicorn 1.0.2 still imports
`distutils` and `pkg_resources`.

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

# List built-in YARA rules and status
glassbox rules yara

# Re-emit a stored report
glassbox report <sha256> --json
glassbox report <sha256> --html
glassbox report <sha256> --html --output /tmp/case.html

# Offline dashboard for every stored case (with per-case HTML reports)
glassbox dashboard --reports

# Build the synthetic demo corpus and evaluate static triage
make corpus
glassbox eval corpus/demo
glassbox eval corpus/demo --mode static --json

# Ablation modes: static+unpack and static+emulation
glassbox eval corpus/upx-benign --mode unpack
glassbox eval corpus/local-benign --mode emulation --timeout 8

# Real local benign corpus (trusted installed software, no downloads)
make corpus-benign
glassbox eval corpus/local-benign
make corpus-mixed && glassbox eval corpus/mixed

# Official public benign installers + extended 36-sample measurement
make corpus-installers
make bench-extended

# Isolated real-corpus measurement (requires lawful samples in the lab)
make real-eval CORPUS=/path/to/real-corpus ARGS="--emulation --timeout 60"

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
binary precision/recall/F1, PR-AUC, recall at FPR ≤ 1%, calibration (Brier and
expected calibration error), a confusion matrix, and technique-level recall. It
also supports three ablation modes: `static`, `unpack`, and `emulation`. A
manifest entry looks like:

```json
{
  "path": "suspicious-injection.exe",
  "label": "suspicious",
  "techniques": ["T1055"],
  "family": "injector",
  "notes": "process-injection capability"
}
```

The corpus tooling builds several evaluation sets:

- `scripts/make_corpus.py` (`make corpus`) — ten synthetic PE fixtures; useful
  for regression and demo, not a real-world benchmark.
- `scripts/make_local_benign_corpus.py` (`make corpus-benign`) — collects real
  benign Windows PEs from trusted local installs (VS Code, Python launchers),
  deduplicates by SHA-256, labels them `clean`, and writes provenance into the
  manifest. No downloads, no execution.
- `scripts/make_mixed_corpus.py` (`make corpus-mixed`) — references the local
  benign corpus plus the non-clean synthetic samples, so you get a mixed-set
  measurement without copying files.
- `scripts/fetch_benign_installers.py` (`make corpus-installers`) — downloads
  five pinned official public installers/apps (7-Zip, Inno Setup, Python,
  Notepad++, NuGet) into ignored `corpus/benign-installers/`; never runs them
  and pins/records hashes and source URLs.
- `make corpus-extended` / `make bench-extended` — combines the local benign
  corpus, installer corpus, and synthetic malicious fixtures into a 36-sample
  set (28 clean, 3 suspicious, 5 malicious-synthetic) for evaluation.
- `scripts/make_upx_corpus.py` — packs a trusted benign PE with UPX for
  unpack-ablation testing (needs `make upx` or a system UPX).
- `scripts/stage_real_corpus.py` — stages operator-provided real samples into
  a private, ignored corpus directory, validates PE formatting, deduplicates,
  and creates a manifest. See `docs/REAL_CORPUS.md` for the safety workflow.
- `scripts/run_real_corpus_evaluation.py` (`make real-eval`) — in an
  isolated lab, validates provenance/integrity, runs static and UPX-unpack
  evaluation (optionally Speakeasy), and writes a report with mispredictions.
  See `docs/ISOLATED_LAB.md` and `docs/REAL_CORPUS.md`.
- `scripts/validate_corpus.py` (`make corpus-validate`) — checks manifest shape,
  duplicates, labels, ATT&CK IDs, provenance, imphash clusters, permissions,
  and reports signed / installer / .NET / packer coverage.
- `scripts/false_positive_study.py` (`make fp-study`) — runs the static path
  and slices results by signature, installer, .NET, packer, and family.

Current benign coverage includes 23 local-install PEs plus five pinned public
installer/application binaries. The extended 36-sample set shows 97.2%
accuracy, 0/28 false positives, 87.5% binary recall, PR-AUC 0.903, and 96%
technique recall; its only miss is `evasive-timing-only.exe`. It covers one
.NET assembly and two installer hints (`NSIS`, `Inno Setup`). This is still not
a real-malware benchmark.

Measured results are in `docs/EVALUATION.md`. In short: the local benign and
public installer corpora have zero false positives; the extended mixed set
shows 97.2% accuracy, 87.5% binary recall, and 96% technique recall, with one
known static false negative (`evasive-timing-only.exe`). No real malware has
been evaluated or executed.
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
| `report --html` | working (standalone, offline, interactive graph/timeline/diff) |
| `dashboard` | working (offline index, search/filter, per-case reports) |
| `rules list/test` | working |
| `rules yara` | working |
| `unpack` | working (UPX only; detects other packers) |
| `eval` | working (`--mode static|unpack|emulation`, PR-AUC, recall@FPR, calibration, technique recall) |

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
    yara.py       YARA loading/matching -> evidence-linked findings
    yara_rules/   built-in YARA rules
    dotnet.py     .NET CLR/metadata marker analysis
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
suite has 64 tests, including corpus metrics, HTML escaping, dashboard
generation, UPX unpacking with a fake unpacker, pointer resolution, YARA
matching, .NET metadata markers, the real-corpus runner, interactive report
sections, and the evaluation ablation harness.

## Current limitations

- .NET analysis reads CLR metadata at the PE level; it does not decompile or
  run IL. Findings describe capabilities and markers, not proof of intent. Only
  one .NET control is currently available in the extended corpus.
- Emulated API arguments are logged; pointers into the sample image are resolved to strings. Heap/stack pointers are still unresolved — see `docs/EMULATION.md` and `docs/EMULATION_COVERAGE.md`.

- Child processes are not truly executed; dropped files are captured and queued.
- Emulation is best-effort and can be evaded by anti-analysis samples
  (`GB-EMU-000` flags this). Speakeasy also rejects ARM64 samples with a clear
  error; 19/23 local benign samples ran and 4 ARM64 samples did not.
- Only UPX unpacking is implemented; other packers are detected and marked
  unsupported. Child payloads are analyzed one level deep, not recursively.
- Correlation is a report-level summary; it does not yet build a full graph
  database. The dashboard is static and offline (no server or persistent
  application). Case reports now include an interactive evidence graph,
  timeline, and unpack diff viewer, but there is no live server or multi-case
  timeline.
- The evaluation includes real **benign** binaries, but no real **malicious**
  samples have been evaluated or executed. The local benign corpus is also not
  representative. Real-malware numbers remain outstanding.
- `glassbox eval` can now run static / unpack / emulation ablations, but the
  mixed corpus is only real benign + synthetic malicious; it is not a benchmark
  of real-world detection quality.
- An Authenticode signature present reduces the score by 20 points. A signature
  is not validated against a chain or revocation list, and signed samples can
  still be flagged or remain clean. Treat it as a weak mitigation, not a trust
  decision.
- Static analysis misses timing-only anti-analysis samples such as
  `corpus/demo/evasive-timing-only.exe` (see `docs/EVALUATION.md`).
