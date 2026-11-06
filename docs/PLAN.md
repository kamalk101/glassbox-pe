# GlassBox PE — Build Plan

> Offline, evidence-first triage for a single Windows executable. Two-person
> project. CLI first, UI later. Emulation instead of a Windows VM.

## Product sentence

**GlassBox PE takes one `.exe`, sees through packing, emulates it safely, correlates
static claims with attempted behaviour, and produces a technique-level verdict with
proof for every claim.**

## Scope

### In scope
- One selected `.exe` at a time (on-demand triage, not a background monitor)
- Static PE analysis, string/IOC extraction, capability rules
- Packer detection and unpacking (UPX first, generic later)
- User-mode emulation with Speakeasy (process/file/network/registry events)
- Correlation, evidence-weighted verdict, ATT&CK mapping
- Recursive payload analysis (dropped files and embedded PE resources)
- JSON, terminal, and HTML reports; STIX export later
- Optional UI after the CLI is solid

### Out of scope
- Real-time protection or kernel drivers
- Live malware execution on the host
- Real C2 contact; no outbound traffic from samples
- Automatic remediation
- Cloud service or multi-user deployment
- Claims of guaranteed detection

## Architecture

```
                    ┌──────────────────────────────┐
                    │ Core analyzer (pure Python)  │
                    │ rules · scoring · report     │
                    └──────────────▲───────────────┘
                                   │ common event schema
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
      ┌──────┴──────┐       ┌──────┴───────┐      ┌──────┴───────┐
      │ Static      │       │ Emulation    │      │ VM (future)  │
      │ backend     │       │ backend      │      │ backend      │
      │ pefile/dnfile│      │ Speakeasy   │      │ Sysmon/ETW   │
      │ YARA/capa   │       │ Qiling       │      │ Procmon/pcap │
      └─────────────┘       └──────────────┘      └──────────────┘
       strength: static      strength: attempted    strength: observed
```

The analyzer never depends on one backend. Swapping emulation for a VM later is a
backend change, not a rewrite.

## Event schema

Every fact is an event:

```json
{
  "id": "evt-0042",
  "source": "emulation",
  "strength": "attempted",
  "category": "network",
  "action": "http_post",
  "target": "https://bad.example/gate.php",
  "data": {"body_preview": "user=kamal", "bytes": 312},
  "technique": "T1071.001",
  "parent": "evt-0031"
}
```

- **Categories:** `process`, `file`, `network`, `registry`, `pe`, `signature`, `other`
- **Strength:** `static` (capability), `attempted` (emulated attempt), `observed` (VM)
- Every finding references one or more event IDs.

## Phases

| Phase | Goal | Status |
|---|---|---|
| **0** | Repo, CLI, case store, schema v0, synthetic PE fixture | done |
| **1** | Static core: PE parse, strings/IOCs, import behaviours, rules, scoring, terminal + JSON | done |
| **2** | Rule depth, sneakiness breakdown, YARA, capa, installer detection | part done (sneakiness reasons, built-in YARA, managed .NET metadata markers; capa still absent) |
| **3** | Packer detection + UPX/generic unpack + before/after diff | done for UPX; generic embedded/appended-PE extraction added; common packers detected, full generic unpack planned |
| **4** | Speakeasy emulation: process/file/network/registry events, dropped files | basic done, validated on 23 local benign samples (19 ran, 4 ARM64 unsupported); network/registry classification, pointer resolution, and a full synthetic all-category report added; network/registry still not observed in benign corpus |
| **5** | Correlation, technique-level verdicts, evidence graph, HTML report, differential | done (correlation summary, evidence-linked HTML, unpack diff); graph UI later |
| **6** | Corpus, evaluation (PR-AUC, per-technique recall, evasion), demo script | partial (synthetic + local benign + mixed set; ablation modes, staging/validation/FP-study tooling; real malicious samples pending) |
| **7** | UI: case dashboard, evidence graph, timeline, diff viewer | done (offline searchable dashboard, multi-case timeline and verdict activity charts; interactive case graph/timeline/diff) |
| **8** | Native Windows desktop shell (PySide6) | in progress (case list, scan queue, detail views) |

## Feature tiers

### Must (demo works)
Static core, YARA, sneakiness score, UPX unpack, emulation in four categories,
correlation, technique verdicts, JSON + HTML, CLI workflow.

### Strong
Generic unpack for embedded/appended PE, installer recursion, differential/trojanized-update detection,
STIX export, similarity search (imphash/ssdeep/TLSH), counterfactuals, batch mode.

### Stretch
UI, ML classifier with SHAP/calibration, VM backend, watch mode, threat-intel
enrichment, Qiling fallback.

## Safety rules

- Never execute a sample on the host.
- Emulation runs inside Speakeasy/Qiling, in a subprocess, never natively.
- Real samples only inside an isolated environment; live demo uses synthetic samples.
- No outbound network during analysis; network calls are simulated.
- Case files store hashes and metadata, not the original binary (dropped files are
  captured separately under the case's emulation directory).
- Do not add features that make samples run on the host.

## Evaluation plan

- **Corpus:** 20–30 benign (portable apps, installers, dev tools), 5–8 synthetic
  malicious exes, 5–10 real samples handled in isolation. Current status:
  28 clean benign controls (23 local-install + 5 pinned public installers), 10
  synthetic fixtures; real malicious set pending.
  See `docs/EVALUATION.md`.
- **Metrics:** PR-AUC, recall at FPR ≤ 1%, technique-level recall on synthetic
  samples, calibration check on the evidence-weighted confidence.
- **Ablation:** static vs static+unpack vs static+emulation.
- **Evasion:** UPX, .NET obfuscation (metadata markers only; no IL analysis),
  anti-VM sample; document failures.
- **False positives:** installer-aware analysis and signed binaries.
- **Future bonus:** compare emulated `attempted` behaviour with VM `observed`
  behaviour.

### Implemented harness

`glassbox eval <corpus>` reads a JSON manifest and emits machine-readable or
terminal metrics. Modes: `static`, `unpack`, `emulation`. Metrics include
PR-AUC, recall at FPR ≤ 1%, calibration (Brier/ECE), per-class scores, and
technique-level recall. `scripts/make_corpus.py` generates the ten-fixture
synthetic smoke set. `scripts/make_local_benign_corpus.py`,
`scripts/make_mixed_corpus.py`, and `scripts/make_upx_corpus.py` build the
real-benign, mixed, installer, and UPX ablation sets.
`scripts/fetch_benign_installers.py` materialises five pinned public benign
installer binaries. `scripts/stage_real_corpus.py`,
`scripts/validate_corpus.py`, and `scripts/false_positive_study.py` are the
isolated real-corpus workflow. `scripts/run_real_corpus_evaluation.py`
validates provenance and integrity, then runs static/unpack/optional emulation
and writes a measurement report without executing a sample.
`scripts/run_emulation_coverage.py` runs Speakeasy across a benign corpus, one
sample per subprocess, and writes a category/behaviour coverage matrix.
`scripts/summarize_emulation_coverage.py` prints a per-sample and per-category
coverage table from an emulation JSON report. See `docs/REAL_CORPUS.md`,
`docs/ISOLATED_LAB.md`, `docs/PHASE_6_DRY_RUN.md`, `docs/EMULATION_COVERAGE.md`,
and `docs/EVALUATION.md`. The
harness can be pointed at a real malicious corpus once samples are lawfully
available.

## Current commands

```bash
glassbox scan sample.exe              # static triage
glassbox scan sample.exe --json       # machine-readable
glassbox scan sample.exe --quiet      # one-line verdict
glassbox emu sample.exe --timeout 60  # static + emulation
glassbox analyze sample.exe           # alias for the deep path
glassbox unpack packed.exe            # UPX unpack + child diff
glassbox unpack packed.exe --json
glassbox report <id> --html           # standalone evidence-linked report
glassbox dashboard --reports          # offline case index + per-case reports
glassbox eval corpus/demo             # labelled-corpus metrics (static)
glassbox eval corpus/mixed-extended         # local benign + installers + synthetic malicious
make bench-extended                 # build and evaluate the extended mixed set
glassbox eval corpus/local-benign --mode emulation --timeout 8
glassbox eval corpus/upx-benign --mode unpack
make corpus-validate              # corpus sanity + coverage counts
make fp-study                     # false-positive slices by signature/packer/etc.
make real-eval CORPUS=/path/to/real-corpus ARGS="--emulation --timeout 60"
python scripts/stage_real_corpus.py /path/to/samples --confirm-malware
glassbox rules yara                   # built-in YARA status
glassbox cases list
glassbox cases show <id-or-prefix>
glassbox rules list
glassbox rules test sample.exe
```

`make corpus` generates the ten-fixture synthetic corpus under `corpus/demo/`.
`make eval` runs the static evaluator and prints accuracy, per-class scores,
binary PR-AUC, recall at FPR ≤ 1%, calibration, confusion matrix, and ATT&CK
technique recall. `make bench` builds the mixed set and prints the same metrics
against it. `make bench-extended` does the same for 36 samples: 28 clean
benign controls plus the synthetic malicious fixtures.

UPX discovery precedence: `GLASSBOX_UPX`, `PATH`, then `tools/upx` in the
project. Fetch a standalone binary with `sh scripts/fetch_upx.sh`.

Exit codes: `0` clean, `1` suspicious, `2` malicious, `3` inconclusive/error.
