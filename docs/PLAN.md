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
      │ pefile/LIEF │       │ Speakeasy    │      │ Sysmon/ETW   │
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
| **2** | Rule depth, sneakiness breakdown, YARA, capa, installer detection | part done (sneakiness reasons) |
| **3** | Packer detection + UPX/generic unpack + before/after diff | done for UPX; common packers detected, generic unpack planned |
| **4** | Speakeasy emulation: process/file/network/registry events, dropped files | basic done (API events, dropped files, behaviour findings) |
| **5** | Correlation, technique-level verdicts, evidence graph, HTML report, differential | done (correlation summary, evidence-linked HTML, unpack diff); graph UI later |
| **6** | Corpus, evaluation (PR-AUC, per-technique recall, evasion), demo script | partial (synthetic corpus + metrics harness; real corpus pending) |
| **7** | UI: case dashboard, evidence graph, timeline, diff viewer | optional |

## Feature tiers

### Must (demo works)
Static core, YARA, sneakiness score, UPX unpack, emulation in four categories,
correlation, technique verdicts, JSON + HTML, CLI workflow.

### Strong
Generic unpack, installer recursion, differential/trojanized-update detection,
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
  malicious exes, 5–10 real samples handled in isolation.
- **Metrics:** PR-AUC, recall at FPR ≤ 1%, technique-level recall on synthetic
  samples, calibration check on the evidence-weighted confidence.
- **Ablation:** static vs static+unpack vs static+emulation.
- **Evasion:** UPX, .NET obfuscation, anti-VM sample; document failures.
- **False positives:** installer-aware analysis and signed binaries.
- **Future bonus:** compare emulated `attempted` behaviour with VM `observed`
  behaviour.

### Implemented harness

`glassbox eval <corpus>` reads a JSON manifest and emits machine-readable or
terminal metrics. `scripts/make_corpus.py` generates a small synthetic smoke
corpus. The harness can be pointed at a real corpus later without changing the
analyzer; manifest labels and expected ATT&CK techniques drive the metrics.

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
glassbox eval corpus/demo             # labelled-corpus metrics
glassbox cases list
glassbox cases show <id-or-prefix>
glassbox rules list
glassbox rules test sample.exe
```

`make corpus` generates a six-sample synthetic corpus under `corpus/demo/`.
`make eval` runs the static evaluator and prints accuracy, per-class scores,
binary PR-AUC, confusion matrix, and ATT&CK technique recall.

UPX discovery precedence: `GLASSBOX_UPX`, `PATH`, then `tools/upx` in the
project. Fetch a standalone binary with `sh scripts/fetch_upx.sh`.

Exit codes: `0` clean, `1` suspicious, `2` malicious, `3` inconclusive/error.
