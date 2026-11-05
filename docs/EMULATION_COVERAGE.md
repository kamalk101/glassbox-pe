# Emulation coverage validation

Date: 2026-11-05 · scope: real benign Windows PEs and synthetic fixtures · no real malware

This document records the coverage pass, not a claim of detection quality.

## Method

- static corpus evaluation: `glassbox eval <corpus-directory>`;
- emulation ablation: `glassbox eval <corpus-directory> --mode emulation --timeout 8`;
- coverage summary: `scripts/summarize_emulation_coverage.py <evaluation.json> [--markdown]`;
- synthetic acceptance coverage through `tests/test_emu.py`;
- no network access during emulation;
- no sample executed natively on this host.

The coverage JSON now records both sample counts and event/behaviour counts.
Older artefacts do not contain the new `category_events` / `behaviours`
fields; use a fresh evaluation run to populate them.

## Observed results on the 23-sample local benign corpus

| Set | Result |
|---|---|
| x86/x64 samples | 19/23 ran in emulation |
| ARM64 samples | 4/23 rejected by the backend (expected) |
| API events | 1,527 |
| Samples with API events | 19/19 x86/x64 |
| Samples with `file` events | 8 |
| Samples with `process` events | 12 |
| Samples with `pe` events | 19 |
| Samples with `other` events | 19 |
| Samples with `network` events | 0 |
| Samples with `registry` events | 0 |
| API-call range | 0–400 |
| Dropped files | 0 |
| Dynamic code segments | 0 |
| Attempted behaviour counts | `dynamic_loading` 73, `file` 8 |

The four unsupported samples are all ARM64, so they are reported as explicit
failures rather than counted as successful emulation.

Static evaluation remains:

- 23/23 correctly classified as clean;
- 0 false positives;
- no real malicious positives.

## Public installer corpus

The five pinned public installer binaries were **not re-run in emulation** for
this pass. The extended evaluation was interrupted by resource exhaustion of
the host, and an uncompleted run must not be reported as coverage. No installer
results are claimed here.

## Synthetic acceptance coverage

`tests/test_emu.py` exercises a report containing:

- `KERNEL32.CreateRemoteThread` and `WriteProcessMemory` → `GB-EMU-001`;
- `KERNEL32.InternetOpenA` → `GB-EMU-003`;
- `KERNEL32.CreateFileA` and `WriteFile` → file/write events;
- `ADVAPI32.RegSetValueExA` → `GB-EMU-002`;
- runtime code segments → `GB-EMU-011`.

This proves the emulation plumbing and classification are wired. It does **not**
prove how often real software reaches those paths.

## What this means for the benchmark

- Process and file attempted behaviour are observed and logged on real benign
  software.
- Registry and network behaviour were not observed in this benign corpus at
  all, so the benchmark proxy is too narrow to validate them.
- `pe` and `other` events are dominated by ordinary startup APIs and are not
  themselves detection evidence.
- Empty API traces (`GB-EMU-000`) distinguish packing/evasion but cannot
  prove intent.

## Gaps and next measurements

1. Benign software that actually opens a network socket or writes an autorun
   key needs to be included, or coverage will remain 0 for those categories.
2. Public installer emulation requires either an isolated/low-memory runner or
   explicit fixture evidence; the current local corpus does not supply it.
3. Real-malicious emulation is outside this pass and requires an isolated lab
   and lawful samples.
4. A network/registry coverage percentage is not reported until representative
   samples exercise those categories.

## How to regenerate this evidence

```bash
# static evaluation
glassbox eval corpus/local-benign --json

# emulation ablation
glassbox eval corpus/local-benign --mode emulation --timeout 8 --json > /tmp/eval-local-benign.json

# class coverage table
python scripts/summarize_emulation_coverage.py /tmp/eval-local-benign.json --markdown
```

No output in this document replaces an isolated real-malicious measurement.
