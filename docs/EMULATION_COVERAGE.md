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

## Public installer corpus

A separate sequential coverage run completed for 4/5 installers. `nuget.exe`
failed to produce a Speakeasy report.

| Set | Result |
|---|---|
| x86/x64 samples | 4/5 ran in emulation |
| ARM64 samples | none |
| API events | 269 |
| Samples with API events | 4/4 x86/x64 |
| Samples with `file` events | 1 |
| Samples with `process` events | 4 |
| Samples with `pe` events | 4 |
| Samples with `other` events | 4 |
| Samples with `network` events | 0 |
| Samples with `registry` events | 0 |
| Attempted behaviour counts | `dynamic_loading` 33, `file` 2 |

## Five-candidate emulation pass

A focused pass over five selected samples with static network/registry APIs found
no attempted network or registry events in emulation. All five ran, but only the
Python installer reached file APIs.

| sample | ran | API calls | categories | behaviours |
|---|---|---:|---|---|
| 7-Zip 26.05 | yes | 19 | other, pe, process | dynamic_loading:1 |
| Inno Setup 7.1.1 | yes | 12 | other, pe, process | dynamic_loading:4 |
| Notepad++ 8.9.8.1 | yes | 55 | other, pe, process | dynamic_loading:14 |
| Python 3.14.10 | yes | 183 | file, other, pe, process | dynamic_loading:14, file:2 |
| wxc-exec | yes | 36 | other, pe, process | dynamic_loading:7 |

Static analysis shows network/registry APIs in these samples, but their
startup paths do not exercise those code paths in Speakeasy. This is a corpus
and workload limitation, not proof that GlassBox can detect attempted
network/registry behaviour in general.

## Combined benign/installer coverage

This table covers the 23-sample local benign corpus and the five public
installer binaries. The five-candidate pass above is a separate focused check.

| Set | Result |
|---|---|
| x86/x64 samples | 23/28 ran in emulation |
| ARM64 samples | 4/28 rejected by the backend (expected) |
| API events | 1,796 |
| Samples with `file` events | 9 |
| Samples with `process` events | 16 |
| Samples with `pe` events | 23 |
| Samples with `other` events | 23 |
| Samples with `network` events | 0 |
| Samples with `registry` events | 0 |
| Dropped files | 0 |
| Dynamic code segments | 0 |
| Attempted behaviour counts | `dynamic_loading` 106, `file` 10 |
| Failed emulations | 5 (4 ARM64 + nuget) |

## Synthetic acceptance coverage

`tests/fixtures/speakeasy_reports.py` contains a synthetic Speakeasy report
that exercises the full attempted-behaviour surface:

- process injection → `GB-EMU-001`;
- registry persistence → `GB-EMU-002`;
- network communication → `GB-EMU-003`;
- file writes → `GB-EMU-006`;
- attempted registry query → `GB-EMU-012`;
- runtime code segments → `GB-EMU-011`;
- keylogging and screen capture → `GB-EMU-008` and `GB-EMU-009`;
- dropped files → `GB-EMU-010`.

Lowest-value attempted findings are deliberately suppressed when static
analysis already established the same capability (for example execution,
runtime loading, anti-analysis). The fixture test checks that higher-value or
new signals remain, that file/network/registry resources are recorded, and
that an unclassified startup API maps to `other`.

It also checks that file, network, and registry resources are resolved from
image-backed pointers and that the no-API-trace finding carries ATT&CK
markers.

A runtime support probe using a tiny synthetic PE that calls `InternetOpenA`
and `RegSetValueExA` logged `InternetOpenA` as attempted network behaviour.
That Speakeasy build produced no registry API events for `RegSetValueExA`;
instead it returned a report with zero API calls. Registry category behaviour
is therefore parser- and fixture-validated in this project, not dynamically
validated by real-world Speakeasy behaviour.

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
2. Registry attempted runtime coverage depends on Speakeasy support for those
  APIs; current evidence is parser/fixture-validated, not runtime-validated.
3. Public installer emulation requires either an isolated/low-memory runner or
   explicit fixture evidence; the current local corpus does not supply it.
4. Real-malicious emulation is outside this pass and requires an isolated lab
   and lawful samples.
5. A network/registry coverage percentage is not reported until representative
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
