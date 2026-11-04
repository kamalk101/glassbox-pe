# GlassBox PE

**Offline, evidence-first triage for Windows PE executables.**

GlassBox PE takes a single `.exe`, looks at what it *is* and what it *tries to do*,
and produces a technique-level verdict where every claim is backed by an evidence
event.

> Status: **static core + basic Speakeasy emulation**. Unpacking and HTML
> reporting are next. See `docs/PLAN.md`.

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

## Usage

```bash
# Static triage only (fast, safe)
glassbox scan suspicious.exe

# Static + emulation
glassbox emu suspicious.exe --timeout 60
glassbox analyze suspicious.exe --timeout 60

# Machine-readable output
glassbox scan suspicious.exe --json
glassbox emu suspicious.exe --json

# List and inspect cases
glassbox cases list
glassbox cases show <sha256>

# Re-emit a stored report
glassbox report <sha256> --json
```

Each scan creates a case directory:

```
cases/<sha256>/
  case.json                       # events, findings, verdict, hashes
  emulation/speakeasy-report.json # raw emulator report (after `emu`)
  emulation/dropped/              # files written during emulation
```

## Current commands

| Command | Status |
|---|---|
| `scan` | working (static) |
| `emu` | working (Speakeasy: API events, dropped files, behaviour findings) |
| `analyze` | working (static + emulation) |
| `cases list/show/delete` | working |
| `report --json` | working |
| `rules list/test` | working |
| `unpack` | Phase 3 |
| `report --html` | Phase 5 |

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
    rules.py      detection rules -> findings
  emu/
    speakeasy_backend.py  subprocess runner + report/dropped-file capture
    apply.py              report -> attempted events + findings
  score.py        sneakiness + evidence-weighted verdict
  report/         terminal and JSON output
```

## Tests

```bash
.venv/bin/pytest
```

Tests build a synthetic PE fixture in `tests/fixtures/make_pe.py`; no malware is
required. Emulation tests are skipped if Speakeasy is not installed.

## Current limitations

- Emulated API arguments are logged, but pointers are not yet resolved to strings.
- Child processes are not truly executed; dropped files are captured and queued.
- Emulation can be evaded by anti-analysis samples (`GB-EMU-000` flags this).
- Generic unpacking and HTML reports are not implemented yet.
