# GlassBox PE

**Offline, evidence-first triage for Windows PE executables.**

GlassBox PE takes a single `.exe`, looks at what it *is* and what it *tries to do*,
and produces a technique-level verdict where every claim is backed by an evidence
event.

> Status: **Phase 1 — static core**. Emulation, unpacking, and HTML reporting are
> planned next. See `docs/PLAN.md`.

## Why

Most student malware detectors output one number. GlassBox PE outputs:

- what the sample can do (static capabilities)
- what it tried to do (emulated behavior, coming in Phase 4)
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

This tool is **offline and non-executing** in its current form. It parses bytes and
extracts strings. It never runs the sample. Emulation (Phase 4) runs code inside a
CPU emulator, not on your host. Do not run real malware outside an isolated
environment.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```bash
# Static triage of one executable
glassbox scan suspicious.exe

# Machine-readable output
glassbox scan suspicious.exe --json

# List and inspect cases
glassbox cases list
glassbox cases show <sha256>

# Re-emit a stored report
glassbox report <sha256> --json
```

Each scan creates a case directory:

```
cases/<sha256>/
  case.json      # events, findings, verdict, hashes
```

## Current commands

| Command | Status |
|---|---|
| `scan` | working (static) |
| `cases list/show/delete` | working |
| `report --json` | working |
| `rules list` | working |
| `unpack` | Phase 3 |
| `emu` | Phase 4 |
| `analyze --deep` | Phase 5 |
| `report --html` | Phase 5 |

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
  score.py        sneakiness + evidence-weighted verdict
  report/         terminal and JSON output
```

## Tests

```bash
.venv/bin/pytest
```

Tests build a synthetic PE fixture in `tests/fixtures/make_pe.py`; no malware is
required.
