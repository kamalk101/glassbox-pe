# GlassBox PE

**Offline, evidence-first triage for Windows PE executables.**

GlassBox PE takes a single `.exe`, looks at what it *is* and what it *tries to do*,
and produces a technique-level verdict where every claim is backed by an evidence
event.

> Status: **static core + basic Speakeasy emulation + UPX unpacking**.
> HTML reporting and deeper correlation are next. See `docs/PLAN.md`.

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
```

`unpack` detects UPX, ASPack, MPRESS, Themida, VMProtect, Enigma, Petite, and
NsPack by section names/markers, plus a high-entropy/low-import heuristic. UPX
is unpacked automatically; other packers are reported as unsupported. The
unpacked child gets its own case, a before/after diff (sections, imports,
findings, score), and a `GB-UNP-001` finding when hidden capabilities appear.

Each scan creates a case directory:

```
cases/<sha256>/
  case.json                       # events, findings, verdict, hashes
  emulation/speakeasy-report.json # raw emulator report (after `emu`)
  emulation/dropped/              # files written during emulation
  unpacked/                       # unpacked child binary (after `unpack`)
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
| `unpack` | working (UPX only; detects other packers) |
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
    packer.py     packer detection (UPX and common packers)
    rules.py      detection rules -> findings
  unpack/
    service.py    detect -> choose unpacker -> validate output
    upx.py        UPX discovery and subprocess invocation
    diff.py       packed vs unpacked child comparison
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
- Only UPX unpacking is implemented; other packers are detected and marked
  unsupported. Child payloads are analyzed one level deep, not recursively.
- HTML reports and full correlation are not implemented yet.
