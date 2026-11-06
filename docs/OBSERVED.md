# Phase 9: observed VM backend

This document describes the **observed** backend, not a complete Windows sandbox.

## Goal

Give GlassBox PE an optional Windows VM step that records behavior and links it
to the same evidence graph used by static and emulated analysis.

## Components

- `scripts/Invoke-ObservedSample.ps1` — guest-side runner/collector.
- `scripts/Install-Sysmon.ps1` — optional Sysmon setup script.
- `glassbox observed ingest` — imports a report into an existing case.
- `glassbox/observed.py` — validation and conversion of observed JSON into
  GlassBox events.

## Host-side validation

```bash
glassbox observed ingest --sample /path/to/sample.exe \
  --report /path/to/observed-report.json \
  --cases-dir cases
```

The sample is parsed statically; it is never executed on the Linux host.

## Report schema

Expected JSON:

```json
{
  "sample": {"sha256": "...", "file_name": "..."},
  "environment": {"vm_name": "tiny", "isolated": true, "os": "Windows 10"},
  "started_at": "2026-11-06T00:00:00+00:00",
  "ended_at": "2026-11-06T00:00:01+00:00",
  "events": [
    {"action": "process_start", "category": "process", "target": "sample.exe"}
  ],
  "dropped_files": []
}
```

GlassBox maps events to `Source.VM` and `Strength.OBSERVED`.

## What is proven and what is not

Proven:

- host-side import and validation work;
- case evidence graph can include observed events;
- static and observed evidence can be correlated;
- HTML report can render the observed evidence section.

Not yet proven:

- generic collection on every Windows 10/11 configuration;
- complete coverage of process/file/network/registry telemetry;
- malware behavior on an uncontrolled sample;
- universal isolation without a dedicated VM.

## Windows lab requirements

- dedicated VM;
- snapshot before use;
- no shared folders;
- no credentials or browser data;
- network disabled or sink-holed;
- Sysmon or equivalent telemetry installed;
- only explicitly selected samples are run.

## Limitations

- The VM is not a magic sandbox.
- Packed or anti-VM samples can avoid meaningful observed activity.
- Network telemetry may require Sysmon and guest configuration.
- Observed behavior is evidence, not proof of malice.
- The `tiny` VM may have an isolated user account that blocks Guest Control.

## Current status

Host-side tooling, validation, ingestion, reports, and UI integration are
implemented. The full Phase 9 proof still requires a Windows lab VM and a safe
sample that actually performs observable activity. That particular execution
requires a VM configuration and credentials permitted by the user.
