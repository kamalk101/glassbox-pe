# GlassBox observed Windows agent

This directory contains the guest-side collector used by Phase 9.

## Purpose

- run a selected PE in an isolated Windows lab;
- collect process tree, file, registry, and network telemetry;
- export a bounded JSON report for GlassBox;
- never transmit data outside the VM.

## Current approach

- `Invoke-ObservedSample.ps1` launches a selected process and waits for it;
- `Export-ObservedReport.ps1` exports a compact report for the requested time window;
- results are copied to the host and imported with `glassbox observe --report ...`.

## Required VM state

- dedicated, clean snapshot;
- no shared folders;
- network disabled or isolated;
- Sysmon installed and configured for the event categories above;
- local administrator access for setup.
