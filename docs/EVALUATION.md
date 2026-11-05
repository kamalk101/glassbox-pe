# GlassBox PE — Evaluation

Date: 2026-11-05 · scope: static, UPX unpack, and Speakeasy emulation

No real malware has been evaluated or executed. This document records the
current evidence, the corpus mix, and the known failures. Treat the results as
engineering measurements, not a benchmark of real-world detection quality.

## Current measurements

| Set | N | Result |
|---|---|---|
| Synthetic demo set (`corpus/demo`, 2 clean, 3 suspicious, 5 synthetic malicious) | 10 | 90% accuracy; binary precision 100%, recall 87.5%, F1 0.933; PR-AUC 0.975; recall at FPR ≤ 1% = 87.5% at score ≥ 0.25; technique recall 96% (24/25). One false negative: `evasive-timing-only.exe`. Zero static false positives on synthetic clean fixtures. |
| Real local benign corpus (`corpus/local-benign`: trusted Windows PEs from installed VS Code and Python launcher packages) | 23 | 0 false positives, 23/23 clean. PR-AUC / recall@FPR are undefined because the set contains no positives. After a 20-point Authenticode-presence mitigation, previously flagged Microsoft/VS Code tools are clean. |
| Public benign installers (`corpus/benign-installers`: official pinned 7-Zip, Inno Setup, Python, Notepad++, NuGet) | 5 | 0 false positives, 5/5 clean. Detects two installer hints (`NSIS`, `Inno Setup`) and one .NET assembly. |
| Extended mixed set (`corpus/mixed-extended`: 28 clean + 3 suspicious + 5 synthetic malicious) | 36 | 97.2% accuracy; binary precision 100%, recall 87.5%, F1 0.933; PR-AUC 0.903; recall at FPR ≤ 1% = 87.5% at score ≥ 0.25; technique recall 96% (24/25). Only false negative: `evasive-timing-only.exe`. |
| Mixed set (`corpus/mixed`: 23 real benign + 8 synthetic suspicious/malicious) | 31 | 96.8% accuracy; binary precision 100%, recall 87.5%, F1 0.933; PR-AUC 0.907; recall at FPR ≤ 1% = 87.5% at score ≥ 0.25; technique recall 96% (24/25). Only false negative: `evasive-timing-only.exe`. |
| UPX unpack ablation (`corpus/upx-benign`: real UPX-packed 7-Zip extractor) | 1 | Raw static verdict: suspicious (31). After `--mode unpack`: child score 15, predicted clean. Unpack resolves the packed-stub false positive. |
| Emulation validation (`glassbox eval corpus/local-benign --mode emulation`) | 23 | 19/23 ran; 4/23 ARM64 samples rejected before emulation (expected). 1,527 API events; attempted categories seen in this benign set: `pe`, `other`, `process` (12), `file` (8). No `network` or `registry` behaviour was observed in this set. |

Calibration, which is heuristic only: Brier 0.117 and ECE 0.207 on the synthetic
set; Brier 0.232 and ECE 0.377 on the mixed set. These numbers should not be
used to claim probability calibration until a real malicious corpus exists.

False-positive slices on the extended mixed set (`make fp-study` against
`corpus/mixed-extended`): signed benign 0/13, unsigned benign 0/15, installer
hints 0/2, .NET 0/1; non-clean synthetic detected 7/8 — the one miss is
`evasive-timing-only.exe`. Installer and .NET coverage remains tiny (2 and 1
samples), so it is a smoke check, not a comprehensive false-positive study.
Use `docs/REAL_CORPUS.md` to expand them in an isolated lab.

## What the corpora are — and are not

- `corpus/local-benign` is **real** Windows PE software (Microsoft/VS Code
  component binaries and Python distlib launchers), collected by
  `scripts/make_local_benign_corpus.py`, deduplicated by SHA-256, and labelled
  `clean` with the source path in the manifest for audit. It is not a
  representative benign benchmark; it over-represents one vendor and one kind of
  tool.
- `corpus/demo` is synthetic and rule-aligned enough to regression-test changes.
  It is honestly expected to detect almost everything it was designed for.
- `corpus/mixed` combines the above; it gives a nonzero positive rate but does
  **not** contain real malware.
- Real malicious samples must be obtained and handled only in an isolated
  environment; they are deliberately not included.

## Failure and limitation log

1. **`evasive-timing-only.exe`** (T1497.001) is classified clean. Timing-only
   anti-analysis (Sleep / GetTickCount / QueryPerformanceCounter) is too common
   in ordinary software; it is treated as non-suspicious unless strong debugger
   or environment checks are present. This is a known false negative.
2. **ARM64 samples are not emulated** (`Speakeasy backend does not support ARM64
   samples`). The evaluator records them as explicit errors rather than silent
   passes.
3. **Non-UPX packers** are detected but not unpacked; they stay `unsupported`.
   Static-only triage of those samples remains weak.
4. **.NET assemblies** are parsed only at the native PE level; managed IL is not
   analyzed.
5. **Emulation coverage is uneven.** In the 23-sample benign set it reached
   `process`/`file` categories only; no `network` or `registry` behaviour was
   observed. The pipeline logs those categories when present, but this set does
   not validate them.
6. **Authenticode mitigation is presence-only.** A signature subtracts 20 points,
   but GlassBox does not validate the chain, revocation, or Microsoft
   attestation. A stolen-signed malicious binary can still pass as "signed".
   Mitigations are listed under `verdict.mitigations`.
7. **Packed-stub bias.** Raw static mode flags real UPX-packed benign software;
   the unpack ablation corrects it by analysing the child image. Static-only
   users should still treat a packed verdict as "unpack required".
8. **Installer false positive.** The public 7-Zip installer was initially
   flagged suspicious because any registry-write capability was a medium
   finding. The rule is now low severity; `GB-REG-001` still covers autorun
   keys specifically.
9. **.NET indicator bug.** `is_dotnet` relied on `DIRECTORY_ENTRY_COM_DESCRIPTOR`
   and missed CLR-header assemblies; it now inspects the CLR data directory.
10. **Locale and version bytes produce IOC noise.** Version strings like
   `1.0.0.0` are still extracted as addresses; rule tuning reduced their
   impact but they have not been eliminated.
11. **No real-malware PR-AUC exists yet.** The recall at FPR ≤ 1% figure comes
    from the mixed set; it does not measure real-world malware detection.

## How to reproduce

```bash
python scripts/validate_corpus.py corpus/mixed-extended
python scripts/false_positive_study.py corpus/mixed-extended --format markdown
# Synthetic regression / demo
make corpus && make eval

# Real local benign corpus (trusted installed software; no downloads)
make corpus-benign
.venv/bin/glassbox eval corpus/local-benign
.venv/bin/glassbox eval corpus/local-benign --mode emulation --timeout 8

# Mixed measurement
make corpus-mixed && .venv/bin/glassbox eval corpus/mixed

# Extended measurement (local benign + public installers + synthetic malicious)
make bench-extended

# UPX ablation — pack a trusted benign PE yourself
make upx-corpus SRC=/path/to/benign.exe && make eval-unpack
```

## Next evaluation steps

- Add a real malicious corpus in an isolated environment and re-measure.
- Expand the installer/.NET controls and add more signed and unsigned
  samples; one .NET assembly is not a .NET analysis strategy.
- Add managed-IL analysis for .NET payloads.
- Add packed real-malware and non-UPX packed samples to exercise the unpacker.
- Replace the single `GB-EMU-000` anti-emulation signal with richer handling of
  timeouts and no-API-event reports.
