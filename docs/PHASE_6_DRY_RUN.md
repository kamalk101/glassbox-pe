# Phase 6 dry-run report

This document records a synthetic-fixture dry run of the real-corpus workflow.
It is not a real-malicious measurement and must not be interpreted as evidence
of real-world detection quality.

## Purpose

The real-corpus runner already accepts a validated manifest, then:

1. validates hashes, PE parsing, duplicate detection, and file permissions;
2. runs static analysis;
3. runs the UPX unpack ablation;
4. optionally runs Speakeasy emulation;
5. writes `MEASUREMENT.md` and machine-readable JSON artifacts;
6. never executes a sample natively.

The dry run exercises that full path.

## Dry-run environment

- Corpus: `corpus/demo`
- Samples: 10 synthetic PE fixtures
- Emulation: enabled with Speakeasy
- UPX: one synthetic packed fixture
- Real malicious samples: none
- Output directory: `/tmp/opencode/phase6-dry-run`

## Result

Static and unpack paths both reported:

- samples evaluated: 10
- 3-class accuracy: 90.0%
- binary precision/recall/F1: 1.0 / 0.875 / 0.9333
- PR-AUC: 0.975
- recall at FPR <= 1%: 0.875 at score >= 0.25
- false positives: 0
- false negatives: 1
- technique recall: 96% (24/25)

Emulation path reported:

- ran: 10/10
- failed: 0
- API calls: 0
- samples with API events: 0
- calibration: Brier 0.0999, ECE 0.168

One synthetic misprediction:

- `evasive-timing-only.exe` actual `suspicious`, predicted `clean`, score 0; findings `GB-PE-008`.

The synthetic corpus is constructed so most fixtures are expected to be
detected. Its metrics validate the pipeline, not its ability to detect real
malware.

## What is missing for completion

Phase 6 cannot be completed without an isolated, authorized malicious corpus:

- lawful sample source;
- isolated Linux or Windows VM;
- provenance for every sample;
- read-only staging if possible;
- no live network access;
- report output kept separate from sample files.

When those are supplied, run:

```bash
python scripts/stage_real_corpus.py /path/to/prepared-samples \
  --output corpus/real-malware \
  --layout auto \
  --confirm-malware
python scripts/validate_corpus.py corpus/real-malware --require-provenance
python scripts/run_real_corpus_evaluation.py corpus/real-malware \
  --output-dir /secure-report \
  --require-provenance \
  --emulation --timeout 60
```

## Interpretation

- The evaluation harness is built and exercised end-to-end.
- The pipeline does not need a Windows desktop, but it does need a proper isolated lab for real samples.
- The results above do not substitute for real-world measurement.
