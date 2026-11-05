# Real corpus evaluation workflow

This document describes how to evaluate GlassBox against **operator-provided
real malware** without executing anything on a normal host. See also
`docs/ISOLATED_LAB.md` for the full lab procedure and minimum corpus gates.
As of 2026-11-05,
the repository contains no real malware and none has been executed. The
staging tooling is ready; the samples must come from an isolated lab.

## Safety model

- Never run a sample on the analysis host. Speakeasy is user-mode emulation,
  not a hard sandbox. Treat every unknown sample as potentially malicious.
- Acquire and unpack samples in an isolated environment: a disposable VM, a
  sacrificial analysis machine, or a vetted lab share. Disable networking.
- Do not use production credentials, mounted home directories, or synced folders
  in the lab.
- This repository ignores `corpus/` by default. Keep malicious samples under
  `corpus/real-malware/` with directory mode `0700` and files mode `0600`.
- Prefer hashes over original filenames. Original paths are kept only in the
  manifest's provenance field so the source can be audited.
- Before sharing results, decide whether file names and provenance may be
  disclosed. Hash-only reporting is safer externally.

## Legal and provenance requirements

You need lawful access to the samples. Valid sources include an internal
incident-response corpus, licensed malware feeds, and isolated research
repositories. Check their terms. Do not scrape random sites, do not ask others
for unlicensed copies, and do not redistribute samples.

Each staged sample should have a label and, where known, expected ATT&CK
techniques. GlassBox can validate syntax, not ground truth.

## Preparing a source directory

Use one of two layouts:

```text
prepared-samples/
  clean/        optional benign controls
  suspicious/   suspected or low-confidence samples
  malicious/    high-confidence malware
```

Or use a flat directory and pass `--label`. Archives must be unpacked first in
the isolated lab; the staging script does not extract archives and never runs a
sample.

## Staging

```bash
python scripts/stage_real_corpus.py /path/to/prepared-samples \
  --output corpus/real-malware \
  --layout auto \
  --confirm-malware
```

The script:

1. selects `.exe` files only;
2. validates that each file parses as a PE;
3. computes SHA-256 and removes duplicates;
4. copies files with mode `0600` into a directory with mode `0700`;
5. writes `manifest.json` with label, family, techniques, hashes, and
   provenance.

For flat input:

```bash
python scripts/stage_real_corpus.py /path/to/flat-samples \
  --output corpus/real-malware \
  --layout flat --label malicious --confirm-malware
```

If you know expected techniques, pass repeatable `--technique`, for example
`--technique T1055 --technique T1105`. Global values are recorded on every
staged sample; edit the manifest for per-sample technique sets.

## Validate and evaluate

```bash
python scripts/validate_corpus.py corpus/real-malware --require-provenance
python scripts/false_positive_study.py corpus/real-malware
glassbox eval corpus/real-malware --mode static
glassbox eval corpus/real-malware --mode unpack
# only in the isolated lab
python scripts/run_real_corpus_evaluation.py corpus/real-malware \
  --output-dir /secure-output --emulation --timeout 60
```

`validate_corpus.py` checks manifest shape, file presence, non-PE files,
duplicate hashes, and ATT&CK IDs. `false_positive_study.py` slices the static
result by signed / installer / .NET / packer / family, which is the main
false-positive risk area.

## Recommended corpus mix

- 20–30 benign controls: signed and unsigned applications, installers, dev
  tools, and — if available — .NET assemblies. Current extended coverage: 13
  signed and 15 unsigned benign samples, 2 installer hints, 1 .NET assembly.
  More coverage is still desirable.
- 5–8 synthetic malicious fixtures from `make_corpus`, for regression.
- 5–10 high-confidence real malware families, preferably covering injection,
  persistence, network C2, packing, and credential access.
- Packed controls: UPX-packed benign binaries, plus at least one packed
  malicious sample.

## Metrics to report

Use the existing evaluator, and report confidence intervals if you expand the
sample set. At minimum:

- PR-AUC and recall at FPR ≤ 1% on the mixed set;
- per-class precision/recall/F1 and macro-F1;
- per-technique recall;
- Brier and expected calibration error, with the caveat that confidence is not
  a calibrated probability yet;
- false-positive count on signed and unsigned benign controls;
- ablation results: static vs static+unpack vs static+emulation;
- every false positive and every miss, with root cause.

## After evaluation

Remove or quarantine the corpus according to lab policy. Do not commit sample
binaries or the generated `reports/` / `cases/` directories. Publish aggregate
metrics and failure classes, not sample bytes or infrastructure indicators.
