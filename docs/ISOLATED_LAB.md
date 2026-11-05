# Isolated real-corpus laboratory protocol

This is the required procedure for moving from benchmark fixtures to
real-world evaluation. It is deliberately strict because malicious executables
are hazardous. It documents the division of responsibility between an isolated
lab and the analysis host.

GlassBox itself never executes a sample natively. That does not make a normal
Linux host safe: parsing vulnerabilities, accidentally invoked files, and
downstream tooling can still run the code or expose sensitive data.

## Required environment

One of the following, with no shared folders and no networking:

1. A throwaway Windows/Linux virtual machine with a clean snapshot; or
2. A dedicated, networkless analysis machine; or
3. A licensed lab share that your organization controls.

The lab should include:

- a disposable operating system or offline snapshot;
- no browser, credentials, source-code repository, or business files;
- a read-only acquisition share;
- a clean output share for evaluation results;
- an AV/EDR environment policy if the lab is used in an organization;
- a restore/wipe procedure documented in advance.

If this is not available, do not download live malware. Use local benign
controls or ask for the samples.

## Lawful acquisition

Acceptable sources:

- your organization's incident-response corpus;
- licensed malware feeds and their terms;
- samples already quarantined by a security team;
- public feeds whose licence explicitly permits local research.

Unacceptable:

- downloading samples from random sites;
- redistributing samples;
- using stolen credentials or bypassing access controls;
- temporarily enabling network access to "see what it does";
- claiming a sample is safe because it is open source.

Record for every sample:

```text
SHA-256, family (or unknown), label, source, provenance,
TTP/ATT&CK techniques, unpacking status, notes
```

Do not share exact file names in public reports unless required; hashes and
families are usually sufficient.

## Incident-response sequence

### 1. Prepare the lab

- Take a snapshot before touching samples.
- Disconnect network interfaces or disable virtual NICs.
- Mount the transfer share read-only in the lab.
- Do not mount the lab home directory onto the evaluation host until files
  have been staged.

### 2. Stage the files

Copy high-confidence samples into a directory laid out as:

```text
prepared-samples/
  clean/
  suspicious/
  malicious/
```

Then stage the corpus on an offline machine:

```bash
python scripts/stage_real_corpus.py /path/to/prepared-samples \
  --output corpus/real-malware \
  --layout auto \
  --confirm-malware
```

The script copies PE files, validates PE parsing, hashes with SHA-256,
deduplicates, writes `manifest.json`, and sets mode `0600` under a `0700`
directory. It never executes a sample.

For flat directories, use:

```bash
python scripts/stage_real_corpus.py /path/to/flat-samples \
  --output corpus/real-malware \
  --layout flat --label malicious --confirm-malware
```

### 3. Validate the corpus

```bash
python scripts/validate_corpus.py corpus/real-malware
```

The validator checks:

- required manifest fields;
- valid labels and ATT&CK IDs;
- every file exists and parses as PE;
- declared SHA-256 matches;
- duplicates by SHA-256 and imphash;
- provenance for non-clean samples;
- permissions and family skew warnings;
- installer / .NET / signature / packer coverage.

Require provenance for any serious measurement:

```bash
python scripts/validate_corpus.py corpus/real-malware --require-provenance
```

Exit status is nonzero when validation fails.

### 4. Run the complete measurement

```bash
# Static + UPX unpack ablation
python scripts/run_real_corpus_evaluation.py corpus/real-malware \
  --output-dir /secure-locations/real-report \
  --require-provenance

# Optional, only inside the isolated lab:
python scripts/run_real_corpus_evaluation.py corpus/real-malware \
  --output-dir /secure-locations/real-report \
  --require-provenance --emulation --timeout 60
```

The runner:

1. runs the validator;
2. aborts if real problems are found;
3. evaluates static and UPX-unpack paths;
4. optionally runs Speakeasy emulation;
5. writes `MEASUREMENT.md`, `validation.json`, and JSON evaluation artifacts;
6. lists static false positives and false negatives with findings and scores;
7. never calls any sample as a process.

UPX unpacking is safe in the sense that the unpacker does not execute the
sample, but it still may process malformed bytes; run it in the lab.

### 5. Inspect and act

Review:

- every false positive and false negative;
- signed vs unsigned and .NET effects;
- packed/unpacked child results;
- emulation errors and no-API-event reports;
- manifest and provenance issues;
- `imphash` clusters that make the corpus look broader than it is.

Do not tweak rules merely to improve the reported score. Record the failure,
then fix it and re-measure on a held-out sample set. Otherwise the benchmark
passes but the product learned nothing.

### 6. Wipe or retain according to policy

- If the lab is disposable, restore the snapshot.
- If retained, keep files mode `0600` and directory mode `0700`.
- Do not copy the corpus to any shared host, cloud service, or personal device.
- Do not commit sample binaries or reports containing unrestricted file names.

## Minimum useful corpus

Before publishing a number, require at least:

- 20 clean benign controls;
- 5 synthetic controls for regression;
- 5 distinct real malicious families;
- 2 packed malicious samples;
- at least 5 unsigned and 5 signed benign controls;
- at least one .NET benign and one .NET malicious or suspicious sample;
- provenance for every non-clean sample.

The synthetic corpus is acceptable for regression but not for a real-world
claim. The public benign installer corpus included in this repository is
useful as a false-positive floor, not as a substitute for representative
benign software.

## What the measurement means

GlassBox output is a triage score, not a probability. Use the runner to
measure:

- static vs static+unpack vs static+emulation;
- false positives per benign family;
- missed techniques and missed families;
- whether emulation adds useful evidence or only noise.

If emulation fails on the corpus, report that as a result; do not silently
fall back to static-only claims.

## Output handling

Keep `reports/` and `corpus/` outside git. In public documentation, publish
aggregate metrics and failure classes only. Remove paths and proprietary file
names from reports before external sharing.
