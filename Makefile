.PHONY: install test sample demo upx corpus eval bench corpus-benign corpus-mixed eval-emulation upx-corpus eval-unpack dashboard clean

PY := .venv/bin/python
PIP := .venv/bin/pip
GLASSBOX := .venv/bin/glassbox
SAMPLE := /tmp/opencode/glassbox-sample.exe
CASES := /tmp/opencode/glassbox-cases

install:
	python3 -m venv .venv
	$(PIP) install -e ".[dev,emu]"

test:
	$(PY) -m pytest

sample:
	mkdir -p /tmp/opencode
	$(PY) tests/fixtures/make_pe.py $(SAMPLE) --packed

demo:
	sh scripts/demo.sh

upx:
	sh scripts/fetch_upx.sh

corpus:
	$(PY) scripts/make_corpus.py

eval: corpus
	$(GLASSBOX) eval corpus/demo

corpus-benign:
	$(PY) scripts/make_local_benign_corpus.py --clean

corpus-mixed: corpus corpus-benign
	$(PY) scripts/make_mixed_corpus.py

bench: corpus-mixed
	$(GLASSBOX) eval corpus/mixed

eval-emulation: corpus-benign
	$(GLASSBOX) eval corpus/local-benign --mode emulation --timeout 8

upx-corpus:
	@if [ -z "$(SRC)" ]; then \
		echo "usage: make upx-corpus SRC=/path/to/benign.exe" >&2; exit 1; \
	fi
	$(PY) scripts/make_upx_corpus.py --clean --source "$(SRC)"

eval-unpack:
	$(GLASSBOX) eval corpus/upx-benign --mode unpack

dashboard:
	$(GLASSBOX) dashboard --reports

clean:
	rm -rf cases reports corpus .pytest_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
