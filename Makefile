.PHONY: install test sample demo upx corpus eval dashboard clean

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

dashboard:
	$(GLASSBOX) dashboard --reports

clean:
	rm -rf cases reports corpus .pytest_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
