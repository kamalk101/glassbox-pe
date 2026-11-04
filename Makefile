.PHONY: install test sample demo clean

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

demo: sample
	-$(GLASSBOX) scan $(SAMPLE) --cases-dir $(CASES) --force

clean:
	rm -rf cases .pytest_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
