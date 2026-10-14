# Sn1per MCP Server - developer targets.
.PHONY: help venv test lint build check clean

PYTHON ?= python3
VENV := .venv
PY := $(VENV)/bin/python
PYTEST := $(PY) -m pytest -q -p no:cacheprovider
# The release check reads a clone as a private tree: a never-exported file (P.2) kept
# out of git with .git/info/exclude is noted, not failed. CI runs the strict default;
# to reproduce it locally run `make lint CHECK_FLAGS=`.
CHECK_FLAGS ?= --private-branch

help:
	@echo "venv   - create .venv and install the package with the dev extra"
	@echo "test   - run the test suite (inside a private network namespace when available)"
	@echo "lint   - ruff check and the release consistency check (CHECK_FLAGS= for the CI mode)"
	@echo "build  - build the sdist and wheel, then twine check"
	@echo "check  - lint and test"
	@echo "clean  - remove build and test artifacts"

venv:
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e '.[dev]'

# Same uid, no network interface up. Never `unshare -r`: it maps the tests to
# uid 0 inside the namespace and changes the code paths under test.
test:
	@if unshare --map-current-user --net true 2>/dev/null; then \
		echo "running tests in a private network namespace"; \
		unshare --map-current-user --net $(PYTEST); \
	else \
		$(PYTEST); \
	fi

lint:
	$(PY) -m ruff check src tests scripts
	$(PY) scripts/check_release_consistency.py $(CHECK_FLAGS)

build:
	rm -rf dist
	$(PY) -m build
	$(PY) -m twine check --strict dist/*

check: lint test

clean:
	rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -path ./$(VENV) -prune -o -type d -name __pycache__ -prune -exec rm -rf {} +
