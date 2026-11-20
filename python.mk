# SPDX-License-Identifier: MIT
# The Python SDK's targets, included by the Makefile.

# The Python SDK (sdk/python) is built and checked with the Python of the
# environment, which needs its dev extra: pip install -e "sdk/python[dev]"
PYTHON ?= python3

.PHONY: py-lint
py-lint: ## check the Python SDK: ruff, ruff format, mypy --strict (needs sdk/python[dev])
	@cd sdk/python && $(PYTHON) -m ruff check . && $(PYTHON) -m ruff format --check . && $(PYTHON) -m mypy

.PHONY: py-test
py-test: ## run the Python SDK's tests (needs sdk/python[dev])
	@cd sdk/python && $(PYTHON) -m pytest

.PHONY: py-build
py-build: ## build the Python SDK's wheel and sdist into build/python (version from the git tag)
	@rm -rf build/python
	@$(PYTHON) -m build --outdir build/python sdk/python
