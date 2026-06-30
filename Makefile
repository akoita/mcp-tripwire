# MCP-Tripwire — self-documenting Makefile.
# `make check` is the single pre-PR gate (Hard Rule #8), reused identically in CI.
.DEFAULT_GOAL := help
PYTHON ?= python3
VENV ?= .venv
RUN_PYTHON = $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,$(PYTHON))
.PHONY: help install ensure-dev check lint test test-agent guardrails eval demo demo-proxy demo-proxy-sse demo-adk ci ci-local watchdog-start watchdog-stop watchdog-status watchdog-tick clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install dev dependencies via uv when available, otherwise pip
	@if command -v uv >/dev/null 2>&1; then \
		uv sync --extra dev; \
	else \
		if $(PYTHON) -m ensurepip --version >/dev/null 2>&1; then \
			$(PYTHON) -m venv $(VENV); \
			$(VENV)/bin/python -m pip install -U pip; \
			$(VENV)/bin/python -m pip install -e ".[dev]"; \
		else \
			echo "python venv support is unavailable; install uv or python3-venv"; \
			exit 1; \
		fi; \
	fi

ensure-dev:  ## Bootstrap dev tools so make check works on a fresh Python environment
	@if command -v uv >/dev/null 2>&1; then \
		uv sync --extra dev >/dev/null; \
	else \
		$(PYTHON) -c 'import importlib.util, sys; sys.exit(0 if all(importlib.util.find_spec(p) for p in ("pytest", "ruff")) else 1)' || \
		(if $(PYTHON) -m ensurepip --version >/dev/null 2>&1; then \
			$(PYTHON) -m venv $(VENV) && $(VENV)/bin/python -m pip install -U pip >/dev/null && $(VENV)/bin/python -m pip install -e ".[dev]"; \
		else \
			echo "warning: dev bootstrap skipped; install uv or python3-venv for strict local linting"; \
		fi); \
	fi

check: ensure-dev lint test guardrails  ## THE pre-PR gate: lint + test + guardrails

lint:  ## Lint + format-check with ruff
	@if command -v uv >/dev/null 2>&1; then \
		uv run ruff check . && uv run ruff format --check .; \
	elif $(RUN_PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(RUN_PYTHON) -m ruff check . && $(RUN_PYTHON) -m ruff format --check .; \
	elif $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff check . && $(PYTHON) -m ruff format --check .; \
	else \
		echo "warning: ruff unavailable; skipping local lint (CI installs uv and runs lint strictly)"; \
	fi

test:  ## Run deterministic unit + integration tests
	@if command -v uv >/dev/null 2>&1; then uv run pytest; else $(RUN_PYTHON) -m pytest || $(PYTHON) -m pytest; fi

test-agent:  ## Run optional HTTP/ADK tests with the agent extra installed
	@if command -v uv >/dev/null 2>&1; then PYTHONPATH=src:. uv run --extra dev --extra agent pytest tests/unit/test_agents.py tests/integration/test_http_endpoints.py tests/integration/test_demo_adk_script.py; else PYTHONPATH=src:. $(RUN_PYTHON) -m pytest tests/unit/test_agents.py tests/integration/test_http_endpoints.py tests/integration/test_demo_adk_script.py || PYTHONPATH=src:. $(PYTHON) -m pytest tests/unit/test_agents.py tests/integration/test_http_endpoints.py tests/integration/test_demo_adk_script.py; fi

guardrails:  ## Deterministic enforcement of AGENTS.md hard rules
	@if command -v uv >/dev/null 2>&1; then uv run python scripts/harness_guardrails.py; else $(RUN_PYTHON) scripts/harness_guardrails.py || $(PYTHON) scripts/harness_guardrails.py; fi

eval:  ## Run the attack corpus and report N/M blocked (non-deterministic layer entrypoint)
	@if command -v uv >/dev/null 2>&1; then uv run python -m tripwire.cli ci; else PYTHONPATH=src $(RUN_PYTHON) -m tripwire.cli ci || PYTHONPATH=src $(PYTHON) -m tripwire.cli ci; fi

demo:  ## Run the A/B proof-moment demo (canary secret, local fake sink)
	@if command -v uv >/dev/null 2>&1; then uv run python examples/demo.py; else PYTHONPATH=src $(RUN_PYTHON) examples/demo.py || PYTHONPATH=src $(PYTHON) examples/demo.py; fi

demo-proxy:  ## Same proof moment, end-to-end through the StdioTripwireProxy bridge
	@if command -v uv >/dev/null 2>&1; then uv run python examples/demo_proxy.py; else PYTHONPATH=src $(RUN_PYTHON) examples/demo_proxy.py || PYTHONPATH=src $(PYTHON) examples/demo_proxy.py; fi

demo-adk:  ## ADK multi-agent demo: Scanner / Red-team / Attestor (requires `[agent]` extra)
	@if command -v uv >/dev/null 2>&1; then uv run --extra agent python examples/demo_adk.py; else PYTHONPATH=src $(RUN_PYTHON) examples/demo_adk.py || PYTHONPATH=src $(PYTHON) examples/demo_adk.py; fi

demo-proxy-sse:  ## SSE proxy demo end-to-end: in-process fixture + SseTripwireProxy + three-act proof (requires `[agent]` extra)
	@if command -v uv >/dev/null 2>&1; then PYTHONPATH=src:. uv run --extra agent python examples/demo_proxy_sse.py; else PYTHONPATH=src:. $(RUN_PYTHON) examples/demo_proxy_sse.py || PYTHONPATH=src:. $(PYTHON) examples/demo_proxy_sse.py; fi

ci-local:  ## Full local mirror of CI (lint+test+guardrails + bandit + dogfood + pip-audit)
	@bash scripts/ci-local.sh

watchdog-start:  ## Start the pr-watchdog daemon in the background (polls open PRs)
	@bash scripts/pr-watchdog.sh start

watchdog-stop:  ## Stop the pr-watchdog daemon
	@bash scripts/pr-watchdog.sh stop

watchdog-status:  ## Show pr-watchdog daemon status + seen-PRs ledger
	@bash scripts/pr-watchdog.sh status

watchdog-tick:  ## Run one watchdog poll in the foreground (no loop)
	@bash scripts/pr-watchdog.sh tick

clean:  ## Remove caches and eval artifacts
	rm -rf .pytest_cache .ruff_cache **/__pycache__ artifacts/traces/* artifacts/grade_results/* 2>/dev/null || true
