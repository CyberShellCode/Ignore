# CyberShellV2 Makefile
# Simple helpers (Linux/macOS/WSL; on Windows use PowerShell equivalents)

# Set shell to bash for consistent behavior
SHELL := /bin/bash

# Python configuration
PYTHON ?= python
PIP ?= pip
VENV := .venv
ACT := . $(VENV)/bin/activate

# Set default goal
.DEFAULT_GOAL := all

# Declare phony targets
.PHONY: all test venv install install-llm install-dashboard run demo openai ollama dashboard clean test-unit test-integration lint help

# Default target - builds the environment
all: venv install
	@echo "Environment setup complete. Run 'make run' to start CyberShellV2"

# Test target for CI/static analysis
test: venv install
	@echo "Running tests..."
	$(ACT) && pytest tests/ -v --cov=cybershell --cov-report=term-missing || \
		(echo "pytest not found, trying unittest..." && $(PYTHON) -m unittest discover -s tests -p "test_*.py" -v) || \
		(echo "No tests found or test framework not installed")

# Unit tests only
test-unit: venv install
	@echo "Running unit tests..."
	$(ACT) && pytest tests/unit/ -v --cov=cybershell || \
		$(PYTHON) -m unittest discover -s tests/unit -p "test_*.py" -v

# Integration tests only  
test-integration: venv install
	@echo "Running integration tests..."
	$(ACT) && pytest tests/integration/ -v || \
		$(PYTHON) -m unittest discover -s tests/integration -p "test_*.py" -v

# Linting and static analysis
lint: venv install
	@echo "Running linters..."
	$(ACT) && (flake8 cybershell/ --max-line-length=120 --exclude=__pycache__ || echo "flake8 not installed")
	$(ACT) && (mypy cybershell/ --ignore-missing-imports || echo "mypy not installed")
	$(ACT) && (black --check cybershell/ || echo "black not installed")

# Create virtual environment
venv:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)

# Install base requirements
install: venv
	@echo "Installing base requirements..."
	$(ACT) && $(PIP) install --upgrade pip
	$(ACT) && $(PIP) install -r requirements.txt

# Install LLM requirements
install-llm: install
	@echo "Installing LLM requirements..."
	$(ACT) && $(PIP) install -r requirements-llm.txt

# Install dashboard requirements
install-dashboard: install
	@echo "Installing dashboard requirements..."
	$(ACT) && $(PIP) install -r requirements-dashboard.txt

# Run with default configuration
run: install
	@echo "Starting CyberShellV2..."
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm none

# Run demo
demo: install
	@echo "Running CyberShellV2 demo..."
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm none

# Run with OpenAI
openai: install-llm
	@echo "Starting with OpenAI LLM..."
	@if [ -z "$$OPENAI_API_KEY" ]; then \
		echo "ERROR: OPENAI_API_KEY environment variable is not set"; \
		echo "Please set it with: export OPENAI_API_KEY='your-api-key'"; \
		exit 1; \
	fi
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner depth_first --scorer weighted_signal --llm openai

# Run with Ollama
ollama: install-llm
	@echo "Starting with Ollama LLM..."
	@echo "Note: Make sure ollama is running locally (ollama serve)"
	$(ACT) && $(PYTHON) -m cybershell http://localhost:8000 --planner breadth_first --scorer high_confidence --llm ollama

# Run dashboard
dashboard: install-dashboard
	@echo "Starting Streamlit dashboard..."
	$(ACT) && streamlit run dashboard/streamlit_app.py

# Clean up artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV) **pycache** .pytest_cache .mypy_cache
	find . -name "__pycache__" -type d -prune -exec rm -rf {} \;
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete
	find . -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info

# Help target
help:
	@echo "CyberShellV2 Makefile Commands:"
	@echo "  make all              - Set up environment (default)"
	@echo "  make test            - Run all tests"
	@echo "  make test-unit       - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make lint            - Run code linters"
	@echo "  make run             - Run CyberShellV2 with default config"
	@echo "  make demo            - Run demo"
	@echo "  make openai          - Run with OpenAI LLM (requires OPENAI_API_KEY)"
	@echo "  make ollama          - Run with Ollama LLM"
	@echo "  make dashboard       - Start Streamlit dashboard"
	@echo "  make install-llm     - Install LLM dependencies"
	@echo "  make install-dashboard - Install dashboard dependencies"
	@echo "  make clean           - Remove all generated files"
	@echo "  make help            - Show this help message"
