.PHONY: help install dev-install format lint type-check test test-cov clean pre-commit-install pre-commit-run

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev-install: ## Install package with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

format: ## Format code with ruff
	ruff format src tests
	ruff check --fix src tests

lint: ## Run linting checks
	ruff check src tests
	ruff format --check src tests

type-check: ## Run type checking with mypy
	mypy src/harombe

test: ## Run tests
	pytest

test-cov: ## Run tests with coverage report
	pytest --cov=harombe --cov-report=term-missing --cov-report=html

clean: ## Clean up generated files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

pre-commit-install: ## Install pre-commit hooks
	pre-commit install

pre-commit-run: ## Run pre-commit hooks on all files
	pre-commit run --all-files

ci: lint type-check test ## Run all CI checks
