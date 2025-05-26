# Makefile for Password Cracker project

.PHONY: help test test-unit test-integration test-security test-performance test-all coverage clean install lint format check

# Default target
help:
	@echo "Password Cracker - Make targets:"
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-security     - Run security tests only"
	@echo "  make test-performance  - Run performance tests only"
	@echo "  make test-all          - Run all tests including slow ones"
	@echo "  make coverage          - Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run linting checks"
	@echo "  make format            - Format code"
	@echo "  make check             - Run all checks (lint + tests)"
	@echo ""
	@echo "Setup:"
	@echo "  make install           - Install dependencies"
	@echo "  make install-dev       - Install development dependencies"
	@echo "  make clean             - Clean up generated files"

# Install dependencies
install:
	pip install -r requirements.txt

install-dev: install
	pip install pytest pytest-cov pytest-xdist pytest-timeout
	pip install black flake8 mypy isort
	pip install safety bandit

# Run all tests
test:
	python tests/run_tests.py

# Run specific test categories
test-unit:
	python tests/run_tests.py --unit

test-integration:
	python tests/run_tests.py --integration

test-security:
	python tests/run_tests.py --security

test-performance:
	python tests/run_tests.py --performance

# Run all tests including slow ones
test-all:
	python tests/run_tests.py --slow

# Run tests with coverage
coverage:
	python tests/run_tests.py --coverage
	@echo "Coverage report generated in htmlcov/index.html"

# Code quality checks
lint:
	flake8 . --config=.flake8
	mypy . --config-file=mypy.ini
	bandit -r . -f json -o bandit-report.json

format:
	black . --line-length=100
	isort . --profile black --line-length=100

# Security checks
security:
	safety check
	bandit -r . -ll
	python tests/run_tests.py --security

# Run all checks
check: lint test

# Clean up generated files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -f bandit-report.json
	rm -rf results/
	rm -rf logs/

# Docker targets
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-test:
	docker-compose run --rm app pytest

# Development helpers
dev-server:
	cd web && python app.py

create-wordlist:
	@echo "Creating sample wordlist..."
	@mkdir -p wordlists
	@echo -e "password\n123456\nadmin\nletmein\nmonkey" > wordlists/sample.txt

# Performance profiling
profile:
	python -m cProfile -o profile.stats basic_cracker.py demo
	python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"

# Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	pydoc -w base_cracker basic_cracker advanced_cracker utils
	@mv *.html docs/

# Quick smoke test
smoke:
	@echo "Running smoke tests..."
	python basic_cracker.py demo
	python advanced_cracker.py demo
	python tests/run_tests.py --smoke