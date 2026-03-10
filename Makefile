.PHONY: test lint typecheck format install dev clean

install:
	pip install -e .

dev:
	pip install -e ".[dev,pydantic]"

test:
	pytest --cov=proxilion -q

lint:
	ruff check proxilion

format:
	ruff format proxilion

typecheck:
	mypy proxilion

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache coverage.xml htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
