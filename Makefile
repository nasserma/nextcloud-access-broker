.PHONY: test lint check

test:
	pytest -v

lint:
	ruff check broker tests

check: lint test