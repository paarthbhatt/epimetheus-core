.PHONY: install test lint build sign verify clean

install:
	python3 -m pip install -e ".[grammars,dev]"

test:
	pytest

lint:
	ruff check epimetheus_core tests

build:
	scripts/release.sh build

# usage: make sign KEY=cosign.key
sign:
	scripts/release.sh sign $(KEY)

# usage: make verify PUB=cosign.pub
verify:
	scripts/release.sh verify $(PUB)

clean:
	rm -rf dist build *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
