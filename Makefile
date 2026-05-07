.PHONY: test setup

test: setup
	uv run pytest tests/

run-dev: setup
	sudo uv run execguard --config=execguard.dev.ini

install: setup
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

setup: .venv/bin/python

.venv/bin/python: pyproject.toml uv.lock
	uv sync
