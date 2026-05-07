.PHONY: test setup

test: setup
	uv run pytest tests/

run-dev: setup
	sudo uv run execguard --config=execguard.dev.ini -v

install: setup
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

setup: .venv/pyvenv.cfg
	@if [ ! -f execguard.dev.ini ]; then cp execguard.example.ini execguard.dev.ini; fi

.venv/pyvenv.cfg: pyproject.toml uv.lock
	uv sync
	@touch .venv/pyvenv.cfg
