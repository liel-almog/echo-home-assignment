SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.PHONY: all build image

all: build

build:
	@if [[ -d dist && ! -w dist ]]; then echo 'dist/ is not writable; fix its ownership before building' >&2; exit 1; fi

	mkdir -p dist

	docker build --pull --no-cache --target artifact --output type=tar,dest=- . | tar --no-same-owner --no-same-permissions -xf - -C dist

	@if [[ $$EUID -eq 0 && -n "$${SUDO_UID:-}" ]]; then chown -R "$$SUDO_UID:$${SUDO_GID:-$$SUDO_UID}" dist; fi

image:
	docker build --pull --no-cache --target runtime -t nginx-echo:1.25.5 .
