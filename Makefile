# dotvault Makefile
#
# Common targets:
#   make install   — build release + install to ~/.dotvault/bin (or $PREFIX)
#   make build     — cargo build --release
#   make test      — cargo test
#   make check     — clippy + fmt check
#
# Override the install prefix:
#   make install PREFIX=/usr/local

PREFIX ?= $(HOME)/.dotvault
BINDIR  = $(PREFIX)/bin

CARGO ?= cargo

.PHONY: all build release install test check fmt clippy clean

all: build

build: release

release:
	$(CARGO) build --release

# Install the release binary to ~/.dotvault/bin (mirrors scripts/install.sh).
# Builds first so the binary is always current.
install: release
	@mkdir -p $(BINDIR)
	install -m 0755 target/release/dotvault $(BINDIR)/dotvault
	@echo "Installed dotvault to $(BINDIR)/dotvault"
	@$(BINDIR)/dotvault version | head -1

test:
	$(CARGO) test

check: clippy fmt

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt -- --check

clean:
	$(CARGO) clean
