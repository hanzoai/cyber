.PHONY: help build build-go build-rust build-web test test-go test-rust test-web release-binaries clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN_DIR ?= bin
RELEASE_DIR ?= dist/release
GO_LDFLAGS ?= -s -w -X main.version=$(VERSION)

PLATFORMS := \
	darwin/arm64 \
	darwin/amd64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64

help:
	@printf '%s\n' \
	  'make build             build Go cyber, Rust cyber-probe, and TypeScript web/dist' \
	  'make test              run Go, Rust, and TypeScript test suites' \
	  'make release-binaries  cross-compile Go cyber binaries + Rust cyber-probe + SHA256SUMS' \
	  'make clean             remove build and release artifacts'

build: build-go build-rust build-web

build-go:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags="$(GO_LDFLAGS)" -o $(BIN_DIR)/cyber ./cmd/cyber

build-rust:
	@mkdir -p $(BIN_DIR)
	RUSTFLAGS="-D warnings" cargo build --release --manifest-path rust/cyber-probe/Cargo.toml
	@cp rust/cyber-probe/target/release/cyber-probe $(BIN_DIR)/cyber-probe

build-web:
	pnpm --dir web install --prefer-offline
	pnpm --dir web run build

test: test-go test-rust test-web

test-go:
	GOWORK=off go vet ./...
	GOWORK=off go test -v ./...

test-rust:
	RUSTFLAGS="-D warnings" cargo test --manifest-path rust/cyber-probe/Cargo.toml

test-web:
	pnpm --dir web run typecheck
	pnpm --dir web run test

release-binaries:
	@rm -rf $(RELEASE_DIR)
	@mkdir -p $(RELEASE_DIR)
	@set -eu; \
	for spec in $(PLATFORMS); do \
	  os="$${spec%/*}"; \
	  arch="$${spec#*/}"; \
	  ext=""; \
	  if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	  out="$(RELEASE_DIR)/cyber-$${os}-$${arch}$${ext}"; \
	  echo "Building $$out"; \
	  CGO_ENABLED=0 GOWORK=off GOOS="$$os" GOARCH="$$arch" \
	    go build -trimpath -ldflags="$(GO_LDFLAGS)" -o "$$out" ./cmd/cyber; \
	done
	RUSTFLAGS="-D warnings" cargo build --release --manifest-path rust/cyber-probe/Cargo.toml
	@host_os="$$(uname -s | tr '[:upper:]' '[:lower:]')"; \
	host_arch="$$(uname -m)"; \
	case "$$host_arch" in \
	  x86_64) host_arch="amd64" ;; \
	  arm64|aarch64) host_arch="arm64" ;; \
	esac; \
	cp rust/cyber-probe/target/release/cyber-probe "$(RELEASE_DIR)/cyber-probe-$${host_os}-$${host_arch}"
	@cd $(RELEASE_DIR) && (command -v sha256sum >/dev/null 2>&1 && sha256sum * || shasum -a 256 *) > ../SHA256SUMS.tmp && mv ../SHA256SUMS.tmp SHA256SUMS
	@echo "Release artifacts written to $(RELEASE_DIR):"
	@cat $(RELEASE_DIR)/SHA256SUMS

clean:
	rm -rf $(BIN_DIR) dist rust/cyber-probe/target web/dist
