BINARY := httpanalyzer
PKG := ./cmd/httpanalyzer
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt lint install clean snapshot release

build: ## Build the binary for the host platform
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY) $(PKG)

test: ## Run the test suite
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Check formatting (fails if unformatted)
	@gofmt -l . | tee /dev/stderr | (! read)

install: ## Install the binary into GOPATH/bin
	go install -ldflags "$(LDFLAGS)" $(PKG)

clean: ## Remove build artifacts
	rm -rf dist

snapshot: ## Build a local cross-platform snapshot (requires goreleaser)
	goreleaser release --snapshot --clean

release: ## Cut a release (requires goreleaser + a pushed tag)
	goreleaser release --clean

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n",$$1,$$2}'
