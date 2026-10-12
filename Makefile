# NanoIO developer tasks. Override with e.g. `make run ROOT=/tmp/nanoio-data`.
GO   ?= go
ROOT ?= ./data
# Development-only root credential for `make run`; override or set your own.
NANOIO_ROOT_USER     ?= nanoadmin
NANOIO_ROOT_PASSWORD ?= nanoadmin-dev-secret
export NANOIO_ROOT_USER NANOIO_ROOT_PASSWORD
BIN  ?= bin/nanoio

.PHONY: all build test oracle run fmt vet fuzz clean help

all: test build

help:
	@echo "make test   vet + all tests with the race detector"
	@echo "make oracle  admin API checked against MinIO's madmin-go (separate module)"
	@echo "make run    start the server on ROOT (default ./data); Ctrl-C to stop"
	@echo "make build  build $(BIN)"
	@echo "make fuzz   10s fuzz run of the metadata decoder"
	@echo "make fmt    gofmt the tree"

build:
	$(GO) build -o $(BIN) ./cmd/nanoio

vet:
	$(GO) vet ./...

test: vet
	$(GO) test -race -count=1 ./...

# madmin-go is AGPL-3.0: it is linked only into this test module, never the server.
oracle:
	cd test/madmin-oracle && GOFLAGS=-mod=mod $(GO) test -count=1 ./...

run: build
	./$(BIN) --root $(ROOT)

fuzz:
	$(GO) test ./internal/meta -run xxx -fuzz FuzzDecode -fuzztime 10s

fmt:
	gofmt -w .

clean:
	rm -rf bin
