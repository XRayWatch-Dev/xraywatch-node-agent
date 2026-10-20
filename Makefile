.PHONY: check test build

VERSION := $(shell tr -d '[:space:]' < VERSION)

check:
	test -n "$(VERSION)"
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

test:
	go test ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/xraywatch-node-agent ./cmd/xraywatch-node-agent
