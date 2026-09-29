.PHONY: build test vet check

VERSION ?= dev

build:
	go build -ldflags "-X main.version=$(VERSION)" -o cert-status ./cmd/cert-status

test:
	go test ./...

vet:
	go vet ./...

check: test vet build
