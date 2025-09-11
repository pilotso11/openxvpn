# Makefile for OpenXVPN

.PHONY: help build test test-verbose test-race test-coverage clean lint docker-build docker-test fmt vet

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Build targets
build: ## Build the Go binary
	go build -o out/openxvpn .

build-all: ## Build for all platforms
	GOOS=linux GOARCH=amd64 go build -o dist/openxvpn-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o dist/openxvpn-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o dist/openxvpn-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o dist/openxvpn-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o dist/openxvpn-windows-amd64.exe .

# Test targets
test: test-coverage
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v -race ./...

test-coverage: ## Run tests with coverage
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out

test-all: ## Run all tests (may fail due to interface issues)
	go test -race ./...

# Quality targets
fmt: ## Format Go code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (requires golangci-lint to be installed)
	golangci-lint run

# Docker targets
docker-build: ## Build Docker image
	docker build -t openxvpn .

docker-test: ## Test Docker image
	docker run --rm openxvpn /vpn/openxvpn --help || true

# Development targets
deps: ## Download dependencies
	go mod download
	go mod verify

tidy: ## Tidy go modules
	go mod tidy

clean: ## Clean build artifacts
	rm -f coverage.out coverage.html
	rm -rf out/ dist/

# CI targets (used by GitHub Actions)
ci-test: fmt vet test-race test-coverage ## Run all CI tests

# Documentation
docs: ## Generate documentation
	@echo "Documentation is available in README.md"
	@echo "API documentation: go doc ./..."
