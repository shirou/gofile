.PHONY: all build test test_golden clean fmt vet lint

# Default target
all: build

# Build the gofile binary
build:
	go build -o gofile ./cmd/gofile

# Run all tests (excluding golden tests)
test:
	go test -v ./...

# Run golden tests for comparing with system file command
test_golden:
	@echo "Running golden tests to compare gofile with system file command..."
	go test -v -tags golden ./test/golden

# Run golden tests for specific magic file
test_golden_file:
	@if [ -z "$(FILE)" ]; then \
		echo "Usage: make test_golden_file FILE=compress"; \
		exit 1; \
	fi
	go test -v -tags golden ./test/golden -run TestListCommandComparison/$(FILE)

# Update golden test expected outputs
test_golden_update:
	@echo "Updating golden test expected outputs from system file command..."
	go test -tags golden ./test/golden -update

# Run golden tests with verbose diff output
test_golden_verbose:
	go test -v -tags golden ./test/golden -verbose-diff

# Run important magic file tests only
test_golden_important:
	go test -v -tags golden ./test/golden -run TestListCommandSpecificFiles

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Run golangci-lint (if installed)
lint:
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping..."

# Clean build artifacts
clean:
	rm -f gofile
	rm -f cmd/gofile/gofile
	rm -rf test/golden/Magdir/*.expected.actual
	go clean -testcache

# Run tests with coverage
coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Check that gofile can be built
check:
	go build -o /tmp/gofile-test ./cmd/gofile && rm /tmp/gofile-test
	@echo "Build check passed"

# Install gofile to GOPATH/bin
install:
	go install ./cmd/gofile

# Help target
help:
	@echo "Available targets:"
	@echo "  make build                 - Build the gofile binary"
	@echo "  make test                  - Run all tests (excluding golden tests)"
	@echo "  make test_golden           - Run golden tests comparing with system file command"
	@echo "  make test_golden_file FILE=<name> - Test specific magic file"
	@echo "  make test_golden_update    - Update golden test expected outputs"
	@echo "  make test_golden_verbose   - Run golden tests with verbose diff output"
	@echo "  make test_golden_important - Run tests for important magic files only"
	@echo "  make fmt                   - Format code"
	@echo "  make vet                   - Run go vet"
	@echo "  make lint                  - Run golangci-lint (if installed)"
	@echo "  make clean                 - Clean build artifacts and test cache"
	@echo "  make coverage              - Generate test coverage report"
	@echo "  make check                 - Verify that gofile can be built"
	@echo "  make install               - Install gofile to GOPATH/bin"
	@echo "  make help                  - Show this help message"