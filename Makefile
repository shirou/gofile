# GoFile Makefile

.PHONY: all build test test-unit test-integration test-golden test-benchmark clean setup-test fetch-testdata help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build parameters
BINARY_NAME=gofile
BINARY_UNIX=$(BINARY_NAME)_unix
CMD_DIR=./cmd/file

# Test parameters
TEST_TIMEOUT=30s
TEST_VERBOSE=-v
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# External dependencies
FILE_TESTS_REPO=https://github.com/file/file-tests.git
FILE_REPO=https://github.com/file/file.git
TESTDATA_DIR=./test/testdata
GOLDEN_DIR=./test/golden

all: build

## Build commands
build:
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_DIR)

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) $(CMD_DIR)

## Test commands
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	$(GOTEST) $(TEST_VERBOSE) -timeout $(TEST_TIMEOUT) -coverprofile=$(COVERAGE_FILE) ./...

test-integration: setup-test
	@echo "Running integration tests..."
	$(GOTEST) $(TEST_VERBOSE) -timeout 60s -tags=integration ./test/integration/...

test-golden: setup-test generate-golden
	@echo "Running golden tests..."
	$(GOTEST) $(TEST_VERBOSE) -timeout 120s -tags=golden ./test/golden/...

test-benchmark: setup-test
	@echo "Running benchmark tests..."
	$(GOTEST) -bench=. -benchmem -timeout 300s ./test/benchmark/...

test-coverage: test-unit
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

## Test data management
setup-test: fetch-testdata copy-magic

fetch-testdata:
	@echo "Fetching test data..."
	@if [ ! -d "$(TESTDATA_DIR)/file-tests" ]; then \
		mkdir -p $(TESTDATA_DIR) && \
		cd $(TESTDATA_DIR) && \
		git clone $(FILE_TESTS_REPO) file-tests; \
	else \
		echo "Test data already exists, updating..."; \
		cd $(TESTDATA_DIR)/file-tests && git pull; \
	fi
	@if [ ! -d "$(TESTDATA_DIR)/file-source" ]; then \
		cd $(TESTDATA_DIR) && \
		git clone $(FILE_REPO) file-source; \
	else \
		echo "File source already exists, updating..."; \
		cd $(TESTDATA_DIR)/file-source && git pull; \
	fi

copy-magic:
	@echo "Copying magic files..."
	@mkdir -p $(TESTDATA_DIR)/magic
	@if [ -f "/usr/lib/file/magic.mgc" ]; then \
		cp /usr/lib/file/magic.mgc $(TESTDATA_DIR)/magic/; \
	elif [ -f "/usr/share/misc/magic.mgc" ]; then \
		cp /usr/share/misc/magic.mgc $(TESTDATA_DIR)/magic/; \
	else \
		echo "Warning: magic.mgc not found in standard locations"; \
	fi
	@if [ -f "/usr/share/file/magic" ]; then \
		cp /usr/share/file/magic $(TESTDATA_DIR)/magic/magic.txt; \
	elif [ -f "/usr/share/misc/magic" ]; then \
		cp /usr/share/misc/magic $(TESTDATA_DIR)/magic/magic.txt; \
	fi

generate-golden: setup-test
	@echo "Generating golden test data..."
	@mkdir -p $(GOLDEN_DIR)
	@./scripts/generate_golden.sh

## Development commands
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(COVERAGE_FILE)
	rm -f $(COVERAGE_HTML)

clean-test:
	rm -rf $(TESTDATA_DIR)
	rm -rf $(GOLDEN_DIR)

deps:
	$(GOMOD) download
	$(GOMOD) tidy

## Comparison and validation
compare-results: build setup-test
	@echo "Comparing results with official file command..."
	@./scripts/compare_results.sh

validate-magic: setup-test
	@echo "Validating magic.mgc parsing..."
	@$(GOTEST) $(TEST_VERBOSE) -run TestMagicParsing ./internal/magic/...

## Performance testing
perf-test: build setup-test
	@echo "Running performance tests..."
	@./scripts/perf_test.sh

memory-test: build setup-test
	@echo "Running memory usage tests..."
	@$(GOTEST) -run TestMemoryUsage -memprofile=mem.prof ./test/benchmark/...
	@$(GOCMD) tool pprof -http=:8080 mem.prof

## Continuous Integration
ci: deps test test-integration test-golden compare-results

## Development helpers
fmt:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

lint:
	golangci-lint run

## Documentation
docs:
	@echo "Generating documentation..."
	$(GOCMD) doc -all . > docs/api_reference.md

## Help
help:
	@echo "Available targets:"
	@echo "  build           - Build the binary"
	@echo "  build-linux     - Build Linux binary"
	@echo "  test            - Run unit and integration tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration- Run integration tests"
	@echo "  test-golden     - Run golden tests (comparison with file command)"
	@echo "  test-benchmark  - Run benchmark tests"
	@echo "  test-coverage   - Generate test coverage report"
	@echo "  setup-test      - Setup test environment and fetch test data"
	@echo "  fetch-testdata  - Fetch test data from repositories"
	@echo "  generate-golden - Generate golden test data"
	@echo "  compare-results - Compare results with official file command"
	@echo "  validate-magic  - Validate magic.mgc parsing"
	@echo "  perf-test       - Run performance tests"
	@echo "  memory-test     - Run memory usage tests"
	@echo "  clean           - Clean build artifacts"
	@echo "  clean-test      - Clean test data"
	@echo "  deps            - Download and tidy dependencies"
	@echo "  fmt             - Format code"
	@echo "  vet             - Run go vet"
	@echo "  lint            - Run linter"
	@echo "  docs            - Generate documentation"
	@echo "  ci              - Run full CI pipeline"
	@echo "  help            - Show this help message"
