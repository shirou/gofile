REPO_DIR := repos/file
MAGDIR_SRC := $(REPO_DIR)/magic/Magdir
MAGDIR_DST := internal/magic/magicdata/Magdir
TESTDATA_SRC := $(REPO_DIR)/tests
TESTDATA_DST := internal/magic/testdata/tests

.PHONY: update-magic update-testdata update-all test build

## Update the embedded magic database from the upstream file(1) repository
update-magic:
	cd $(REPO_DIR) && git pull
	rm -rf $(MAGDIR_DST)
	mkdir -p $(MAGDIR_DST)
	cp $(MAGDIR_SRC)/* $(MAGDIR_DST)/

## Copy test files from the upstream repository into testdata/
update-testdata:
	rm -rf $(TESTDATA_DST)
	mkdir -p $(TESTDATA_DST)
	cp $(TESTDATA_SRC)/* $(TESTDATA_DST)/

## Update both magic database and test data
update-all: update-magic update-testdata

## Run all tests
test:
	go test ./...

## Build the CLI
build:
	go build -o bin/file ./cmd/file
