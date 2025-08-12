# Golden Tests for gofile List Command

This directory contains tests that compare the output of the `gofile --list` command with the system's `file --list` command for all magic files in the reference implementation.

## Directory Structure

```
test/golden/
├── list_comparison_test.go  # Main test file
├── test_helper.go           # Helper functions
└── Magdir/                  # Test execution directory
    ├── <magic_file>         # Copied magic file (e.g., "hp", "android")
    └── <magic_file>.expected # Expected output from file --list
```

## Running Tests

### Run all comparison tests
```bash
go test ./test/golden
```

### Run tests with verbose output
```bash
go test -v ./test/golden
```

### Test a specific magic file
```bash
go test -v ./test/golden -run TestListCommandComparison/compress
```

### Update expected outputs (golden files)
```bash
go test ./test/golden -update
```

### Show detailed differences when tests fail
```bash
go test -v ./test/golden -verbose-diff
```

### Test only important/common magic files
```bash
go test -v ./test/golden -run TestListCommandSpecificFiles
```

## Test Flags

- `-update`: Regenerate all `.expected` files from the system `file` command
- `-magic-file=<name>`: Test only a specific magic file
- `-verbose-diff`: Show detailed line-by-line differences when outputs don't match

## How It Works

1. **Setup Phase**: 
   - Builds the `gofile` binary from source
   - Copies magic files from `github.com/file/file/magic/Magdir/` to `test/golden/Magdir/`

2. **Golden File Generation**:
   - Runs `file -m <magic_file> --list` for each magic file
   - Saves output to `<magic_file>.expected`

3. **Comparison Phase**:
   - Runs `gofile -m <magic_file> --list` for each magic file
   - Compares output with the `.expected` file
   - Reports any differences

4. **Debugging**:
   - When tests fail, actual output is saved to `<magic_file>.expected.actual`
   - You can use `diff` to see detailed differences

## Test Coverage

The tests cover:
- All 300+ magic files in the Magdir directory
- Strength calculation accuracy
- Message format consistency
- Binary vs Text pattern classification
- Sort order validation

## Troubleshooting

### System file command not found
If the system `file` command is not available, tests will be skipped with an appropriate message.

### Differences in output
When tests fail due to output differences:
1. Check the `.actual` file for the gofile output
2. Use `diff` to compare: `diff Magdir/<file>.expected Magdir/<file>.expected.actual`
3. Run with `-verbose-diff` for detailed output

### Updating after implementation changes
After fixing issues in the gofile implementation, re-run tests to verify:
```bash
go test -v ./test/golden -run TestListCommandComparison/<specific_file>
```

## Known Issues

- The system `file` command may output warning messages that need to be filtered
- Strength calculations may differ between implementations and need investigation
- Some magic files may have platform-specific behavior