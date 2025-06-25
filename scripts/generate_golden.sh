#!/bin/bash

# Generate golden test data by running official file command on test files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTDATA_DIR="$PROJECT_ROOT/test/testdata"
GOLDEN_DIR="$PROJECT_ROOT/test/golden"
FILE_TESTS_DIR="$TESTDATA_DIR/file-tests"

echo "Generating golden test data..."

# Check if file-tests exists
if [ ! -d "$FILE_TESTS_DIR" ]; then
    echo "Error: file-tests directory not found. Run 'make fetch-testdata' first."
    exit 1
fi

# Create golden directories
mkdir -p "$GOLDEN_DIR/expected"
mkdir -p "$GOLDEN_DIR/samples"

# Counter for progress
total_files=0
processed_files=0

# Count total files first
echo "Counting test files..."
total_files=$(find "$FILE_TESTS_DIR/db" -type f ! -name "*.source.txt" | wc -l)
echo "Found $total_files test files"

# Process each test file
find "$FILE_TESTS_DIR/db" -type f ! -name "*.source.txt" | while read -r test_file; do
    # Get relative path from db directory
    rel_path="${test_file#$FILE_TESTS_DIR/db/}"
    
    # Create directory structure in golden
    golden_dir="$GOLDEN_DIR/samples/$(dirname "$rel_path")"
    mkdir -p "$golden_dir"
    
    # Copy test file
    cp "$test_file" "$GOLDEN_DIR/samples/$rel_path"
    
    # Generate expected results
    expected_dir="$GOLDEN_DIR/expected/$(dirname "$rel_path")"
    mkdir -p "$expected_dir"
    
    # Run file command and save results
    base_name=$(basename "$rel_path")
    
    # Basic file output
    file "$test_file" > "$expected_dir/${base_name}.out" 2>/dev/null || echo "ERROR: Could not process $test_file" > "$expected_dir/${base_name}.out"
    
    # MIME type output
    file --mime-type "$test_file" > "$expected_dir/${base_name}.mime" 2>/dev/null || echo "ERROR: Could not get MIME type for $test_file" > "$expected_dir/${base_name}.mime"
    
    # MIME encoding output
    file --mime-encoding "$test_file" > "$expected_dir/${base_name}.encoding" 2>/dev/null || echo "ERROR: Could not get encoding for $test_file" > "$expected_dir/${base_name}.encoding"
    
    # Brief output
    file --brief "$test_file" > "$expected_dir/${base_name}.brief" 2>/dev/null || echo "ERROR: Could not get brief output for $test_file" > "$expected_dir/${base_name}.brief"
    
    processed_files=$((processed_files + 1))
    if [ $((processed_files % 100)) -eq 0 ]; then
        echo "Processed $processed_files/$total_files files..."
    fi
done

echo "Golden test data generation completed!"
echo "Generated data for $total_files files"
echo "Results saved in: $GOLDEN_DIR"

# Generate test categories summary
echo "Generating test categories summary..."
find "$GOLDEN_DIR/samples" -mindepth 1 -maxdepth 1 -type d | while read -r category_dir; do
    category=$(basename "$category_dir")
    file_count=$(find "$category_dir" -type f | wc -l)
    echo "$category: $file_count files"
done > "$GOLDEN_DIR/categories.txt"

echo "Test categories summary saved in: $GOLDEN_DIR/categories.txt"
