#!/bin/bash

# Compare gofile results with official file command

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GOLDEN_DIR="$PROJECT_ROOT/test/golden"
GOFILE_BIN="$PROJECT_ROOT/gofile"

echo "Comparing gofile results with official file command..."

# Check if gofile binary exists
if [ ! -f "$GOFILE_BIN" ]; then
    echo "Error: gofile binary not found. Run 'make build' first."
    exit 1
fi

# Check if golden data exists
if [ ! -d "$GOLDEN_DIR/samples" ]; then
    echo "Error: Golden test data not found. Run 'make generate-golden' first."
    exit 1
fi

# Results directory
RESULTS_DIR="$PROJECT_ROOT/test/results"
mkdir -p "$RESULTS_DIR"

# Counters
total_tests=0
passed_tests=0
failed_tests=0

# Create comparison report
REPORT_FILE="$RESULTS_DIR/comparison_report.txt"
FAILED_FILE="$RESULTS_DIR/failed_tests.txt"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

echo "GoFile vs File Command Comparison Report" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "=========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Failed Tests Details" > "$FAILED_FILE"
echo "===================" >> "$FAILED_FILE"
echo "" >> "$FAILED_FILE"

# Process each test file
find "$GOLDEN_DIR/samples" -type f | while read -r test_file; do
    # Get relative path
    rel_path="${test_file#$GOLDEN_DIR/samples/}"
    expected_dir="$GOLDEN_DIR/expected/$(dirname "$rel_path")"
    base_name=$(basename "$rel_path")
    
    # Skip if expected results don't exist
    if [ ! -f "$expected_dir/${base_name}.out" ]; then
        continue
    fi
    
    total_tests=$((total_tests + 1))
    
    # Run gofile on test file
    gofile_output=$("$GOFILE_BIN" "$test_file" 2>/dev/null || echo "ERROR: gofile failed")
    gofile_mime=$("$GOFILE_BIN" --mime-type "$test_file" 2>/dev/null || echo "ERROR: gofile mime failed")
    
    # Read expected results
    expected_output=$(cat "$expected_dir/${base_name}.out" 2>/dev/null || echo "ERROR: Could not read expected output")
    expected_mime=$(cat "$expected_dir/${base_name}.mime" 2>/dev/null || echo "ERROR: Could not read expected mime")
    
    # Compare results
    output_match=false
    mime_match=false
    
    # Extract just the description part (after the colon and space)
    gofile_desc=$(echo "$gofile_output" | sed 's/^[^:]*: //')
    expected_desc=$(echo "$expected_output" | sed 's/^[^:]*: //')
    
    if [ "$gofile_desc" = "$expected_desc" ]; then
        output_match=true
    fi
    
    # Extract MIME type
    gofile_mime_type=$(echo "$gofile_mime" | sed 's/^[^:]*: //')
    expected_mime_type=$(echo "$expected_mime" | sed 's/^[^:]*: //')
    
    if [ "$gofile_mime_type" = "$expected_mime_type" ]; then
        mime_match=true
    fi
    
    # Record results
    if [ "$output_match" = true ] && [ "$mime_match" = true ]; then
        passed_tests=$((passed_tests + 1))
        echo "PASS: $rel_path" >> "$REPORT_FILE"
    else
        failed_tests=$((failed_tests + 1))
        echo "FAIL: $rel_path" >> "$REPORT_FILE"
        
        # Add detailed failure info
        echo "FAILED: $rel_path" >> "$FAILED_FILE"
        echo "  Expected: $expected_desc" >> "$FAILED_FILE"
        echo "  Got:      $gofile_desc" >> "$FAILED_FILE"
        echo "  Expected MIME: $expected_mime_type" >> "$FAILED_FILE"
        echo "  Got MIME:      $gofile_mime_type" >> "$FAILED_FILE"
        echo "" >> "$FAILED_FILE"
    fi
    
    # Progress indicator
    if [ $((total_tests % 50)) -eq 0 ]; then
        echo "Processed $total_tests tests..."
    fi
done

# Generate summary
{
    echo "Comparison Summary"
    echo "=================="
    echo "Total tests: $total_tests"
    echo "Passed: $passed_tests"
    echo "Failed: $failed_tests"
    if [ $total_tests -gt 0 ]; then
        accuracy=$(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo "N/A")
        echo "Accuracy: ${accuracy}%"
    fi
    echo ""
    echo "Detailed results: $REPORT_FILE"
    echo "Failed tests: $FAILED_FILE"
} > "$SUMMARY_FILE"

# Display summary
cat "$SUMMARY_FILE"

# Exit with error if accuracy is below threshold
if [ $total_tests -gt 0 ]; then
    accuracy_int=$(echo "$accuracy" | cut -d. -f1)
    if [ "$accuracy_int" -lt 90 ]; then
        echo "Warning: Accuracy below 90% threshold"
        exit 1
    fi
fi
