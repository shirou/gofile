#!/bin/bash

# Performance testing script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GOFILE_BIN="$PROJECT_ROOT/gofile"
GOLDEN_DIR="$PROJECT_ROOT/test/golden"
RESULTS_DIR="$PROJECT_ROOT/test/results"

echo "Running performance tests..."

# Check if binaries exist
if [ ! -f "$GOFILE_BIN" ]; then
    echo "Error: gofile binary not found. Run 'make build' first."
    exit 1
fi

if [ ! -d "$GOLDEN_DIR/samples" ]; then
    echo "Error: Test data not found. Run 'make setup-test' first."
    exit 1
fi

mkdir -p "$RESULTS_DIR"

PERF_REPORT="$RESULTS_DIR/performance_report.txt"

echo "Performance Test Report" > "$PERF_REPORT"
echo "Generated: $(date)" >> "$PERF_REPORT"
echo "=======================" >> "$PERF_REPORT"
echo "" >> "$PERF_REPORT"

# Test categories
categories=("png" "jpg" "pdf" "txt" "exe" "zip" "doc" "xls" "ppt")

for category in "${categories[@]}"; do
    category_dir="$GOLDEN_DIR/samples/$category"
    
    if [ ! -d "$category_dir" ]; then
        echo "Skipping $category (not found)"
        continue
    fi
    
    echo "Testing $category files..."
    
    # Count files
    file_count=$(find "$category_dir" -type f | wc -l)
    
    if [ $file_count -eq 0 ]; then
        continue
    fi
    
    # Test gofile performance
    echo "  Testing gofile..."
    gofile_start=$(date +%s.%N)
    find "$category_dir" -type f | head -20 | while read -r file; do
        "$GOFILE_BIN" "$file" >/dev/null 2>&1 || true
    done
    gofile_end=$(date +%s.%N)
    gofile_time=$(echo "$gofile_end - $gofile_start" | bc -l)
    
    # Test official file performance
    echo "  Testing file command..."
    file_start=$(date +%s.%N)
    find "$category_dir" -type f | head -20 | while read -r file; do
        file "$file" >/dev/null 2>&1 || true
    done
    file_end=$(date +%s.%N)
    file_time=$(echo "$file_end - $file_start" | bc -l)
    
    # Calculate ratio
    if [ "$(echo "$file_time > 0" | bc -l)" -eq 1 ]; then
        ratio=$(echo "scale=2; $gofile_time / $file_time" | bc -l)
    else
        ratio="N/A"
    fi
    
    # Record results
    {
        echo "$category files:"
        echo "  File count: $file_count (tested: 20)"
        echo "  gofile time: ${gofile_time}s"
        echo "  file time: ${file_time}s"
        echo "  Ratio (gofile/file): $ratio"
        echo ""
    } >> "$PERF_REPORT"
    
    echo "  gofile: ${gofile_time}s, file: ${file_time}s, ratio: $ratio"
done

# Memory usage test
echo "Testing memory usage..."
echo "Memory Usage Test:" >> "$PERF_REPORT"

# Test with a large file if available
large_file=$(find "$GOLDEN_DIR/samples" -type f -size +1M | head -1)
if [ -n "$large_file" ]; then
    echo "  Testing with large file: $(basename "$large_file")"
    
    # Monitor gofile memory usage
    /usr/bin/time -v "$GOFILE_BIN" "$large_file" 2>&1 | grep "Maximum resident set size" >> "$PERF_REPORT" || true
    
    # Monitor file command memory usage
    /usr/bin/time -v file "$large_file" 2>&1 | grep "Maximum resident set size" >> "$PERF_REPORT" || true
fi

echo "" >> "$PERF_REPORT"
echo "Performance test completed!"
echo "Results saved in: $PERF_REPORT"

# Display summary
echo ""
echo "Performance Summary:"
echo "==================="
tail -20 "$PERF_REPORT"
