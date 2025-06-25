package gofile

import (
	"strings"
	"testing"
)

func TestNewDetector(t *testing.T) {
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	if detector == nil {
		t.Fatal("Detector is nil")
	}

	// Check that database is loaded
	stats := detector.GetStats()
	if stats.TotalEntries == 0 {
		t.Error("No magic entries loaded")
	}

	t.Logf("Loaded magic database with %d entries", stats.TotalEntries)
}

func TestDetectBytes_Basic(t *testing.T) {
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Test with empty data
	info, err := detector.DetectBytes([]byte{})
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if info == nil {
		t.Fatal("FileInfo is nil")
	}

	// Should return some basic info
	if info.Description == "" {
		t.Error("Description is empty")
	}

	if info.MimeType == "" {
		t.Error("MIME type is empty")
	}

	t.Logf("Empty data detected as: %s (%s)", info.Description, info.MimeType)
}

func TestDetectBytes_TextData(t *testing.T) {
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Test with text data
	textData := []byte("Hello, World!\nThis is a test file.\n")
	info, err := detector.DetectBytes(textData)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	t.Logf("Text data detected as: %s (%s)", info.Description, info.MimeType)
}

func TestDetectFile_NonExistent(t *testing.T) {
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Test with non-existent file
	_, err = detector.DetectFile("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	
	if opts == nil {
		t.Fatal("DefaultOptions returned nil")
	}

	if opts.MaxBytes <= 0 {
		t.Error("MaxBytes should be positive")
	}

	if opts.FollowLinks {
		t.Error("FollowLinks should be false by default")
	}

	if opts.Brief {
		t.Error("Brief should be false by default")
	}

	if opts.MimeType {
		t.Error("MimeType should be false by default")
	}

	if opts.MimeEncoding {
		t.Error("MimeEncoding should be false by default")
	}
}

func TestNewDetectorWithOptions(t *testing.T) {
	opts := &Options{
		MaxBytes:     512,
		FollowLinks:  true,
		Brief:        true,
		MimeType:     true,
		MimeEncoding: false,
	}

	detector, err := NewDetectorWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to create detector with options: %v", err)
	}

	if detector == nil {
		t.Fatal("Detector is nil")
	}

	// Verify options are stored
	if detector.options.MaxBytes != opts.MaxBytes {
		t.Errorf("Expected MaxBytes %d, got %d", opts.MaxBytes, detector.options.MaxBytes)
	}

	if detector.options.FollowLinks != opts.FollowLinks {
		t.Errorf("Expected FollowLinks %v, got %v", opts.FollowLinks, detector.options.FollowLinks)
	}
}

// Convenience function tests
func TestConvenienceFunctions(t *testing.T) {
	// Test DetectBytes convenience function
	data := []byte("test data")
	info, err := DetectBytes(data)
	if err != nil {
		t.Fatalf("DetectBytes failed: %v", err)
	}

	if info == nil {
		t.Fatal("FileInfo is nil")
	}

	t.Logf("Convenience DetectBytes result: %s", info.Description)
}

// Benchmark tests
func BenchmarkNewDetector(b *testing.B) {
	for i := 0; i < b.N; i++ {
		detector, err := NewDetector()
		if err != nil {
			b.Fatalf("Failed to create detector: %v", err)
		}
		_ = detector
	}
}

func BenchmarkDetectBytes(b *testing.B) {
	detector, err := NewDetector()
	if err != nil {
		b.Fatalf("Failed to create detector: %v", err)
	}

	data := []byte("Hello, World! This is test data for benchmarking.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.DetectBytes(data)
		if err != nil {
			b.Fatalf("Detection failed: %v", err)
		}
	}
}
