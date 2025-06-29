package gofile

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestDetectFile(t *testing.T) {
	// Create a test PNG file
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	tmpFile, err := os.CreateTemp("", "test_*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(pngData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	// Test DetectFile
	result, err := DetectFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("DetectFile failed: %v", err)
	}

	if !strings.Contains(result, "PNG") {
		t.Errorf("Expected PNG detection, got: %s", result)
	}
}

func TestDetectFileWithOptions(t *testing.T) {
	// Create a test PNG file
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	tmpFile, err := os.CreateTemp("", "test_*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(pngData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	// Test with MIME option
	opts := &Options{MIME: true}
	result, err := DetectFileWithOptions(tmpFile.Name(), opts)
	if err != nil {
		t.Fatalf("DetectFileWithOptions failed: %v", err)
	}

	if !strings.Contains(result, "image/png") {
		t.Errorf("Expected MIME type image/png, got: %s", result)
	}

	// Test with Brief option
	opts = &Options{Brief: true}
	result, err = DetectFileWithOptions(tmpFile.Name(), opts)
	if err != nil {
		t.Fatalf("DetectFileWithOptions failed: %v", err)
	}

	// Brief mode should return shorter description
	if len(result) > 50 {
		t.Errorf("Expected brief description to be shorter, got: %s (length: %d)", result, len(result))
	}
}

func TestDetectReader(t *testing.T) {
	// Create a test PNG data
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	reader := bytes.NewReader(pngData)

	// Test DetectReader
	result, err := DetectReader(reader)
	if err != nil {
		t.Fatalf("DetectReader failed: %v", err)
	}

	if !strings.Contains(result, "PNG") {
		t.Errorf("Expected PNG detection, got: %s", result)
	}
}

func TestDetectReaderWithOptions(t *testing.T) {
	// Create a test PNG data
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	// Test with MIME option
	reader := bytes.NewReader(pngData)
	opts := &Options{MIME: true}
	result, err := DetectReaderWithOptions(reader, opts)
	if err != nil {
		t.Fatalf("DetectReaderWithOptions failed: %v", err)
	}

	if !strings.Contains(result, "image/png") {
		t.Errorf("Expected MIME type image/png, got: %s", result)
	}
}

func TestDetectBytes(t *testing.T) {
	// Test PNG data
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	result, err := DetectBytes(pngData)
	if err != nil {
		t.Fatalf("DetectBytes failed: %v", err)
	}

	if !strings.Contains(result, "PNG") {
		t.Errorf("Expected PNG detection, got: %s", result)
	}

	// Test empty data
	result, err = DetectBytes([]byte{})
	if err != nil {
		t.Fatalf("DetectBytes failed on empty data: %v", err)
	}

	if result != "empty" {
		t.Errorf("Expected 'empty' for empty data, got: %s", result)
	}
}

func TestDetectBytesWithOptions(t *testing.T) {
	// Test PNG data
	pngData := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk header
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 pixel
		0x08, 0x02, 0x00, 0x00, 0x00, 0x37, 0x42, 0xB8, // PNG format data
		0x89, // IHDR CRC
	}

	// Test with MIME option
	opts := &Options{MIME: true}
	result, err := DetectBytesWithOptions(pngData, opts)
	if err != nil {
		t.Fatalf("DetectBytesWithOptions failed: %v", err)
	}

	if !strings.Contains(result, "image/png") {
		t.Errorf("Expected MIME type image/png, got: %s", result)
	}

	// Test text data detection
	textData := []byte("Hello, World!")
	result, err = DetectBytes(textData)
	if err != nil {
		t.Fatalf("DetectBytes failed on text data: %v", err)
	}

	if !strings.Contains(result, "ASCII") || !strings.Contains(result, "text") {
		t.Errorf("Expected ASCII text detection, got: %s", result)
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.MIME {
		t.Error("Expected MIME to be false by default")
	}
	if opts.Brief {
		t.Error("Expected Brief to be false by default")
	}
}

func TestFlatDatabase(t *testing.T) {
	db := &FlatDatabase{}
	
	// Test empty database
	entries := db.GetEntries()
	if len(entries) != 0 {
		t.Errorf("Expected empty database, got %d entries", len(entries))
	}
}