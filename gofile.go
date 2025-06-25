// Package gofile provides file type detection functionality
// compatible with the Unix file command.
package gofile

import (
	"fmt"
	"io"
	"os"

	"github.com/shirou/gofile/internal/magic"
)

// FileInfo represents information about a detected file
type FileInfo struct {
	Description string  // Human-readable description
	MimeType    string  // MIME type
	Encoding    string  // Character encoding (for text files)
	Extensions  []string // Common file extensions
	Confidence  float64 // Confidence level (0.0-1.0)
}

// Options configures file detection behavior
type Options struct {
	MagicFile   string // Path to custom magic file
	MaxBytes    int    // Maximum bytes to read (0 = no limit)
	FollowLinks bool   // Follow symbolic links
	Brief       bool   // Return brief description only
	MimeType    bool   // Return MIME type only
	MimeEncoding bool  // Return MIME encoding only
}

// DefaultOptions returns default detection options
func DefaultOptions() *Options {
	return &Options{
		MaxBytes:    1024 * 1024, // 1MB default
		FollowLinks: false,
		Brief:       false,
		MimeType:    false,
		MimeEncoding: false,
	}
}

// Detector handles file type detection
type Detector struct {
	db      *magic.Database
	options *Options
}

// NewDetector creates a new file detector with default options
func NewDetector() (*Detector, error) {
	return NewDetectorWithOptions(DefaultOptions())
}

// NewDetectorWithOptions creates a new file detector with custom options
func NewDetectorWithOptions(opts *Options) (*Detector, error) {
	detector := &Detector{
		db:      magic.NewDatabase(),
		options: opts,
	}

	// Load magic database
	var err error
	if opts.MagicFile != "" {
		err = detector.db.Load(opts.MagicFile)
	} else {
		err = detector.db.LoadDefault()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load magic database: %w", err)
	}

	return detector, nil
}

// DetectFile detects the type of a file by path
func (d *Detector) DetectFile(filename string) (*FileInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	return d.DetectReader(file)
}

// DetectReader detects the type of data from a reader
func (d *Detector) DetectReader(r io.Reader) (*FileInfo, error) {
	// Read initial bytes for detection
	maxBytes := d.options.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024 // Default 1MB
	}

	data := make([]byte, maxBytes)
	n, err := r.Read(data)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return d.DetectBytes(data[:n])
}

// DetectBytes detects the type of data from a byte slice
func (d *Detector) DetectBytes(data []byte) (*FileInfo, error) {
	// TODO: Implement actual detection logic
	// For now, return a placeholder result
	
	info := &FileInfo{
		Description: "data", // Placeholder
		MimeType:    "application/octet-stream",
		Encoding:    "",
		Extensions:  []string{},
		Confidence:  0.5,
	}

	return info, nil
}

// GetStats returns statistics about the loaded magic database
func (d *Detector) GetStats() *magic.DatabaseStats {
	return d.db.Stats()
}

// Convenience functions for simple use cases

// DetectFile detects the type of a file using default options
func DetectFile(filename string) (*FileInfo, error) {
	detector, err := NewDetector()
	if err != nil {
		return nil, err
	}
	return detector.DetectFile(filename)
}

// DetectReader detects the type of data from a reader using default options
func DetectReader(r io.Reader) (*FileInfo, error) {
	detector, err := NewDetector()
	if err != nil {
		return nil, err
	}
	return detector.DetectReader(r)
}

// DetectBytes detects the type of data from a byte slice using default options
func DetectBytes(data []byte) (*FileInfo, error) {
	detector, err := NewDetector()
	if err != nil {
		return nil, err
	}
	return detector.DetectBytes(data)
}
