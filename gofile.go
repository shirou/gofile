package gofile

import (
	"fmt"
	"io"

	"github.com/shirou/gofile/internal/detector"
	"github.com/shirou/gofile/internal/magic"
)

// Options configures detection behavior
type Options struct {
	MIME        bool // Return MIME type instead of description
	Brief       bool // Return brief description
	MaxReadSize int  // Maximum bytes to read from file (default: 1MB)
	Debug       bool // Enable debug logging
}

var defaultDetector *detector.Detector

func init() {
	// Initialize default detector with embedded magic database
	db, err := magic.LoadDatabase()
	if err != nil {
		// If we can't load the default database, we'll return an error on first use
		return
	}

	defaultDetector = detector.New(db, detector.DefaultOptions())
}

// DetectFile detects the file type of the given file path using default options
func DetectFile(path string) (string, error) {
	if defaultDetector == nil {
		return "", ErrNoDatabaseLoaded
	}
	return defaultDetector.DetectFile(path)
}

// DetectFileWithOptions detects the file type of the given file path with custom options
func DetectFileWithOptions(path string, opts *Options) (string, error) {
	db, err := magic.LoadDatabase()
	if err != nil {
		return "", err
	}

	detectorOpts := &detector.Options{
		MIME:        opts.MIME,
		Brief:       opts.Brief,
		MaxReadSize: opts.MaxReadSize,
		Debug:       opts.Debug,
	}

	if detectorOpts.MaxReadSize == 0 {
		detectorOpts.MaxReadSize = 1024 * 1024 // 1MB default
	}

	d := detector.New(db, detectorOpts)
	return d.DetectFile(path)
}

// DetectReader detects the file type from an io.Reader using default options
func DetectReader(reader io.Reader) (string, error) {
	if defaultDetector == nil {
		return "", ErrNoDatabaseLoaded
	}
	return defaultDetector.DetectReader(reader)
}

// DetectBytes detects the file type from a byte slice using default options
func DetectBytes(data []byte) (string, error) {
	if defaultDetector == nil {
		return "", ErrNoDatabaseLoaded
	}
	return defaultDetector.DetectBytes(data)
}

// ErrNoDatabaseLoaded is returned when no magic database could be loaded
var ErrNoDatabaseLoaded = fmt.Errorf("no magic database loaded")
