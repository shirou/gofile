// Package gofile provides a Go implementation of the Unix file command.
// It identifies file types by examining their content using magic number patterns.
package gofile

import (
	"io"
	"os"
	"path/filepath"

	"github.com/shirou/gofile/internal/detector"
	"github.com/shirou/gofile/internal/magic"
)

// Options configures file detection behavior.
type Options struct {
	MIME  bool // Return MIME type instead of description
	Brief bool // Return brief description
}

// DefaultOptions returns default detection options.
func DefaultOptions() *Options {
	return &Options{
		MIME:  false,
		Brief: false,
	}
}

// DetectFile detects the file type of the given file path using default options.
func DetectFile(path string) (string, error) {
	return DetectFileWithOptions(path, DefaultOptions())
}

// DetectFileWithOptions detects the file type of the given file path with custom options.
func DetectFileWithOptions(path string, opts *Options) (string, error) {
	// Load magic database
	parser := magic.NewParser()
	magicFile := findMagicFile()
	db, err := parser.ParseFile(magicFile)
	if err != nil {
		return "", err
	}

	// Create flat database for detector
	flatDB := &FlatDatabase{}
	for set := 0; set < 2; set++ {
		for _, entry := range db.Magic[set] {
			if entry.Type != 0 {
				flatDB.entries = append(flatDB.entries, entry)
			}
		}
	}

	// Configure detector options
	detectorOpts := detector.DefaultOptions()
	detectorOpts.MIME = opts.MIME
	detectorOpts.Brief = opts.Brief

	// Create detector and perform detection
	det := detector.New(flatDB, detectorOpts)
	return det.DetectFile(path)
}

// DetectReader detects the file type from an io.Reader using default options.
func DetectReader(reader io.Reader) (string, error) {
	return DetectReaderWithOptions(reader, DefaultOptions())
}

// DetectReaderWithOptions detects the file type from an io.Reader with custom options.
func DetectReaderWithOptions(reader io.Reader, opts *Options) (string, error) {
	// Load magic database
	parser := magic.NewParser()
	magicFile := findMagicFile()
	db, err := parser.ParseFile(magicFile)
	if err != nil {
		return "", err
	}

	// Create flat database for detector
	flatDB := &FlatDatabase{}
	for set := 0; set < 2; set++ {
		for _, entry := range db.Magic[set] {
			if entry.Type != 0 {
				flatDB.entries = append(flatDB.entries, entry)
			}
		}
	}

	// Configure detector options
	detectorOpts := detector.DefaultOptions()
	detectorOpts.MIME = opts.MIME
	detectorOpts.Brief = opts.Brief

	// Create detector and perform detection
	det := detector.New(flatDB, detectorOpts)
	return det.DetectReader(reader)
}

// DetectBytes detects the file type from a byte slice using default options.
func DetectBytes(data []byte) (string, error) {
	return DetectBytesWithOptions(data, DefaultOptions())
}

// DetectBytesWithOptions detects the file type from a byte slice with custom options.
func DetectBytesWithOptions(data []byte, opts *Options) (string, error) {
	// Load magic database
	parser := magic.NewParser()
	magicFile := findMagicFile()
	db, err := parser.ParseFile(magicFile)
	if err != nil {
		return "", err
	}

	// Create flat database for detector
	flatDB := &FlatDatabase{}
	for set := 0; set < 2; set++ {
		for _, entry := range db.Magic[set] {
			if entry.Type != 0 {
				flatDB.entries = append(flatDB.entries, entry)
			}
		}
	}

	// Configure detector options
	detectorOpts := detector.DefaultOptions()
	detectorOpts.MIME = opts.MIME
	detectorOpts.Brief = opts.Brief

	// Create detector and perform detection
	det := detector.New(flatDB, detectorOpts)
	return det.DetectBytes(data)
}

// FlatDatabase implements DatabaseInterface for the detector
type FlatDatabase struct {
	entries []*magic.MagicEntry
}

// GetEntries returns all magic entries in the database
func (db *FlatDatabase) GetEntries() []*magic.MagicEntry {
	return db.entries
}

// findMagicFile locates the magic.mgc file in various standard locations
func findMagicFile() string {
	// Try different possible locations for magic.mgc
	locations := []string{
		// Relative paths (for testing)
		"test/testdata/magic/magic.mgc",
		"testdata/magic/magic.mgc",
		"../test/testdata/magic/magic.mgc",
		"../../test/testdata/magic/magic.mgc",
		// System locations
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc", 
		"/usr/share/file/magic.mgc",
		"/etc/magic.mgc",
		"./magic.mgc",
	}
	
	for _, location := range locations {
		if _, err := os.Stat(location); err == nil {
			return location
		}
	}
	
	// If not found, try to find project root and construct path
	if projectRoot := findProjectRoot(); projectRoot != "" {
		magicFile := filepath.Join(projectRoot, "test", "testdata", "magic", "magic.mgc")
		if _, err := os.Stat(magicFile); err == nil {
			return magicFile
		}
	}
	
	// Fallback to first location (will cause error later if not found)
	return locations[0]
}

// findProjectRoot attempts to find the project root directory
func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	
	return ""
}