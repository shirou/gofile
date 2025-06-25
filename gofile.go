// Package gofile provides a pure Go implementation of the Linux file command
package gofile

import (
	"fmt"
	"io"
	"os"
	
	"github.com/shirou/gofile/internal/magic"
)

// File represents a file type detector
type File struct {
	database *magic.Database
	options  Options
}

// Options configures the file detector behavior
type Options struct {
	MagicFiles     []string // Custom magic files to load
	FollowSymlinks bool     // Follow symbolic links
	Brief          bool     // Brief output mode
	MimeType       bool     // Output MIME type
	MimeEncoding   bool     // Output MIME encoding
	KeepGoing      bool     // Continue after first match
	Debug          bool     // Enable debug output
}

// New creates a new File detector with default magic files
func New() (*File, error) {
	return NewWithOptions(Options{})
}

// NewWithOptions creates a new File detector with custom options
func NewWithOptions(opts Options) (*File, error) {
	var db *magic.Database
	var err error
	
	if len(opts.MagicFiles) > 0 {
		// Load specified magic files
		parser := magic.NewParser()
		for _, path := range opts.MagicFiles {
			if err := parser.ParseFile(path); err != nil {
				if opts.Debug {
					fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", path, err)
				}
			}
		}
		parser.OrganizeSets()
		db = parser.GetDatabase()
	} else {
		// Load default magic files
		db, err = magic.LoadDefaultMagicFiles()
		if err != nil {
			return nil, fmt.Errorf("failed to load magic files: %w", err)
		}
	}
	
	return &File{
		database: db,
		options:  opts,
	}, nil
}

// IdentifyFile identifies the type of a file by path
func (f *File) IdentifyFile(path string) (string, error) {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot stat %s: %w", path, err)
	}
	
	// Handle special file types
	if info.IsDir() {
		return "directory", nil
	}
	
	if info.Mode()&os.ModeSymlink != 0 && !f.options.FollowSymlinks {
		target, _ := os.Readlink(path)
		if target != "" {
			return fmt.Sprintf("symbolic link to %s", target), nil
		}
		return "symbolic link", nil
	}
	
	if info.Mode()&os.ModeDevice != 0 {
		if info.Mode()&os.ModeCharDevice != 0 {
			return "character special", nil
		}
		return "block special", nil
	}
	
	if info.Mode()&os.ModeNamedPipe != 0 {
		return "fifo (named pipe)", nil
	}
	
	if info.Mode()&os.ModeSocket != 0 {
		return "socket", nil
	}
	
	// Regular file - open and identify
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer file.Close()
	
	return f.Identify(file)
}

// Identify identifies the type of data from a reader
func (f *File) Identify(r io.Reader) (string, error) {
	// Read initial data for magic testing
	buffer := make([]byte, 8192)
	n, err := r.Read(buffer)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read data: %w", err)
	}
	
	if n == 0 {
		return "empty", nil
	}
	
	buffer = buffer[:n]
	
	// TODO: Implement actual magic pattern matching
	// For now, return a simple detection based on common patterns
	
	// Check for text
	if isText(buffer) {
		return "ASCII text", nil
	}
	
	// Default
	return "data", nil
}

// isText checks if buffer contains text data
func isText(buffer []byte) bool {
	for _, b := range buffer {
		// Check for non-printable characters (except common whitespace)
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
		if b > 0x7E && b < 0xA0 {
			return false
		}
	}
	return true
}

// GetDatabase returns the magic database
func (f *File) GetDatabase() *magic.Database {
	return f.database
}

// ListMagic returns the magic patterns with their strengths
func (f *File) ListMagic() []string {
	return f.database.FormatForList()
}