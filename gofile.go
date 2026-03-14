// Package gofile provides a pure Go implementation of the Unix file(1) command.
// It identifies file types using magic number rules from the embedded magic database.
package gofile

import (
	"github.com/shirou/gofile/internal/magic"
)

// Options controls the behavior of file identification.
type Options struct {
	// MimeType outputs MIME type instead of description.
	MimeType bool
	// Brief enables brief mode (no filename prefix).
	Brief bool
}

// FileIdentifier identifies file types using magic number rules.
type FileIdentifier struct {
	fi *magic.FileIdentifier
}

// New creates a FileIdentifier using the embedded magic database.
func New(opts Options) (*FileIdentifier, error) {
	fi, err := magic.New(magic.Options{
		MimeType: opts.MimeType,
		Brief:    opts.Brief,
	})
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{fi: fi}, nil
}

// NewFromDir creates a FileIdentifier using magic files from the given directory.
func NewFromDir(dir string, opts Options) (*FileIdentifier, error) {
	fi, err := magic.NewFromDir(dir, magic.Options{
		MimeType: opts.MimeType,
		Brief:    opts.Brief,
	})
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{fi: fi}, nil
}

// NewFromMgcFile creates a FileIdentifier from a compiled .mgc file.
func NewFromMgcFile(path string, opts Options) (*FileIdentifier, error) {
	fi, err := magic.NewFromMgcFile(path, magic.Options{
		MimeType: opts.MimeType,
		Brief:    opts.Brief,
	})
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{fi: fi}, nil
}

// NewFromPath creates a FileIdentifier from a path that can be either
// a .mgc compiled file or a directory of text magic files.
func NewFromPath(path string, opts Options) (*FileIdentifier, error) {
	fi, err := magic.NewFromPath(path, magic.Options{
		MimeType: opts.MimeType,
		Brief:    opts.Brief,
	})
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{fi: fi}, nil
}

// NewFromSystemMgc creates a FileIdentifier using the system .mgc file.
// It searches localDir first (if non-empty), then system paths.
// Falls back to the embedded database if no .mgc file is found.
func NewFromSystemMgc(localDir string, opts Options) (*FileIdentifier, error) {
	fi, err := magic.NewFromSystemMgc(localDir, magic.Options{
		MimeType: opts.MimeType,
		Brief:    opts.Brief,
	})
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{fi: fi}, nil
}

// IdentifyFile identifies a file by its path.
func (f *FileIdentifier) IdentifyFile(path string) (string, error) {
	return f.fi.IdentifyFile(path)
}

// IdentifyBuffer identifies content from a byte buffer.
func (f *FileIdentifier) IdentifyBuffer(buf []byte) string {
	return f.fi.IdentifyBuffer(buf)
}
