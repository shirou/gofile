package detector

import (
	"testing"

	"github.com/shirou/gofile/internal/magic"
)

func TestDetector_DetectBytes(t *testing.T) {
	// Create a simple test database
	db := &MockDatabase{}
	
	// Create test magic entries
	entries := []*magic.MagicEntry{
		// PNG signature
		{
			Offset: 0,
			Type:   magic.FILE_LONG,
			Value:  [64]byte{0x47, 0x4E, 0x50, 0x89}, // PNG signature first 4 bytes (little endian)
			Vallen: 4,
			Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
			Reln:   '=',
		},
		// JPEG signature
		{
			Offset: 0,
			Type:   magic.FILE_SHORT,
			Value:  [64]byte{0xD8, 0xFF}, // JPEG signature (little endian)
			Vallen: 2,
			Desc:   [64]byte{'J', 'P', 'E', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
			Reln:   '=',
		},
		// PDF signature
		{
			Offset: 0,
			Type:   magic.FILE_STRING,
			Value:  [64]byte{'%', 'P', 'D', 'F'}, // PDF signature
			Vallen: 4,
			Desc:   [64]byte{'P', 'D', 'F', ' ', 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't'},
			Reln:   '=',
		},
	}
	
	// Set entries in mock database
	db.SetEntries(entries)
	
	detector := New(db, DefaultOptions())
	
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "PNG file",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expected: "PNG image data",
		},
		{
			name:     "JPEG file",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0},
			expected: "JPEG image data",
		},
		{
			name:     "PDF file",
			data:     []byte{'%', 'P', 'D', 'F', '-', '1', '.', '4'},
			expected: "PDF document",
		},
		{
			name:     "Unknown file",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: "data",
		},
		{
			name:     "Empty file",
			data:     []byte{},
			expected: "empty",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.DetectBytes(tt.data)
			if err != nil {
				t.Fatalf("DetectBytes() error = %v", err)
			}
			if result != tt.expected {
				t.Errorf("DetectBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_DetectBytes_MIME(t *testing.T) {
	// Create test database
	db := &MockDatabase{}
	entries := []*magic.MagicEntry{
		{
			Offset: 0,
			Type:   magic.FILE_LONG,
			Value:  [64]byte{0x47, 0x4E, 0x50, 0x89}, // PNG signature (little endian)
			Vallen: 4,
			Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
			Reln:   '=',
		},
	}
	db.SetEntries(entries)
	
	opts := &Options{MIME: true}
	detector := New(db, opts)
	
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	result, err := detector.DetectBytes(pngData)
	if err != nil {
		t.Fatalf("DetectBytes() error = %v", err)
	}
	
	expected := "image/png"
	if result != expected {
		t.Errorf("DetectBytes() MIME = %v, want %v", result, expected)
	}
}

func TestDetector_CompareValues(t *testing.T) {
	detector := &Detector{}
	
	tests := []struct {
		name     string
		actual   uint64
		expected uint64
		relation byte
		want     bool
	}{
		{"Equal default", 42, 42, 0, true},
		{"Equal explicit", 42, 42, '=', true},
		{"Not equal", 42, 43, '!', true},
		{"Less than", 41, 42, '<', true},
		{"Greater than", 43, 42, '>', true},
		{"Bitwise AND", 0xFF, 0x0F, '&', true},
		{"Bitwise XOR", 0xFF, 0x0F, '^', true},
		{"Equal false", 42, 43, '=', false},
		{"Not equal false", 42, 42, '!', false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.compareValues(tt.actual, tt.expected, tt.relation)
			if result != tt.want {
				t.Errorf("compareValues(%d, %d, %c) = %v, want %v", 
					tt.actual, tt.expected, tt.relation, result, tt.want)
			}
		})
	}
}

func TestDetector_ReadIntegers(t *testing.T) {
	detector := &Detector{}
	
	// Test data: 0x12345678 in both endian formats
	bigEndian := []byte{0x12, 0x34, 0x56, 0x78}
	littleEndian := []byte{0x78, 0x56, 0x34, 0x12}
	
	// Test 16-bit reads
	t.Run("uint16 big endian", func(t *testing.T) {
		result := detector.readUint16(bigEndian, false)
		expected := uint16(0x1234)
		if result != expected {
			t.Errorf("readUint16(bigEndian) = 0x%04X, want 0x%04X", result, expected)
		}
	})
	
	t.Run("uint16 little endian", func(t *testing.T) {
		result := detector.readUint16(littleEndian, true)
		expected := uint16(0x5678)
		if result != expected {
			t.Errorf("readUint16(littleEndian) = 0x%04X, want 0x%04X", result, expected)
		}
	})
	
	// Test 32-bit reads
	t.Run("uint32 big endian", func(t *testing.T) {
		result := detector.readUint32(bigEndian, false)
		expected := uint32(0x12345678)
		if result != expected {
			t.Errorf("readUint32(bigEndian) = 0x%08X, want 0x%08X", result, expected)
		}
	})
	
	t.Run("uint32 little endian", func(t *testing.T) {
		result := detector.readUint32(littleEndian, true)
		expected := uint32(0x12345678)
		if result != expected {
			t.Errorf("readUint32(littleEndian) = 0x%08X, want 0x%08X", result, expected)
		}
	})
}

func TestDetector_DescriptionToMIME(t *testing.T) {
	detector := &Detector{}
	
	tests := []struct {
		desc     string
		expected string
	}{
		{"PNG image data", "image/png"},
		{"JPEG image data", "image/jpeg"},
		{"GIF image data", "image/gif"},
		{"PDF document", "application/pdf"},
		{"HTML document", "text/html"},
		{"XML document", "text/xml"},
		{"Unknown format", "application/octet-stream"},
	}
	
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := detector.descriptionToMIME(tt.desc)
			if result != tt.expected {
				t.Errorf("descriptionToMIME(%q) = %q, want %q", tt.desc, result, tt.expected)
			}
		})
	}
}

func TestDetector_MakeBrief(t *testing.T) {
	detector := &Detector{}
	
	tests := []struct {
		name     string
		desc     string
		expected string
	}{
		{
			name:     "Short description",
			desc:     "PNG image",
			expected: "PNG image",
		},
		{
			name:     "Long description",
			desc:     "This is a very long description that should be truncated because it exceeds the maximum length",
			expected: "This is a very long description that should be ...",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.makeBrief(tt.desc)
			if result != tt.expected {
				t.Errorf("makeBrief(%q) = %q, want %q", tt.desc, result, tt.expected)
			}
		})
	}
}

// Mock implementation for testing
type MockDatabase struct {
	entries []*magic.MagicEntry
}

func (db *MockDatabase) GetEntries() []*magic.MagicEntry {
	return db.entries
}

func (db *MockDatabase) SetEntries(entries []*magic.MagicEntry) {
	db.entries = entries
}
