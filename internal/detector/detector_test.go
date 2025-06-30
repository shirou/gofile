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
			Value:  [96]byte{0x47, 0x4E, 0x50, 0x89}, // PNG signature first 4 bytes (little endian)
			Vallen: 4,
			Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
			Reln:   '=',
		},
		// JPEG signature
		{
			Offset: 0,
			Type:   magic.FILE_SHORT,
			Value:  [96]byte{0xD8, 0xFF}, // JPEG signature (little endian)
			Vallen: 2,
			Desc:   [64]byte{'J', 'P', 'E', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
			Reln:   '=',
		},
		// PDF signature
		{
			Offset: 0,
			Type:   magic.FILE_STRING,
			Value:  [96]byte{'%', 'P', 'D', 'F'}, // PDF signature
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
			Value:  [96]byte{0x47, 0x4E, 0x50, 0x89}, // PNG signature (little endian)
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

func TestDetector_MagicTypes_Quad(t *testing.T) {

	// Test FILE_QUAD (64-bit integer)
	t.Run("FILE_QUAD", func(t *testing.T) {
		db := &MockDatabase{}

		// Create 64-bit test value: 0x123456789ABCDEF0
		quadValue := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_QUAD,
				Value:  [96]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
				Vallen: 8,
				Desc:   [64]byte{'6', '4', '-', 'b', 'i', 't', ' ', 'i', 'n', 't', 'e', 'g', 'e', 'r'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with matching 64-bit value
		testData := append(quadValue, []byte{0x00, 0x01, 0x02, 0x03}...)

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "64-bit integer"
		if result != expected {
			t.Errorf("FILE_QUAD detection = %v, want %v", result, expected)
		}
	})

	// Test FILE_BEQUAD (big-endian 64-bit)
	t.Run("FILE_BEQUAD", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BEQUAD,
				Value:  [96]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
				Vallen: 8,
				Desc:   [64]byte{'B', 'E', ' ', '6', '4', '-', 'b', 'i', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data: 0x123456789ABCDEF0 in big-endian format
		testData := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "BE 64-bit"
		if result != expected {
			t.Errorf("FILE_BEQUAD detection = %v, want %v", result, expected)
		}
	})

	// Test FILE_LEQUAD (little-endian 64-bit)
	t.Run("FILE_LEQUAD", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_LEQUAD,
				Value:  [96]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
				Vallen: 8,
				Desc:   [64]byte{'L', 'E', ' ', '6', '4', '-', 'b', 'i', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data: 0x123456789ABCDEF0 in little-endian format
		testData := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "LE 64-bit"
		if result != expected {
			t.Errorf("FILE_LEQUAD detection = %v, want %v", result, expected)
		}
	})
}

func TestDetector_MagicTypes_Float(t *testing.T) {

	// Test FILE_BEFLOAT (big-endian 32-bit float)
	t.Run("FILE_BEFLOAT", func(t *testing.T) {
		db := &MockDatabase{}

		// Float value 3.14159 in IEEE 754 format (big-endian: 0x40490FDB)
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BEFLOAT,
				Value:  [96]byte{0x40, 0x49, 0x0F, 0xDB},
				Vallen: 4,
				Desc:   [64]byte{'B', 'E', ' ', 'f', 'l', 'o', 'a', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with matching float value in big-endian format
		testData := []byte{0x40, 0x49, 0x0F, 0xDB}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "BE float"
		if result != expected {
			t.Errorf("FILE_BEFLOAT detection = %v, want %v", result, expected)
		}
	})

	// Test FILE_LEFLOAT (little-endian 32-bit float)
	t.Run("FILE_LEFLOAT", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_LEFLOAT,
				Value:  [96]byte{0xDB, 0x0F, 0x49, 0x40}, // Same float in little-endian
				Vallen: 4,
				Desc:   [64]byte{'L', 'E', ' ', 'f', 'l', 'o', 'a', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with matching float value in little-endian format
		testData := []byte{0xDB, 0x0F, 0x49, 0x40}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "LE float"
		if result != expected {
			t.Errorf("FILE_LEFLOAT detection = %v, want %v", result, expected)
		}
	})
}

func TestDetector_MagicTypes_Double(t *testing.T) {

	// Test FILE_BEDOUBLE (big-endian 64-bit double)
	t.Run("FILE_BEDOUBLE", func(t *testing.T) {
		db := &MockDatabase{}

		// Double value 3.141592653589793 in IEEE 754 format (big-endian: 0x400921FB54442D18)
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BEDOUBLE,
				Value:  [96]byte{0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18},
				Vallen: 8,
				Desc:   [64]byte{'B', 'E', ' ', 'd', 'o', 'u', 'b', 'l', 'e'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with matching double value in big-endian format
		testData := []byte{0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "BE double"
		if result != expected {
			t.Errorf("FILE_BEDOUBLE detection = %v, want %v", result, expected)
		}
	})

	// Test FILE_LEDOUBLE (little-endian 64-bit double)
	t.Run("FILE_LEDOUBLE", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_LEDOUBLE,
				Value:  [96]byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40}, // Same double in little-endian
				Vallen: 8,
				Desc:   [64]byte{'L', 'E', ' ', 'd', 'o', 'u', 'b', 'l', 'e'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with matching double value in little-endian format
		testData := []byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		expected := "LE double"
		if result != expected {
			t.Errorf("FILE_LEDOUBLE detection = %v, want %v", result, expected)
		}
	})
}

func TestDetector_MagicTypes_EdgeCases(t *testing.T) {
	// Test edge cases for new magic types
	t.Run("insufficient data", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_QUAD,
				Value:  [96]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Vallen: 8,
				Desc:   [64]byte{'6', '4', '-', 'b', 'i', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with insufficient bytes (only 4 bytes for 8-byte quad)
		testData := []byte{0x01, 0x02, 0x03, 0x04}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		// Should fall back to generic detection
		expected := "data"
		if result != expected {
			t.Errorf("Insufficient data handling = %v, want %v", result, expected)
		}
	})

	t.Run("offset beyond data", func(t *testing.T) {
		db := &MockDatabase{}

		entries := []*magic.MagicEntry{
			{
				Offset: 100, // Offset beyond test data
				Type:   magic.FILE_BEFLOAT,
				Value:  [96]byte{0x40, 0x49, 0x0F, 0xDB},
				Vallen: 4,
				Desc:   [64]byte{'f', 'l', 'o', 'a', 't'},
				Reln:   '=',
			},
		}

		db.SetEntries(entries)
		detector := New(db, DefaultOptions())

		// Test data with only 8 bytes
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}

		// Should fall back to generic detection
		expected := "data"
		if result != expected {
			t.Errorf("Offset beyond data handling = %v, want %v", result, expected)
		}
	})
}

func TestDetector_NewMagicTypes_ExtendedDates(t *testing.T) {

	// Test FILE_BELDATE (big-endian long date)
	t.Run("FILE_BELDATE", func(t *testing.T) {
		db := &MockDatabase{}
		
		// Unix timestamp: 1672531200 (2023-01-01 00:00:00 UTC)
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BELDATE,
				Value:  [96]byte{0x63, 0xB4, 0x60, 0x00}, // 1672531200 in big-endian
				Vallen: 4,
				Desc:   [64]byte{'B', 'E', ' ', 'l', 'o', 'n', 'g', ' ', 'd', 'a', 't', 'e'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data with matching timestamp in big-endian format
		testData := []byte{0x63, 0xB4, 0x60, 0x00}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		expected := "BE long date"
		if result != expected {
			t.Errorf("FILE_BELDATE detection = %v, want %v", result, expected)
		}
	})
	
	// Test FILE_LEQDATE (little-endian 64-bit date)
	t.Run("FILE_LEQDATE", func(t *testing.T) {
		db := &MockDatabase{}
		
		// 64-bit timestamp: 1672531200000000000 (nanoseconds)
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_LEQDATE,
				Value:  [96]byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37, 0x17}, // Little-endian 64-bit
				Vallen: 8,
				Desc:   [64]byte{'L', 'E', ' ', '6', '4', '-', 'b', 'i', 't', ' ', 'd', 'a', 't', 'e'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data with matching 64-bit timestamp in little-endian format
		testData := []byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37, 0x17}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		expected := "LE 64-bit date"
		if result != expected {
			t.Errorf("FILE_LEQDATE detection = %v, want %v", result, expected)
		}
	})
	
	// Test FILE_BEQDATE (big-endian 64-bit date)
	t.Run("FILE_BEQDATE", func(t *testing.T) {
		db := &MockDatabase{}
		
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BEQDATE,
				Value:  [96]byte{0x17, 0x37, 0x33, 0x88, 0x79, 0x2D, 0x00, 0x00}, // Big-endian 64-bit  
				Vallen: 8,
				Desc:   [64]byte{'B', 'E', ' ', '6', '4', '-', 'b', 'i', 't', ' ', 'd', 'a', 't', 'e'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data with matching 64-bit timestamp in big-endian format
		testData := []byte{0x17, 0x37, 0x33, 0x88, 0x79, 0x2D, 0x00, 0x00}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		expected := "BE 64-bit date"
		if result != expected {
			t.Errorf("FILE_BEQDATE detection = %v, want %v", result, expected)
		}
	})
}

func TestDetector_NewMagicTypes_String16(t *testing.T) {

	// Test FILE_BESTRING16 (big-endian 16-bit string)
	t.Run("FILE_BESTRING16", func(t *testing.T) {
		db := &MockDatabase{}
		
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BESTRING16,
				Value:  [96]byte{'T', 'e', 's', 't'}, // Pattern to match
				Vallen: 4,
				Desc:   [64]byte{'U', 'T', 'F', '-', '1', '6', ' ', 'B', 'E', ' ', 's', 't', 'r', 'i', 'n', 'g'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data: "Test" in UTF-16 big-endian format
		// T=0x0054, e=0x0065, s=0x0073, t=0x0074
		testData := []byte{0x00, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00} // "Test" + null terminator
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		expected := "UTF-16 BE string"
		if result != expected {
			t.Errorf("FILE_BESTRING16 detection = %v, want %v", result, expected)
		}
	})
}

func TestDetector_NewMagicTypes_Clear(t *testing.T) {

	// Test FILE_CLEAR (state clearing)
	t.Run("FILE_CLEAR", func(t *testing.T) {
		db := &MockDatabase{}
		
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_CLEAR,
				Value:  [96]byte{}, // Clear operation doesn't need a value
				Vallen: 0,
				Desc:   [64]byte{'C', 'l', 'e', 'a', 'r', ' ', 's', 't', 'a', 't', 'e'},
				Reln:   '=',
			},
			// Add a secondary entry that should match after clear
			{
				Offset: 0,
				Type:   magic.FILE_BYTE,
				Value:  [96]byte{0xFF},
				Vallen: 1,
				Desc:   [64]byte{'B', 'y', 't', 'e', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data that matches the byte pattern
		testData := []byte{0xFF, 0x01, 0x02, 0x03}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		// Should match the byte pattern since CLEAR returns false and continues
		expected := "Byte match"
		if result != expected {
			t.Errorf("FILE_CLEAR processing = %v, want %v", result, expected)
		}
	})
}

func TestDetector_NewMagicTypes_EdgeCases_Extended(t *testing.T) {

	// Test insufficient data for 64-bit dates
	t.Run("insufficient data for LEQDATE", func(t *testing.T) {
		db := &MockDatabase{}
		
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_LEQDATE,
				Value:  [96]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Vallen: 8,
				Desc:   [64]byte{'6', '4', '-', 'b', 'i', 't'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data with insufficient bytes (only 4 bytes for 8-byte date)
		testData := []byte{0x01, 0x02, 0x03, 0x04}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		// Should fall back to generic detection
		expected := "data"
		if result != expected {
			t.Errorf("Insufficient data handling = %v, want %v", result, expected)
		}
	})
	
	// Test BESTRING16 with non-ASCII characters
	t.Run("BESTRING16 with non-ASCII", func(t *testing.T) {
		db := &MockDatabase{}
		
		entries := []*magic.MagicEntry{
			{
				Offset: 0,
				Type:   magic.FILE_BESTRING16,
				Value:  [96]byte{'A', 'B'}, // Pattern to match
				Vallen: 2,
				Desc:   [64]byte{'U', 'n', 'i', 'c', 'o', 'd', 'e', ' ', 's', 't', 'r', 'i', 'n', 'g'},
				Reln:   '=',
			},
		}
		
		db.SetEntries(entries)
		detector := New(db, DefaultOptions())
		
		// Test data: mixed ASCII and non-ASCII in UTF-16 BE format
		// A=0x0041, B=0x0042, 0x3042 (Japanese character), C=0x0043
		testData := []byte{0x00, 0x41, 0x00, 0x42, 0x30, 0x42, 0x00, 0x43}
		
		result, err := detector.DetectBytes(testData)
		if err != nil {
			t.Fatalf("DetectBytes() error = %v", err)
		}
		
		expected := "Unicode string"
		if result != expected {
			t.Errorf("BESTRING16 with Unicode = %v, want %v", result, expected)
		}
	})
}

// Mock implementation for testing
type MockDatabase struct {
	entries    []*magic.MagicEntry
	namedEntries map[string]*magic.MagicEntry
}

func (db *MockDatabase) GetEntries() []*magic.MagicEntry {
	return db.entries
}

func (db *MockDatabase) FindNamedEntry(name string) *magic.MagicEntry {
	if db.namedEntries == nil {
		return nil
	}
	return db.namedEntries[name]
}

func (db *MockDatabase) SetEntries(entries []*magic.MagicEntry) {
	db.entries = entries
}

func (db *MockDatabase) SetNamedEntry(name string, entry *magic.MagicEntry) {
	if db.namedEntries == nil {
		db.namedEntries = make(map[string]*magic.MagicEntry)
	}
	db.namedEntries[name] = entry
}
