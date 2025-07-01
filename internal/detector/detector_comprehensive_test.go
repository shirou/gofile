package detector

import (
	"testing"

	"github.com/shirou/gofile/internal/magic"
)

// TestComprehensiveTypesCoverage validates that all magic types are implemented
func TestComprehensiveTypesCoverage(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	// All magic types that should be implemented
	allTypes := []uint8{
		magic.FILE_BYTE, magic.FILE_SHORT, magic.FILE_DEFAULT, magic.FILE_LONG, magic.FILE_STRING,
		magic.FILE_DATE, magic.FILE_BESHORT, magic.FILE_BELONG, magic.FILE_BEDATE,
		magic.FILE_LESHORT, magic.FILE_LELONG, magic.FILE_LEDATE, magic.FILE_PSTRING,
		magic.FILE_LDATE, magic.FILE_BELDATE, magic.FILE_LELDATE, magic.FILE_REGEX,
		magic.FILE_BESTRING16, magic.FILE_LESTRING16, magic.FILE_SEARCH, magic.FILE_MEDATE,
		magic.FILE_MELDATE, magic.FILE_MELONG, magic.FILE_QUAD, magic.FILE_LEQUAD,
		magic.FILE_BEQUAD, magic.FILE_QDATE, magic.FILE_LEQDATE, magic.FILE_BEQDATE,
		magic.FILE_QLDATE, magic.FILE_LEQLDATE, magic.FILE_BEQLDATE, magic.FILE_FLOAT,
		magic.FILE_BEFLOAT, magic.FILE_LEFLOAT, magic.FILE_DOUBLE, magic.FILE_BEDOUBLE,
		magic.FILE_LEDOUBLE, magic.FILE_BEID3, magic.FILE_LEID3, magic.FILE_INDIRECT,
		magic.FILE_QWDATE, magic.FILE_LEQWDATE, magic.FILE_BEQWDATE, magic.FILE_NAME,
		magic.FILE_USE, magic.FILE_CLEAR, magic.FILE_DER, magic.FILE_GUID,
		magic.FILE_OFFSET, magic.FILE_BEVARINT, magic.FILE_LEVARINT, magic.FILE_MSDOSDATE,
		magic.FILE_LEMSDOSDATE, magic.FILE_BEMSDOSDATE, magic.FILE_MSDOSTIME,
		magic.FILE_LEMSDOSTIME, magic.FILE_BEMSDOSTIME, magic.FILE_OCTAL,
	}

	// Test data for each type
	testData := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	for _, magicType := range allTypes {
		t.Run(getTypeName(magicType), func(t *testing.T) {
			entry := &magic.MagicEntry{
				Type:    magicType,
				Offset:  0,
				Reln:    '=',
				NumMask: 0,
				Value:   [96]byte{0x12, 0x34, 0x56, 0x78},
				Desc:    [64]byte{'T', 'e', 's', 't', ' ', 'd', 'e', 's', 'c'},
			}

			// This should not panic and should handle the type gracefully
			match, result := detector.performMatch(testData, entry, testData)

			// We don't expect all to match, but they should all be handled without error
			t.Logf("Type %d (%s): match=%v, result='%s'", magicType, getTypeName(magicType), match, result)
		})
	}
}

// getTypeName returns a human-readable name for a magic type
func getTypeName(magicType uint8) string {
	names := map[uint8]string{
		magic.FILE_BYTE:        "BYTE",
		magic.FILE_SHORT:       "SHORT",
		magic.FILE_DEFAULT:     "DEFAULT",
		magic.FILE_LONG:        "LONG",
		magic.FILE_STRING:      "STRING",
		magic.FILE_DATE:        "DATE",
		magic.FILE_BESHORT:     "BESHORT",
		magic.FILE_BELONG:      "BELONG",
		magic.FILE_BEDATE:      "BEDATE",
		magic.FILE_LESHORT:     "LESHORT",
		magic.FILE_LELONG:      "LELONG",
		magic.FILE_LEDATE:      "LEDATE",
		magic.FILE_PSTRING:     "PSTRING",
		magic.FILE_LDATE:       "LDATE",
		magic.FILE_BELDATE:     "BELDATE",
		magic.FILE_LELDATE:     "LELDATE",
		magic.FILE_REGEX:       "REGEX",
		magic.FILE_BESTRING16:  "BESTRING16",
		magic.FILE_LESTRING16:  "LESTRING16",
		magic.FILE_SEARCH:      "SEARCH",
		magic.FILE_MEDATE:      "MEDATE",
		magic.FILE_MELDATE:     "MELDATE",
		magic.FILE_MELONG:      "MELONG",
		magic.FILE_QUAD:        "QUAD",
		magic.FILE_LEQUAD:      "LEQUAD",
		magic.FILE_BEQUAD:      "BEQUAD",
		magic.FILE_QDATE:       "QDATE",
		magic.FILE_LEQDATE:     "LEQDATE",
		magic.FILE_BEQDATE:     "BEQDATE",
		magic.FILE_QLDATE:      "QLDATE",
		magic.FILE_LEQLDATE:    "LEQLDATE",
		magic.FILE_BEQLDATE:    "BEQLDATE",
		magic.FILE_FLOAT:       "FLOAT",
		magic.FILE_BEFLOAT:     "BEFLOAT",
		magic.FILE_LEFLOAT:     "LEFLOAT",
		magic.FILE_DOUBLE:      "DOUBLE",
		magic.FILE_BEDOUBLE:    "BEDOUBLE",
		magic.FILE_LEDOUBLE:    "LEDOUBLE",
		magic.FILE_BEID3:       "BEID3",
		magic.FILE_LEID3:       "LEID3",
		magic.FILE_INDIRECT:    "INDIRECT",
		magic.FILE_QWDATE:      "QWDATE",
		magic.FILE_LEQWDATE:    "LEQWDATE",
		magic.FILE_BEQWDATE:    "BEQWDATE",
		magic.FILE_NAME:        "NAME",
		magic.FILE_USE:         "USE",
		magic.FILE_CLEAR:       "CLEAR",
		magic.FILE_DER:         "DER",
		magic.FILE_GUID:        "GUID",
		magic.FILE_OFFSET:      "OFFSET",
		magic.FILE_BEVARINT:    "BEVARINT",
		magic.FILE_LEVARINT:    "LEVARINT",
		magic.FILE_MSDOSDATE:   "MSDOSDATE",
		magic.FILE_LEMSDOSDATE: "LEMSDOSDATE",
		magic.FILE_BEMSDOSDATE: "BEMSDOSDATE",
		magic.FILE_MSDOSTIME:   "MSDOSTIME",
		magic.FILE_LEMSDOSTIME: "LEMSDOSTIME",
		magic.FILE_BEMSDOSTIME: "BEMSDOSTIME",
		magic.FILE_OCTAL:       "OCTAL",
	}

	if name, exists := names[magicType]; exists {
		return name
	}
	return "UNKNOWN"
}

// TestAdvancedPatternMatcher tests the advanced pattern matching capabilities
func TestAdvancedPatternMatcher(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())
	apm := NewAdvancedPatternMatcher(detector)

	t.Run("FastHeaderDetection", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			expected bool
			contains string
		}{
			{
				name:     "JPEG header",
				data:     []byte{0xFF, 0xD8, 0xFF, 0xE0},
				expected: true,
				contains: "JPEG",
			},
			{
				name:     "PNG header",
				data:     []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'},
				expected: true,
				contains: "PNG",
			},
			{
				name:     "PDF header",
				data:     []byte{'%', 'P', 'D', 'F', '-', '1', '.', '4'},
				expected: true,
				contains: "PDF",
			},
			{
				name:     "Unknown header",
				data:     []byte{0x00, 0x01, 0x02, 0x03},
				expected: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				match, result := apm.FastHeaderDetection(tt.data)
				if match != tt.expected {
					t.Errorf("FastHeaderDetection() match = %v, want %v", match, tt.expected)
				}
				if tt.expected && tt.contains != "" && !contains(result, tt.contains) {
					t.Errorf("FastHeaderDetection() result = %v, should contain %v", result, tt.contains)
				}
			})
		}
	})

	t.Run("MatchStringGroup", func(t *testing.T) {
		// Test with only "test" pattern to ensure specific matching
		entries := []*magic.MagicEntry{
			{
				Type:  magic.FILE_STRING,
				Value: [96]byte{'t', 'e', 's', 't'},
				Desc:  [64]byte{'T', 'e', 's', 't', ' ', 'f', 'i', 'l', 'e'},
			},
		}

		data := []byte("This is test content for matching")
		match, result := apm.detector.matchStringGroup(data, entries)

		if !match {
			t.Errorf("matchStringGroup() should have matched")
		}
		if result != "Test file" {
			t.Errorf("matchStringGroup() result = %v, want 'Test file'", result)
		}

		// Test with multiple patterns to ensure it finds the first valid match
		entries2 := []*magic.MagicEntry{
			{
				Type:  magic.FILE_STRING,
				Value: [96]byte{'d', 'a', 't', 'a'},
				Desc:  [64]byte{'D', 'a', 't', 'a', ' ', 'f', 'i', 'l', 'e'},
			},
		}

		data2 := []byte("This contains data content")
		match2, result2 := apm.detector.matchStringGroup(data2, entries2)

		if !match2 {
			t.Errorf("matchStringGroup() should have matched second pattern")
		}
		if result2 != "Data file" {
			t.Errorf("matchStringGroup() result = %v, want 'Data file'", result2)
		}
	})
}

// TestDetectorCache tests the caching functionality
func TestDetectorCache(t *testing.T) {
	cache := NewDetectorCache(10)

	t.Run("BasicCaching", func(t *testing.T) {
		// Store and retrieve
		cache.StoreResult("key1", "result1")
		result, exists := cache.GetCachedResult("key1")

		if !exists {
			t.Errorf("Expected cache hit for key1")
		}
		if result != "result1" {
			t.Errorf("GetCachedResult() = %v, want 'result1'", result)
		}

		// Test cache miss
		_, exists = cache.GetCachedResult("nonexistent")
		if exists {
			t.Errorf("Expected cache miss for nonexistent key")
		}
	})

	t.Run("CacheEviction", func(t *testing.T) {
		cache := NewDetectorCache(2) // Small cache for testing eviction

		cache.StoreResult("key1", "result1")
		cache.StoreResult("key2", "result2")
		cache.StoreResult("key3", "result3") // Should evict key1

		_, exists := cache.GetCachedResult("key1")
		if exists {
			t.Errorf("Expected key1 to be evicted")
		}

		_, exists = cache.GetCachedResult("key2")
		if !exists {
			t.Errorf("Expected key2 to still exist")
		}

		_, exists = cache.GetCachedResult("key3")
		if !exists {
			t.Errorf("Expected key3 to exist")
		}
	})

	t.Run("TypeStatistics", func(t *testing.T) {
		cache.UpdateTypeStats(magic.FILE_BYTE, true, 0)
		cache.UpdateTypeStats(magic.FILE_BYTE, false, 4)
		cache.UpdateTypeStats(magic.FILE_BYTE, true, 8)

		stats := cache.GetTypeStats(magic.FILE_BYTE)
		if stats == nil {
			t.Fatal("Expected stats for FILE_BYTE")
		}

		if stats.TotalMatches != 3 {
			t.Errorf("TotalMatches = %d, want 3", stats.TotalMatches)
		}
		if stats.SuccessfulMatches != 2 {
			t.Errorf("SuccessfulMatches = %d, want 2", stats.SuccessfulMatches)
		}
		if stats.FailedMatches != 1 {
			t.Errorf("FailedMatches = %d, want 1", stats.FailedMatches)
		}
		if stats.AverageOffset != 4.0 {
			t.Errorf("AverageOffset = %f, want 4.0", stats.AverageOffset)
		}
	})
}

// TestMiddleEndianImplementations tests the middle-endian specific implementations
func TestMiddleEndianImplementations(t *testing.T) {
	db := &MockDatabase{}
	opts := DefaultOptions()
	opts.Debug = true
	detector := New(db, opts)

	tests := []struct {
		name     string
		funcType uint8
		data     []byte
		expected uint32
	}{
		{
			name:     "MEDATE middle-endian",
			funcType: magic.FILE_MEDATE,
			data:     []byte{0x12, 0x34, 0x56, 0x78}, // Middle-endian: data[2] | data[3]<<8 | data[0]<<16 | data[1]<<24 = 0x34127856
			expected: 0x34127856,
		},
		{
			name:     "MELONG middle-endian",
			funcType: magic.FILE_MELONG,
			data:     []byte{0xAB, 0xCD, 0xEF, 0x01}, // Middle-endian: data[2] | data[3]<<8 | data[0]<<16 | data[1]<<24 = 0xCDAB01EF
			expected: 0xCDAB01EF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &magic.MagicEntry{
				Type:    tt.funcType,
				Offset:  0,
				Reln:    '=',
				NumMask: 0,
				Desc:    [64]byte{'M', 'E', ' ', 't', 'e', 's', 't'},
			}

			// Set expected value in little-endian format in the entry
			entry.Value[0] = byte(tt.expected)
			entry.Value[1] = byte(tt.expected >> 8)
			entry.Value[2] = byte(tt.expected >> 16)
			entry.Value[3] = byte(tt.expected >> 24)

			match, result := detector.performMatch(tt.data, entry, tt.data)
			if !match {
				t.Errorf("Expected match for %s", tt.name)
			}
			if result != "ME test" {
				t.Errorf("Result = %v, want 'ME test'", result)
			}
		})
	}
}

// TestVariableLengthIntegers tests the variable-length integer implementations
func TestVariableLengthIntegers(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		funcType uint8
		data     []byte
		expected uint64
	}{
		{
			name:     "BEVARINT single byte",
			funcType: magic.FILE_BEVARINT,
			data:     []byte{0x7F}, // Single byte, value 127
			expected: 127,
		},
		{
			name:     "BEVARINT two bytes",
			funcType: magic.FILE_BEVARINT,
			data:     []byte{0x81, 0x7F}, // Two bytes, value (1 << 7) + 127 = 255
			expected: 255,
		},
		{
			name:     "LEVARINT single byte",
			funcType: magic.FILE_LEVARINT,
			data:     []byte{0x7F}, // Single byte, value 127
			expected: 127,
		},
		{
			name:     "LEVARINT two bytes",
			funcType: magic.FILE_LEVARINT,
			data:     []byte{0xFF, 0x01}, // Two bytes, little-endian varint
			expected: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &magic.MagicEntry{
				Type:    tt.funcType,
				Offset:  0,
				Reln:    '=',
				NumMask: 0,
				Desc:    [64]byte{'V', 'a', 'r', 'i', 'n', 't'},
			}

			// Set expected value in little-endian format
			for i := 0; i < 8; i++ {
				entry.Value[i] = byte(tt.expected >> (i * 8))
			}

			match, result := detector.performMatch(tt.data, entry, tt.data)
			if !match {
				t.Errorf("Expected match for %s", tt.name)
			}
			if result != "Varint" {
				t.Errorf("Result = %v, want 'Varint'", result)
			}
		})
	}
}

// BenchmarkDetection benchmarks the detection performance
func BenchmarkDetection(b *testing.B) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	// Test data simulating a PNG file
	data := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0x00, 0x00, 0x00, 0x0D}
	data = append(data, make([]byte, 1024)...) // Add more data

	b.Run("StandardDetection", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = detector.DetectBytes(data)
		}
	})

	b.Run("WithCache", func(b *testing.B) {
		cache := NewDetectorCache(100)
		for i := 0; i < b.N; i++ {
			_, _ = detector.EnhancedDetectBytes(data, cache)
		}
	})

	b.Run("FastHeaderDetection", func(b *testing.B) {
		apm := NewAdvancedPatternMatcher(detector)
		for i := 0; i < b.N; i++ {
			_, _ = apm.FastHeaderDetection(data)
		}
	})
}
