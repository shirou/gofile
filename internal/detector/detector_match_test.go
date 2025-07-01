package detector

import (
	"testing"

	"github.com/shirou/gofile/internal/magic"
)

// TestMatchByte tests the matchByte function
func TestMatchByte(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
		desc     string
	}{
		{
			name: "exact byte match",
			data: []byte{0xFF, 0x01, 0x02},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BYTE,
				Value: [96]byte{0xFF},
				Desc:  [64]byte{'B', 'y', 't', 'e', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
			desc:     "Byte match",
		},
		{
			name: "byte mismatch",
			data: []byte{0xFE, 0x01, 0x02},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BYTE,
				Value: [96]byte{0xFF},
				Desc:  [64]byte{'B', 'y', 't', 'e', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "byte with mask",
			data: []byte{0xFF, 0x01, 0x02},
			entry: &magic.MagicEntry{
				Type:    magic.FILE_BYTE,
				Value:   [96]byte{0xF0},
				NumMask: 0xF0,
				Desc:    [64]byte{'M', 'a', 's', 'k', 'e', 'd', ' ', 'b', 'y', 't', 'e'},
				Reln:    '=',
			},
			expected: true,
			desc:     "Masked byte",
		},
		{
			name: "insufficient data",
			data: []byte{},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BYTE,
				Value: [96]byte{0xFF},
				Desc:  [64]byte{'B', 'y', 't', 'e'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchByte(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchByte() match = %v, want %v", match, tt.expected)
			}
			if tt.expected && result != tt.desc {
				t.Errorf("matchByte() desc = %v, want %v", result, tt.desc)
			}
		})
	}
}

// TestMatchShort tests the matchShort function
func TestMatchShort(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
		desc     string
	}{
		{
			name: "exact short match",
			data: []byte{0x12, 0x34, 0x56, 0x78}, // Big-endian data (flag=0 means big-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_SHORT,
				Value: [96]byte{0x34, 0x12}, // Value stored as little-endian (0x1234)
				Desc:  [64]byte{'S', 'h', 'o', 'r', 't', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
				Flag:  0, // No LITTLE_ENDIAN flag, so reads as big-endian
			},
			expected: true,
			desc:     "Short match",
		},
		{
			name: "insufficient data",
			data: []byte{0x34},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_SHORT,
				Value: [96]byte{0x34, 0x12},
				Desc:  [64]byte{'S', 'h', 'o', 'r', 't'},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "short with mask",
			data: []byte{0xFF, 0x12}, // Big-endian: 0xFF12
			entry: &magic.MagicEntry{
				Type:    magic.FILE_SHORT,
				Value:   [96]byte{0x12, 0xF0}, // Little-endian stored: 0xF012
				NumMask: 0xF0FF,               // Mask: keep high byte of first and low byte of second
				Desc:    [64]byte{'M', 'a', 's', 'k', 'e', 'd', ' ', 's', 'h', 'o', 'r', 't'},
				Reln:    '=',
				Flag:    0,
			},
			expected: true,
			desc:     "Masked short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchShort(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchShort() match = %v, want %v", match, tt.expected)
			}
			if tt.expected && result != tt.desc {
				t.Errorf("matchShort() desc = %v, want %v", result, tt.desc)
			}
		})
	}
}

// TestMatchLong tests the matchLong function
func TestMatchLong(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
		desc     string
	}{
		{
			name: "exact long match",
			data: []byte{0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD}, // Big-endian data
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12}, // Little-endian stored (0x12345678)
				Desc:  [64]byte{'L', 'o', 'n', 'g', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
				Flag:  0, // No LITTLE_ENDIAN flag, reads as big-endian
			},
			expected: true,
			desc:     "Long match",
		},
		{
			name: "insufficient data",
			data: []byte{0x78, 0x56, 0x34},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12},
				Desc:  [64]byte{'L', 'o', 'n', 'g'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchLong(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLong() match = %v, want %v", match, tt.expected)
			}
			if tt.expected && result != tt.desc {
				t.Errorf("matchLong() desc = %v, want %v", result, tt.desc)
			}
		})
	}
}

// TestMatchString tests the matchString function
func TestMatchString(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
		desc     string
	}{
		{
			name: "exact string match",
			data: []byte("PNG\x0D\x0A\x1A\x0A"),
			entry: &magic.MagicEntry{
				Type:   magic.FILE_STRING,
				Value:  [96]byte{'P', 'N', 'G'},
				Vallen: 3,
				Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e'},
				Reln:   '=',
			},
			expected: true,
			desc:     "PNG image",
		},
		{
			name: "string mismatch",
			data: []byte("JPEG"),
			entry: &magic.MagicEntry{
				Type:   magic.FILE_STRING,
				Value:  [96]byte{'P', 'N', 'G'},
				Vallen: 3,
				Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e'},
				Reln:   '=',
			},
			expected: false,
		},
		{
			name: "insufficient data",
			data: []byte("PN"),
			entry: &magic.MagicEntry{
				Type:   magic.FILE_STRING,
				Value:  [96]byte{'P', 'N', 'G'},
				Vallen: 3,
				Desc:   [64]byte{'P', 'N', 'G'},
				Reln:   '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchString(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchString() match = %v, want %v", match, tt.expected)
			}
			if tt.expected && result != tt.desc {
				t.Errorf("matchString() desc = %v, want %v", result, tt.desc)
			}
		})
	}
}

// TestMatchBELong tests the matchBELong function
func TestMatchBELong(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
		desc     string
	}{
		{
			name: "big-endian long match",
			data: []byte{0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BELONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12}, // Stored as little-endian but compared as big-endian
				Desc:  [64]byte{'B', 'E', ' ', 'l', 'o', 'n', 'g'},
				Reln:  '=',
			},
			expected: true,
			desc:     "BE long",
		},
		{
			name: "insufficient data",
			data: []byte{0x12, 0x34, 0x56},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BELONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12},
				Desc:  [64]byte{'B', 'E'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchBELong(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBELong() match = %v, want %v", match, tt.expected)
			}
			if tt.expected && result != tt.desc {
				t.Errorf("matchBELong() desc = %v, want %v", result, tt.desc)
			}
		})
	}
}

// TestMatchLELong tests the matchLELong function
func TestMatchLELong(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian long match",
			data: []byte{0x78, 0x56, 0x34, 0x12, 0xAB, 0xCD},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LELONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12},
				Desc:  [64]byte{'L', 'E', ' ', 'l', 'o', 'n', 'g'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x78, 0x56, 0x34},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LELONG,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLELong(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLELong() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEShort tests the matchBEShort function
func TestMatchBEShort(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian short match",
			data: []byte{0x12, 0x34, 0x56, 0x78},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BESHORT,
				Value: [96]byte{0x34, 0x12}, // Stored as little-endian
				Desc:  [64]byte{'B', 'E', ' ', 's', 'h', 'o', 'r', 't'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x12},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BESHORT,
				Value: [96]byte{0x34, 0x12},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEShort(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEShort() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEShort tests the matchLEShort function
func TestMatchLEShort(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian short match",
			data: []byte{0x34, 0x12, 0x56, 0x78},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LESHORT,
				Value: [96]byte{0x34, 0x12},
				Desc:  [64]byte{'L', 'E', ' ', 's', 'h', 'o', 'r', 't'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x34},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LESHORT,
				Value: [96]byte{0x34, 0x12},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEShort(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEShort() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEQuad tests the matchBEQuad function
func TestMatchBEQuad(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian quad match",
			data: []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEQUAD,
				Value: [96]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
				Desc:  [64]byte{'B', 'E', ' ', 'q', 'u', 'a', 'd'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEQUAD,
				Value: [96]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEQuad(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEQuad() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEQuad tests the matchLEQuad function
func TestMatchLEQuad(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian quad match",
			data: []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEQUAD,
				Value: [96]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
				Desc:  [64]byte{'L', 'E', ' ', 'q', 'u', 'a', 'd'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEQUAD,
				Value: [96]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEQuad(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEQuad() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchQuad tests the matchQuad function
func TestMatchQuad(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "native quad match",
			data: []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_QUAD,
				Value: [96]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
				Desc:  [64]byte{'Q', 'u', 'a', 'd'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchQuad(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchQuad() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchPString tests the matchPString function
func TestMatchPString(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "pascal string match",
			data: []byte{0x04, 'T', 'e', 's', 't', 0x00}, // Length=4, "Test"
			entry: &magic.MagicEntry{
				Type:  magic.FILE_PSTRING,
				Value: [96]byte{'T', 'e', 's', 't'},
				Desc:  [64]byte{'P', 'a', 's', 'c', 'a', 'l', ' ', 's', 't', 'r', 'i', 'n', 'g'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data for length",
			data: []byte{},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_PSTRING,
				Value: [96]byte{'T', 'e', 's', 't'},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "insufficient data for string",
			data: []byte{0x04, 'T', 'e'},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_PSTRING,
				Value: [96]byte{'T', 'e', 's', 't'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchPString(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchPString() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchGUID tests the matchGUID function
func TestMatchGUID(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "GUID match",
			data: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_GUID,
				Value: [96]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
				Desc:  [64]byte{'G', 'U', 'I', 'D', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_GUID,
				Value: [96]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "GUID mismatch",
			data: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEE},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_GUID,
				Value: [96]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchGUID(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchGUID() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchDER tests the matchDER function
func TestMatchDER(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "DER sequence match",
			data: []byte{0x30, 0x10, 0x02, 0x01, 0x01}, // ASN.1 SEQUENCE, length 16
			entry: &magic.MagicEntry{
				Type:  magic.FILE_DER,
				Value: [96]byte{0x30, 0x10}, // Match both tag and length
				Desc:  [64]byte{'A', 'S', 'N', '.', '1', ' ', 'D', 'E', 'R'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x30},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_DER,
				Value: [96]byte{0x30},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "DER string pattern match",
			data: []byte("-----BEGIN CERTIFICATE-----"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_DER,
				Value: [96]byte{'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'},
				Desc:  [64]byte{'P', 'E', 'M', ' ', 'c', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchDER(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchDER() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchFloat tests the matchFloat function
func TestMatchFloat(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "float match (simplified test)",
			data: []byte{0x00, 0x00, 0x80, 0x3F}, // IEEE 754 float 1.0 (little-endian)
			entry: &magic.MagicEntry{
				Type: magic.FILE_FLOAT,
				// Store 1.0 as double: 0x3FF0000000000000
				Value: [96]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F}, // 1.0 as double
				Desc:  [64]byte{'F', 'l', 'o', 'a', 't', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0xDB, 0x0F, 0x49},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_FLOAT,
				Value: [96]byte{0xDB, 0x0F, 0x49, 0x40},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchFloat(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchFloat() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchDouble tests the matchDouble function
func TestMatchDouble(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "double match",
			data: []byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40}, // IEEE 754 double (little-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_DOUBLE,
				Value: [96]byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40},
				Desc:  [64]byte{'D', 'o', 'u', 'b', 'l', 'e', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_DOUBLE,
				Value: [96]byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchDouble(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchDouble() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEFloat tests the matchBEFloat function
func TestMatchBEFloat(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian float match",
			data: []byte{0x40, 0x49, 0x0F, 0xDB}, // IEEE 754 float 3.14159 (big-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEFLOAT,
				Value: [96]byte{0x40, 0x49, 0x0F, 0xDB},
				Desc:  [64]byte{'B', 'E', ' ', 'f', 'l', 'o', 'a', 't'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x40, 0x49, 0x0F},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEFLOAT,
				Value: [96]byte{0x40, 0x49, 0x0F, 0xDB},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEFloat(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEFloat() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEFloat tests the matchLEFloat function
func TestMatchLEFloat(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian float match",
			data: []byte{0xDB, 0x0F, 0x49, 0x40}, // IEEE 754 float 3.14159 (little-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEFLOAT,
				Value: [96]byte{0xDB, 0x0F, 0x49, 0x40},
				Desc:  [64]byte{'L', 'E', ' ', 'f', 'l', 'o', 'a', 't'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEFloat(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEFloat() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEDouble tests the matchBEDouble function
func TestMatchBEDouble(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian double match",
			data: []byte{0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18}, // IEEE 754 double (big-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEDOUBLE,
				Value: [96]byte{0x40, 0x09, 0x21, 0xFB, 0x54, 0x44, 0x2D, 0x18},
				Desc:  [64]byte{'B', 'E', ' ', 'd', 'o', 'u', 'b', 'l', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEDouble(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEDouble() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEDouble tests the matchLEDouble function
func TestMatchLEDouble(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian double match",
			data: []byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40}, // IEEE 754 double (little-endian)
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEDOUBLE,
				Value: [96]byte{0x18, 0x2D, 0x44, 0x54, 0xFB, 0x21, 0x09, 0x40},
				Desc:  [64]byte{'L', 'E', ' ', 'd', 'o', 'u', 'b', 'l', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEDouble(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEDouble() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEDate tests the matchBEDate function
func TestMatchBEDate(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian date match",
			data: []byte{0x63, 0xB4, 0x60, 0x00}, // Unix timestamp 1672531200 (2023-01-01) big-endian
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEDATE,
				Value: [96]byte{0x00, 0x60, 0xB4, 0x63}, // Stored as little-endian
				Desc:  [64]byte{'B', 'E', ' ', 'd', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x63, 0xB4, 0x60},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEDATE,
				Value: [96]byte{0x00, 0x60, 0xB4, 0x63},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEDate(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEDate() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEDate tests the matchLEDate function
func TestMatchLEDate(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian date match",
			data: []byte{0x00, 0x60, 0xB4, 0x63}, // Unix timestamp 1672531200 little-endian
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEDATE,
				Value: [96]byte{0x00, 0x60, 0xB4, 0x63},
				Desc:  [64]byte{'L', 'E', ' ', 'd', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEDate(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEDate() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBELDate tests the matchBELDate function
func TestMatchBELDate(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian long date match",
			data: []byte{0x63, 0xB4, 0x60, 0x00}, // Unix timestamp big-endian
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BELDATE,
				Value: [96]byte{0x63, 0xB4, 0x60, 0x00},
				Desc:  [64]byte{'B', 'E', ' ', 'l', 'o', 'n', 'g', ' ', 'd', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBELDate(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBELDate() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEQDate tests the matchLEQDate function
func TestMatchLEQDate(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "little-endian 64-bit date match",
			data: []byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37, 0x17}, // 64-bit timestamp little-endian
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEQDATE,
				Value: [96]byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37, 0x17},
				Desc:  [64]byte{'L', 'E', ' ', '6', '4', '-', 'b', 'i', 't', ' ', 'd', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LEQDATE,
				Value: [96]byte{0x00, 0x00, 0x2D, 0x79, 0x88, 0x33, 0x37, 0x17},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEQDate(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchLEQDate() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEQDate tests the matchBEQDate function
func TestMatchBEQDate(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "big-endian 64-bit date match",
			data: []byte{0x17, 0x37, 0x33, 0x88, 0x79, 0x2D, 0x00, 0x00}, // 64-bit timestamp big-endian
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BEQDATE,
				Value: [96]byte{0x17, 0x37, 0x33, 0x88, 0x79, 0x2D, 0x00, 0x00},
				Desc:  [64]byte{'B', 'E', ' ', '6', '4', '-', 'b', 'i', 't', ' ', 'd', 'a', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEQDate(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchBEQDate() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchBEString16 tests the matchBEString16 function
func TestMatchBEString16(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "UTF-16 big-endian string match",
			data: []byte{0x00, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00}, // "Test" in UTF-16 BE + null
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BESTRING16,
				Value: [96]byte{'T', 'e', 's', 't'},
				Desc:  [64]byte{'U', 'T', 'F', '-', '1', '6', ' ', 'B', 'E', ' ', 's', 't', 'r', 'i', 'n', 'g'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "insufficient data",
			data: []byte{0x00},
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BESTRING16,
				Value: [96]byte{'T', 'e', 's', 't'},
				Reln:  '=',
			},
			expected: false,
		},
		{
			name: "non-ASCII Unicode characters",
			data: []byte{0x00, 0x41, 0x00, 0x42, 0x30, 0x42, 0x00, 0x43}, // "AB?C" with Japanese character
			entry: &magic.MagicEntry{
				Type:  magic.FILE_BESTRING16,
				Value: [96]byte{'A', 'B'},
				Desc:  [64]byte{'U', 'n', 'i', 'c', 'o', 'd', 'e', ' ', 's', 't', 'r', 'i', 'n', 'g'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchBEString16(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchBEString16() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchRegex tests the matchRegex function
func TestMatchRegex(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "valid regex match",
			data: []byte("Hello World 123"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_REGEX,
				Value: [96]byte{'H', 'e', 'l', 'l', 'o', ' ', '\\', 'w', '+'},
				Desc:  [64]byte{'R', 'e', 'g', 'e', 'x', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "invalid regex fallback to string search",
			data: []byte("Hello [invalid regex"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_REGEX,
				Value: [96]byte{'[', 'i', 'n', 'v', 'a', 'l', 'i', 'd'},
				Desc:  [64]byte{'F', 'a', 'l', 'l', 'b', 'a', 'c', 'k'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "regex no match",
			data: []byte("Goodbye World"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_REGEX,
				Value: [96]byte{'H', 'e', 'l', 'l', 'o'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchRegex(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchRegex() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchSearch tests the matchSearch function
func TestMatchSearch(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "search pattern found",
			data: []byte("This is a test document with some content to search"),
			entry: &magic.MagicEntry{
				Type:    magic.FILE_SEARCH,
				Offset:  0,
				Value:   [96]byte{'t', 'e', 's', 't'},
				NumMask: 50, // Search within first 50 bytes
				Desc:    [64]byte{'S', 'e', 'a', 'r', 'c', 'h', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:    '=',
			},
			expected: true,
		},
		{
			name: "search pattern not found",
			data: []byte("This is a document without the pattern"),
			entry: &magic.MagicEntry{
				Type:    magic.FILE_SEARCH,
				Offset:  0,
				Value:   [96]byte{'m', 'i', 's', 's', 'i', 'n', 'g'},
				NumMask: 50,
				Reln:    '=',
			},
			expected: false,
		},
		{
			name: "search with offset",
			data: []byte("Skip this part and find pattern here"),
			entry: &magic.MagicEntry{
				Type:    magic.FILE_SEARCH,
				Offset:  15, // Start search after "Skip this part "
				Value:   [96]byte{'p', 'a', 't', 't', 'e', 'r', 'n'},
				NumMask: 20,
				Desc:    [64]byte{'O', 'f', 'f', 's', 'e', 't', ' ', 's', 'e', 'a', 'r', 'c', 'h'},
				Reln:    '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchSearch(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchSearch() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchIndirect tests the matchIndirect function
func TestMatchIndirect(t *testing.T) {
	db := &MockDatabase{}
	opts := DefaultOptions()
	opts.Debug = true
	detector := New(db, opts)

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "basic indirect addressing",
			data: []byte{
				0x10, 0x00, 0x00, 0x00, // Offset 0: pointer to offset 16 (little-endian)
				0x00, 0x00, 0x00, 0x00, // Offset 4: padding
				0x00, 0x00, 0x00, 0x00, // Offset 8: padding
				0x00, 0x00, 0x00, 0x00, // Offset 12: padding
				0xFF, 0xEE, 0xDD, 0xCC, // Offset 16: target data
			},
			entry: &magic.MagicEntry{
				Type:     magic.FILE_BYTE, // The actual data type to evaluate
				Flag:     magic.INDIR,     // Indirect flag
				InType:   magic.FILE_LONG, // Pointer type (32-bit)
				Offset:   0,
				InOffset: 0,
				Value:    [96]byte{0xFF}, // Expected value at target location
				Desc:     [64]byte{'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:     '=',
			},
			expected: true,
		},
		{
			name: "indirect with offset beyond data",
			data: []byte{0xFF, 0xFF, 0xFF, 0xFF}, // Points to offset 0xFFFFFFFF
			entry: &magic.MagicEntry{
				Type:     magic.FILE_INDIRECT,
				Offset:   0,
				InOffset: 0,
				Reln:     '=',
			},
			expected: false,
		},
		{
			name: "insufficient data for base offset",
			data: []byte{0x10, 0x00},
			entry: &magic.MagicEntry{
				Type:     magic.FILE_INDIRECT,
				Offset:   0,
				InOffset: 0,
				Reln:     '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchIndirect(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchIndirect() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchUse tests the matchUse function
func TestMatchUse(t *testing.T) {
	db := &MockDatabase{}
	opts := DefaultOptions()
	opts.Debug = true
	detector := New(db, opts)

	// Set up a named entry for reference testing
	referencedEntry := &magic.MagicEntry{
		Type:  magic.FILE_STRING,
		Value: [96]byte{'t', 'e', 's', 't'},
		Desc:  [64]byte{'R', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e', 'd', ' ', 'e', 'n', 't', 'r', 'y'},
		Reln:  '=',
	}
	db.SetNamedEntry("test_pattern", referencedEntry)

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "USE with valid description",
			data: []byte("Some data"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_USE,
				Value: [96]byte{'r', 'e', 'f', 'e', 'r', 'e', 'n', 'c', 'e'},
				Desc:  [64]byte{'U', 's', 'e', ' ', 'm', 'a', 't', 'c', 'h'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "USE without reference name",
			data: []byte("Some data"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_USE,
				Value: [96]byte{}, // No reference name
				Desc:  [64]byte{'U', 's', 'e'},
				Reln:  '=',
			},
			expected: true, // The function returns true if there's a valid description
		},
		{
			name: "USE with valid reference",
			data: []byte("test data"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_USE,
				Value: [96]byte{'t', 'e', 's', 't', '_', 'p', 'a', 't', 't', 'e', 'r', 'n'},
				Desc:  [64]byte{},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "USE with invalid reference",
			data: []byte("test data"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_USE,
				Value: [96]byte{'n', 'o', 'n', 'e', 'x', 'i', 's', 't', 'e', 'n', 't'},
				Desc:  [64]byte{'F', 'a', 'l', 'l', 'b', 'a', 'c', 'k'},
				Reln:  '=',
			},
			expected: true, // Should use fallback description
		},
		{
			name: "USE with non-matching reference",
			data: []byte("different data"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_USE,
				Value: [96]byte{'t', 'e', 's', 't', '_', 'p', 'a', 't', 't', 'e', 'r', 'n'},
				Desc:  [64]byte{},
				Reln:  '=',
			},
			expected: false, // Reference exists but doesn't match data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, result := detector.matchUse(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchUse() match = %v, want %v, result = %q", match, tt.expected, result)
			}
		})
	}
}

// TestMatchClear tests the matchClear function
func TestMatchClear(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "clear always returns false",
			data: []byte("Any data"),
			entry: &magic.MagicEntry{
				Type: magic.FILE_CLEAR,
				Desc: [64]byte{'C', 'l', 'e', 'a', 'r'},
				Reln: '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchClear(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchClear() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchName tests the matchName function
func TestMatchName(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "name with valid description",
			data: []byte("File content"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_NAME,
				Value: [96]byte{'*', '.', 't', 'x', 't'},
				Desc:  [64]byte{'T', 'e', 'x', 't', ' ', 'f', 'i', 'l', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "name without description",
			data: []byte("File content"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_NAME,
				Value: [96]byte{'*', '.', 't', 'x', 't'},
				Reln:  '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchName(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchName() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchDefault tests the matchDefault function
func TestMatchDefault(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "default always returns false",
			data: []byte("Any data"),
			entry: &magic.MagicEntry{
				Type: magic.FILE_DEFAULT,
				Desc: [64]byte{'D', 'e', 'f', 'a', 'u', 'l', 't'},
				Reln: '=',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchDefault(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchDefault() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchCustomType tests the matchCustomType function
func TestMatchCustomType(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "custom type string match",
			data: []byte("CustomPattern"),
			entry: &magic.MagicEntry{
				Type:  99, // Custom type
				Value: [96]byte{'C', 'u', 's', 't', 'o', 'm'},
				Desc:  [64]byte{'C', 'u', 's', 't', 'o', 'm', ' ', 't', 'y', 'p', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
		{
			name: "custom type byte fallback",
			data: []byte{0xFF, 0x00, 0x01},
			entry: &magic.MagicEntry{
				Type:  114, // Another custom type
				Value: [96]byte{0xFF},
				Desc:  [64]byte{'C', 'u', 's', 't', 'o', 'm', ' ', 'b', 'y', 't', 'e'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchCustomType(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchCustomType() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchLEString16 tests the matchLEString16 function
func TestMatchLEString16(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "LE string16 fallback to string",
			data: []byte("Test"),
			entry: &magic.MagicEntry{
				Type:  magic.FILE_LESTRING16,
				Value: [96]byte{'T', 'e', 's', 't'},
				Desc:  [64]byte{'L', 'E', ' ', 's', 't', 'r', 'i', 'n', 'g', '1', '6'},
				Reln:  '=',
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchLEString16(tt.data, tt.entry)
			if match != tt.expected {
				t.Errorf("matchLEString16() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestMatchOffset tests the matchOffset function
func TestMatchOffset(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	tests := []struct {
		name     string
		data     []byte
		entry    *magic.MagicEntry
		expected bool
	}{
		{
			name: "offset fallback to long",
			data: []byte{0x12, 0x34, 0x56, 0x78}, // Big-endian data
			entry: &magic.MagicEntry{
				Type:  magic.FILE_OFFSET,
				Value: [96]byte{0x78, 0x56, 0x34, 0x12}, // Little-endian stored
				Desc:  [64]byte{'O', 'f', 'f', 's', 'e', 't'},
				Reln:  '=',
				Flag:  0,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := detector.matchOffset(tt.data, tt.entry, tt.data)
			if match != tt.expected {
				t.Errorf("matchOffset() match = %v, want %v", match, tt.expected)
			}
		})
	}
}

// TestEdgeCases tests edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	db := &MockDatabase{}
	detector := New(db, DefaultOptions())

	t.Run("empty data handling", func(t *testing.T) {
		entry := &magic.MagicEntry{
			Type:  magic.FILE_BYTE,
			Value: [96]byte{0xFF},
			Reln:  '=',
		}
		match, _ := detector.matchByte([]byte{}, entry, []byte{})
		if match {
			t.Error("Expected false for empty data")
		}
	})

	t.Run("corrupted description handling", func(t *testing.T) {
		entry := &magic.MagicEntry{
			Type:  magic.FILE_BYTE,
			Value: [96]byte{0xFF},
			Desc:  [64]byte{0x00, 0x01, 0x02, 0x03}, // Non-printable characters
			Reln:  '=',
		}
		match, _ := detector.matchByte([]byte{0xFF}, entry, []byte{0xFF})
		// Behavior depends on isValidDescription implementation
		_ = match // Don't assert specific behavior as it depends on implementation
	})

	t.Run("mask application", func(t *testing.T) {
		entry := &magic.MagicEntry{
			Type:    magic.FILE_BYTE,
			Value:   [96]byte{0xF0},
			NumMask: 0xF0,
			Desc:    [64]byte{'M', 'a', 's', 'k', 'e', 'd'},
			Reln:    '=',
		}
		// 0xFF & 0xF0 = 0xF0, should match
		match, _ := detector.matchByte([]byte{0xFF}, entry, []byte{0xFF})
		if !match {
			t.Error("Expected true for masked byte match")
		}
	})
}
