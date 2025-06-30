package detector

import "testing"

func TestDetector_CompareValues(t *testing.T) {

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
			result := compareValues(tt.actual, tt.expected, tt.relation)
			if result != tt.want {
				t.Errorf("compareValues(%d, %d, %c) = %v, want %v",
					tt.actual, tt.expected, tt.relation, result, tt.want)
			}
		})
	}
}

func TestDetector_ReadIntegers(t *testing.T) {
	// Test data: 0x12345678 in both endian formats
	bigEndian := []byte{0x12, 0x34, 0x56, 0x78}
	littleEndian := []byte{0x78, 0x56, 0x34, 0x12}

	// Test 16-bit reads
	t.Run("uint16 big endian", func(t *testing.T) {
		result := readUint16(bigEndian, false)
		expected := uint16(0x1234)
		if result != expected {
			t.Errorf("readUint16(bigEndian) = 0x%04X, want 0x%04X", result, expected)
		}
	})

	t.Run("uint16 little endian", func(t *testing.T) {
		result := readUint16(littleEndian, true)
		expected := uint16(0x5678)
		if result != expected {
			t.Errorf("readUint16(littleEndian) = 0x%04X, want 0x%04X", result, expected)
		}
	})

	// Test 32-bit reads
	t.Run("uint32 big endian", func(t *testing.T) {
		result := readUint32(bigEndian, false)
		expected := uint32(0x12345678)
		if result != expected {
			t.Errorf("readUint32(bigEndian) = 0x%08X, want 0x%08X", result, expected)
		}
	})

	t.Run("uint32 little endian", func(t *testing.T) {
		result := readUint32(littleEndian, true)
		expected := uint32(0x12345678)
		if result != expected {
			t.Errorf("readUint32(littleEndian) = 0x%08X, want 0x%08X", result, expected)
		}
	})
}

func TestDetector_DescriptionToMIME(t *testing.T) {

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
			result := descriptionToMIME(tt.desc)
			if result != tt.expected {
				t.Errorf("descriptionToMIME(%q) = %q, want %q", tt.desc, result, tt.expected)
			}
		})
	}
}

func TestDetector_MakeBrief(t *testing.T) {

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
			result := makeBrief(tt.desc)
			if result != tt.expected {
				t.Errorf("makeBrief(%q) = %q, want %q", tt.desc, result, tt.expected)
			}
		})
	}
}

func TestDetector_FloatComparison(t *testing.T) {

	// Test floating-point comparison functions
	t.Run("compareFloats", func(t *testing.T) {
		tests := []struct {
			name     string
			actual   float64
			expected float64
			relation byte
			want     bool
		}{
			{"Equal floats", 3.14159, 3.14159, '=', true},
			{"Equal floats default", 3.14159, 3.14159, 0, true},
			{"Not equal floats", 3.14159, 2.71828, '!', true},
			{"Less than floats", 2.71828, 3.14159, '<', true},
			{"Greater than floats", 3.14159, 2.71828, '>', true},
			{"Equal floats false", 3.14159, 2.71828, '=', false},
			{"Not equal floats false", 3.14159, 3.14159, '!', false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := compareFloats(tt.actual, tt.expected, tt.relation)
				if result != tt.want {
					t.Errorf("compareFloats(%f, %f, %c) = %v, want %v",
						tt.actual, tt.expected, tt.relation, result, tt.want)
				}
			})
		}
	})
}
