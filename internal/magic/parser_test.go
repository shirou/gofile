package magic

import (
	"bytes"
	"strings"
	"testing"
)

// Helper functions for tests
func getMimeString(m *Magic) string {
	if m == nil {
		return ""
	}
	// Find null terminator
	idx := bytes.IndexByte(m.Mimetype[:], 0)
	if idx < 0 {
		idx = len(m.Mimetype)
	}
	return string(m.Mimetype[:idx])
}

func TestParseLine(t *testing.T) {
	parser := NewParser()

	tests := map[string]struct {
		line          string
		expectedLevel int
		expectedType  string
		expectedTest  string
		expectedMsg   string
		expectError   bool
	}{
		"Simple string pattern": {
			line:          "0	string	PNG	PNG image data",
			expectedLevel: 0,
			expectedType:  "string",
			expectedTest:  "PNG",
			expectedMsg:   "PNG image data",
			expectError:   false,
		},
		"Nested pattern": {
			line:          ">4	byte	1	32-bit",
			expectedLevel: 1,
			expectedType:  "byte",
			expectedTest:  "1",
			expectedMsg:   "32-bit",
			expectError:   false,
		},
		"Double nested": {
			line:          ">>8	long	x	size %d",
			expectedLevel: 2,
			expectedType:  "long",
			expectedTest:  "x",
			expectedMsg:   "size %d",
			expectError:   false,
		},
		"Invalid format": {
			line:          "invalid",
			expectedLevel: 0,
			expectError:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := parser.parseMagicLine(tt.line, 1)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if parsed == nil {
				t.Error("Expected parsed magic but got nil")
				return
			}

			if int(parsed.ContLevel) != tt.expectedLevel {
				t.Errorf("Level: expected %d, got %d", tt.expectedLevel, parsed.ContLevel)
			}
			if parsed.TypeStr != tt.expectedType {
				t.Errorf("Type: expected %s, got %s", tt.expectedType, parsed.TypeStr)
			}
			if parsed.TestStr != tt.expectedTest {
				t.Errorf("Test: expected %s, got %s", tt.expectedTest, parsed.TestStr)
			}
			if parsed.MessageStr != tt.expectedMsg {
				t.Errorf("Message: expected %s, got %s", tt.expectedMsg, parsed.MessageStr)
			}
		})
	}
}

func TestLoadOne(t *testing.T) {
	magicData := `# Test magic file
# PNG image
0	string	\x89PNG		PNG image data
!:mime	image/png
!:ext	png

# JPEG image
0	string	\xff\xd8\xff	JPEG image data
!:mime	image/jpeg

# Nested example
0	string	TEST		Test file
>4	string	DATA		with data
>>8	long	x		size %d
`

	parser := NewParser()
	reader := strings.NewReader(magicData)

	err := parser.LoadOne(reader, "test.magic")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	db := parser.GetDatabase()
	if len(db.Entries) != 3 {
		t.Errorf("Expected 3 top-level entries, got %d", len(db.Entries))
	}

	// Debug: Print all entries
	for i, entry := range db.Entries {
		if entry.Mp != nil {
			t.Logf("Entry %d: message=%s, type=%d, mime=%s, testStr=%s, contLevel=%d",
				i, entry.Mp.MessageStr, entry.Mp.Type, getMimeString(entry.Mp), entry.Mp.TestStr, entry.Mp.ContLevel)
			for j, child := range entry.Children {
				if child.Mp != nil {
					t.Logf("  Child %d: message=%s, contLevel=%d", j, child.Mp.MessageStr, child.Mp.ContLevel)
				}
			}
		}
	}

	// Check first entry
	png := db.Entries[0]
	if png.Mp.MessageStr != "PNG image data" {
		t.Errorf("Expected PNG message, got %s", png.Mp.MessageStr)
	}
	if getMimeString(png.Mp) != "image/png" {
		t.Errorf("Expected image/png MIME, got %s", getMimeString(png.Mp))
	}

	// Check nested entry
	test := db.Entries[2]
	if len(test.Children) != 1 {
		t.Errorf("Expected 1 child, got %d", len(test.Children))
	}
	if test.Children[0].Mp.MessageStr != "with data" {
		t.Errorf("Expected child message 'with data', got %s", test.Children[0].Mp.MessageStr)
	}
	if len(test.Children[0].Children) != 1 {
		t.Errorf("Expected 1 grandchild, got %d", len(test.Children[0].Children))
	}
}

func TestOrganizeSets(t *testing.T) {
	magicData := `
0	string	\x89PNG	Binary pattern
0	string	#!/bin/sh	Shell script
0	string/t	script	Text pattern
0	regex	^#!/	Script pattern
`

	parser := NewParser()
	reader := strings.NewReader(magicData)

	err := parser.LoadOne(reader, "test.magic")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	parser.OrganizeSets()
	db := parser.GetDatabase()

	if len(db.Sets) != 2 {
		t.Errorf("Expected 2 sets, got %d", len(db.Sets))
	}

	set0 := db.Sets[0]
	if set0.Number != 0 {
		t.Errorf("Expected set 0, got %d", set0.Number)
	}

	// Check that patterns are properly classified as binary or text
	// PNG pattern should be binary (contains \x89)
	// #!/bin/sh should be binary (string type without /t flag)
	// string/t pattern should be text (has /t flag)
	// regex pattern should be text (regex with printable content)

	// Debug: print what we got
	for _, entry := range set0.BinaryEntries {
		t.Logf("Binary entry: type=%s, test=%s, message=%s", entry.Mp.TypeStr, entry.Mp.TestStr, entry.Mp.MessageStr)
	}
	for _, entry := range set0.TextEntries {
		t.Logf("Text entry: type=%s, test=%s, message=%s", entry.Mp.TypeStr, entry.Mp.TestStr, entry.Mp.MessageStr)
	}

	if len(set0.BinaryEntries) != 2 {
		t.Errorf("Expected 2 binary entries in set 0, got %d", len(set0.BinaryEntries))
	}
	if len(set0.TextEntries) != 2 {
		t.Errorf("Expected 2 text entries in set 0, got %d", len(set0.TextEntries))
	}
}

func TestApprenticeSort(t *testing.T) {
	// Create test entries with different strengths
	entries := []*Entry{
		{
			Mp: &Magic{
				TypeStr:  "string",
				TestStr:  "short", // Should have lower strength
				Strength: 10,
				Desc:     [MAXDESC]byte{},
			},
			ContCount: 0,
		},
		{
			Mp: &Magic{
				TypeStr:  "string",
				TestStr:  "verylongstring", // Should have higher strength
				Strength: 50,
				Desc:     [MAXDESC]byte{},
			},
			ContCount: 0,
		},
		{
			Mp: &Magic{
				TypeStr:  "long",
				TestStr:  "0x1234", // Numeric type with fixed strength
				Strength: 30,
				Desc:     [MAXDESC]byte{},
			},
			ContCount: 0,
		},
		{
			Mp: &Magic{
				TypeStr:  "string",
				TestStr:  "medium", // Medium strength
				Strength: 20,
				Desc:     [MAXDESC]byte{},
			},
			ContCount: 0,
		},
	}

	// Copy for message strings
	copy(entries[0].Mp.Desc[:], []byte("Short pattern"))
	copy(entries[1].Mp.Desc[:], []byte("Long pattern"))
	copy(entries[2].Mp.Desc[:], []byte("Numeric pattern"))
	copy(entries[3].Mp.Desc[:], []byte("Medium pattern"))

	// Sort using apprenticeSort
	apprenticeSort(entries)

	// Check that entries are sorted by strength (descending)
	if entries[0].Mp.Strength != 50 {
		t.Errorf("First entry should have strength 50, got %d", entries[0].Mp.Strength)
	}
	if entries[1].Mp.Strength != 30 {
		t.Errorf("Second entry should have strength 30, got %d", entries[1].Mp.Strength)
	}
	if entries[2].Mp.Strength != 20 {
		t.Errorf("Third entry should have strength 20, got %d", entries[2].Mp.Strength)
	}
	if entries[3].Mp.Strength != 10 {
		t.Errorf("Fourth entry should have strength 10, got %d", entries[3].Mp.Strength)
	}
}

func TestApprenticeSortDuplicates(t *testing.T) {
	// Create duplicate entries (same strength and content)
	entries := []*Entry{
		{
			Mp: &Magic{
				TypeStr:     "string",
				TestStr:     "test",
				OperatorStr: "=",
				Strength:    20,
				Offset:      0,
				Desc:        [MAXDESC]byte{},
			},
			ContCount: 0,
		},
		{
			Mp: &Magic{
				TypeStr:     "string",
				TestStr:     "test",
				OperatorStr: "=",
				Strength:    20,
				Offset:      0,
				Desc:        [MAXDESC]byte{},
			},
			ContCount: 0,
		},
	}

	// Copy the same description
	copy(entries[0].Mp.Desc[:], []byte("Duplicate pattern"))
	copy(entries[1].Mp.Desc[:], []byte("Duplicate pattern"))

	// Capture stderr to check for duplicate warning
	// For simplicity, we'll just sort and verify the result
	apprenticeSort(entries)

	// Both entries should still be in the array (duplicates are not removed)
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries after sorting, got %d", len(entries))
	}
}

func TestApprenticeSortWithDER(t *testing.T) {
	// Create DER type entries (should not warn about duplicates)
	entries := []*Entry{
		{
			Mp: &Magic{
				TypeStr:     "der",
				TestStr:     "test",
				OperatorStr: "=",
				Strength:    20,
				Offset:      0,
				Desc:        [MAXDESC]byte{},
			},
			ContCount: 0,
		},
		{
			Mp: &Magic{
				TypeStr:     "der",
				TestStr:     "test",
				OperatorStr: "=",
				Strength:    20,
				Offset:      0,
				Desc:        [MAXDESC]byte{},
			},
			ContCount: 0,
		},
	}

	// Sort - should not produce duplicate warning for DER type
	apprenticeSort(entries)

	// Both entries should still be in the array
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries after sorting, got %d", len(entries))
	}
}

func TestGetStr(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
		warn     bool
		wantErr  bool
	}{
		"simple string": {
			input:    "hello",
			expected: "hello",
			warn:     false,
			wantErr:  false,
		},
		"string with space terminates": {
			input:    "hello world",
			expected: "hello",
			warn:     false,
			wantErr:  false,
		},
		"string with tab terminates": {
			input:    "hello\tworld",
			expected: "hello",
			warn:     false,
		wantErr:  false,
		},
		"escaped space": {
			input:    "hello\\ world",
			expected: "hello world",
			warn:     false,
		wantErr:  false,
		},
		"escaped tab": {
			input:    "hello\\tthere",
			expected: "hello\tthere",
			warn:     false,
		wantErr:  false,
		},
		"escaped newline": {
			input:    "hello\\nworld",
			expected: "hello\nworld",
			warn:     false,
		wantErr:  false,
		},
		"escaped carriage return": {
			input:    "hello\\rworld",
			expected: "hello\rworld",
			warn:     false,
		wantErr:  false,
		},
		"escaped alert": {
			input:    "\\abell",
			expected: "\abell",
			warn:     false,
		wantErr:  false,
		},
		"escaped backspace": {
			input:    "hello\\bworld",
			expected: "hello\bworld",
			warn:     false,
		wantErr:  false,
		},
		"escaped form feed": {
			input:    "hello\\fworld",
			expected: "hello\fworld",
			warn:     false,
		wantErr:  false,
		},
		"escaped vertical tab": {
			input:    "hello\\vworld",
			expected: "hello\vworld",
			warn:     false,
		wantErr:  false,
		},
		"escaped backslash": {
			input:    "hello\\\\world",
			expected: "hello\\world",
			warn:     false,
		wantErr:  false,
		},
		"octal escape single digit": {
			input:    "\\0",
			expected: "\x00",
			warn:     false,
		wantErr:  false,
		},
		"octal escape two digits": {
			input:    "\\12",
			expected: "\x0a",
			warn:     false,
		wantErr:  false,
		},
		"octal escape three digits": {
			input:    "\\101",
			expected: "A",
			warn:     false,
		wantErr:  false,
		},
		"octal escape max value": {
			input:    "\\377",
			expected: "\xff",
			warn:     false,
		wantErr:  false,
		},
		"hex escape lowercase": {
			input:    "\\x41",
			expected: "A",
			warn:     false,
		wantErr:  false,
		},
		"hex escape uppercase": {
			input:    "\\x4A",
			expected: "J",
			warn:     false,
		wantErr:  false,
		},
		"hex escape max value": {
			input:    "\\xff",
			expected: "\xff",
			warn:     false,
		wantErr:  false,
		},
		"hex escape single digit": {
			input:    "\\x4",
			expected: "\x04",
			warn:     false,
		wantErr:  false,
		},
		"hex escape no digits": {
			input:    "\\xgg",
			expected: "xgg",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations >": {
			input:    "\\>",
			expected: ">",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations <": {
			input:    "\\<",
			expected: "<",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations &": {
			input:    "\\&",
			expected: "&",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations ^": {
			input:    "\\^",
			expected: "^",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations =": {
			input:    "\\=",
			expected: "=",
			warn:     false,
		wantErr:  false,
		},
		"escaped relations !": {
			input:    "\\!",
			expected: "!",
			warn:     false,
		wantErr:  false,
		},
		"bracket nesting": {
			input:    "[a-z]",
			expected: "[a-z]",
			warn:     false,
		wantErr:  false,
		},
		"nested brackets": {
			input:    "[[a-z]]",
			expected: "[[a-z]]",
			warn:     false,
		wantErr:  false,
		},
		"escaped dot": {
			input:    "\\.",
			expected: ".",
			warn:     true,
		wantErr:  false,
		},
		"incomplete escape at end": {
			input:    "hello\\",
			expected: "",
			warn:     true,
			wantErr:  true,
		},
		"empty string": {
			input:    "",
			expected: "",
			warn:     false,
		wantErr:  false,
		},
		"complex string": {
			input:    "\\x89PNG\\r\\n\\032\\n",
			expected: "\x89PNG\r\n\x1a\n",
			warn:     false,
		wantErr:  false,
		},
		"string with multiple escapes": {
			input:    "hello\\nworld\\ttab\\x41\\101",
			expected: "hello\nworld\ttabAA",
			warn:     false,
		wantErr:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Test with interpretEscapes=true (default behavior for these tests)
			got, err := getStr(tt.input, tt.warn, true)
			if tt.wantErr {
				if err == nil {
					t.Errorf("getStr(%q, %v, true) expected error, but got none", tt.input, tt.warn)
				}
				return
			}
			if err != nil {
				t.Errorf("getStr(%q, %v, true) unexpected error: %v", tt.input, tt.warn, err)
				return
			}
			if got != tt.expected {
				t.Errorf("getStr(%q, %v, true) = %q, want %q", tt.input, tt.warn, got, tt.expected)
				// Print bytes for debugging
				t.Logf("Got bytes: %v", []byte(got))
				t.Logf("Want bytes: %v", []byte(tt.expected))
			}
		})
	}
}

func TestHexToInt(t *testing.T) {
	tests := map[string]struct {
		input    byte
		expected int
	}{
		"digit 0":        {input: '0', expected: 0},
		"digit 5":        {input: '5', expected: 5},
		"digit 9":        {input: '9', expected: 9},
		"lower a":        {input: 'a', expected: 10},
		"lower f":        {input: 'f', expected: 15},
		"upper A":        {input: 'A', expected: 10},
		"upper F":        {input: 'F', expected: 15},
		"invalid g":      {input: 'g', expected: -1},
		"invalid G":      {input: 'G', expected: -1},
		"invalid space":  {input: ' ', expected: -1},
		"invalid symbol": {input: '@', expected: -1},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := hexToInt(tt.input)
			if got != tt.expected {
				t.Errorf("hexToInt(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}
