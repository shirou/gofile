package magic

import (
	"strings"
	"testing"
)

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
			parsed, err := parser.parseLine(tt.line, 1)

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

			if parsed.Level != tt.expectedLevel {
				t.Errorf("Level: expected %d, got %d", tt.expectedLevel, parsed.Level)
			}
			if parsed.Type != tt.expectedType {
				t.Errorf("Type: expected %s, got %s", tt.expectedType, parsed.Type)
			}
			if parsed.Test != tt.expectedTest {
				t.Errorf("Test: expected %s, got %s", tt.expectedTest, parsed.Test)
			}
			if parsed.Message != tt.expectedMsg {
				t.Errorf("Message: expected %s, got %s", tt.expectedMsg, parsed.Message)
			}
		})
	}
}

func TestParseDirective(t *testing.T) {
	parser := NewParser()

	tests := map[string]struct {
		directive    string
		expectedMime string
		expectedMod  string
	}{
		"MIME type": {
			directive:    "!:mime	image/png",
			expectedMime: "image/png",
			expectedMod:  "",
		},
		"Strength addition": {
			directive:    "!:strength +50",
			expectedMime: "",
			expectedMod:  "+50",
		},
		"Strength absolute": {
			directive:    "!:strength 200",
			expectedMime: "",
			expectedMod:  "200",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entry := &Entry{}
			parser.parseDirective(tt.directive, entry)

			if entry.MimeType != tt.expectedMime {
				t.Errorf("MIME: expected %s, got %s", tt.expectedMime, entry.MimeType)
			}
			if entry.StrengthMod != tt.expectedMod {
				t.Errorf("StrengthMod: expected %s, got %s", tt.expectedMod, entry.StrengthMod)
			}
		})
	}
}

func TestCalculateStrength(t *testing.T) {
	tests := map[string]struct {
		entry    *Entry
		expected int
	}{
		"String pattern with exact match": {
			entry: &Entry{
				Type:     "string",
				Test:     "TESTDATA",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 8*10 + 10, // BASE + 8 chars * MULT + operator(=)
		},
		"String pattern with not equal": {
			entry: &Entry{
				Type:     "string",
				Test:     "TESTDATA",
				Operator: "!=",
				Level:    0,
			},
			expected: 1, // != operator has minimal strength (same as !)
		},
		"String pattern with greater than": {
			entry: &Entry{
				Type:     "string",
				Test:     "TESTDATA",
				Operator: ">",
				Level:    0,
			},
			expected: 20 + 8*10 + (-20), // BASE + 8 chars * MULT + operator(>)
		},
		"String with case-insensitive flag": {
			entry: &Entry{
				Type:     "string",
				Test:     "test",
				Operator: "=",
				Flags:    []string{"c"},
				Level:    0,
			},
			expected: 20 + 4*10 + 10, // BASE + 4 chars * MULT + operator(=), flag(c) does not affect strength
		},
		"String with whitespace flag": {
			entry: &Entry{
				Type:     "string",
				Test:     "test",
				Operator: "=",
				Flags:    []string{"W"},
				Level:    0,
			},
			expected: 20 + 4*10 + 10, // BASE + 4 chars * MULT + operator(=), flag(W) does not affect strength
		},
		"Byte pattern with zero value": {
			entry: &Entry{
				Type:     "byte",
				Test:     "0",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 1*10 + 10 + (-10), // BASE + 1 byte * MULT + operator(=) + zero penalty
		},
		"Short pattern with power of 2": {
			entry: &Entry{
				Type:     "short",
				Test:     "16",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 2*10 + 10 + (-5) + (-5), // BASE + 2 bytes * MULT + operator + power_of_2 + small_value
		},
		"Long pattern with bitwise AND": {
			entry: &Entry{
				Type:     "long",
				Test:     "0xff00",
				Operator: "&",
				Level:    0,
			},
			expected: 20 + 4*10 + (-10), // BASE + 4 bytes * MULT + operator(&)
		},
		"Empty string pattern": {
			entry: &Entry{
				Type:     "string",
				Test:     "",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 0*10 + 10 + (-20), // BASE + 0 chars * MULT + operator + empty penalty
		},
		"Single char string": {
			entry: &Entry{
				Type:     "string",
				Test:     "a",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 1*10 + 10 + (-10), // BASE + 1 char * MULT + operator + single char penalty
		},
		"Common word string": {
			entry: &Entry{
				Type:     "string",
				Test:     "data",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 4*10 + 10 + (-5), // BASE + 4 chars * MULT + operator + common word penalty
		},
		"DER type pattern": {
			entry: &Entry{
				Type:     "der",
				Test:     "test",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 50 + 10, // BASE + DER(50) + operator
		},
		"GUID type pattern": {
			entry: &Entry{
				Type:     "guid",
				Test:     "test",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 50 + 10, // BASE + GUID(50) + operator
		},
		"Offset type pattern": {
			entry: &Entry{
				Type:     "offset",
				Test:     "test",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 10 + 10, // BASE + offset(10) + operator
		},
		"Default type pattern": {
			entry: &Entry{
				Type:     "default",
				Test:     "test",
				Operator: "=",
				Level:    0,
			},
			expected: 0, // default has no strength
		},
		"Clear type pattern": {
			entry: &Entry{
				Type:     "clear",
				Test:     "test",
				Operator: "=",
				Level:    0,
			},
			expected: 0, // clear has no strength
		},
		"X operator (always matches)": {
			entry: &Entry{
				Type:     "long",
				Test:     "",
				Operator: "x",
				Level:    0,
			},
			expected: 1, // x operator has minimal strength
		},
		"Nested pattern level 2": {
			entry: &Entry{
				Type:     "long",
				Test:     "0x1234",
				Operator: "=",
				Level:    2,
			},
			expected: int((20 + 4*10 + 10) * 0.8), // (BASE + 4 bytes * MULT + operator) * level reduction
		},
		"Manual strength modifier addition": {
			entry: &Entry{
				Type:        "string",
				Test:        "test",
				Operator:    "=",
				Level:       0,
				StrengthMod: "+20",
			},
			expected: 20 + 4*10 + 10 + 20, // BASE + 4 chars * MULT + operator + manual addition
		},
		"Manual strength modifier subtraction": {
			entry: &Entry{
				Type:        "string",
				Test:        "test",
				Operator:    "=",
				Level:       0,
				StrengthMod: "-15",
			},
			expected: 20 + 4*10 + 10 - 15, // BASE + 4 chars * MULT + operator - manual subtraction
		},
		"Manual strength modifier multiplication": {
			entry: &Entry{
				Type:        "string",
				Test:        "test",
				Operator:    "=",
				Level:       0,
				StrengthMod: "*2",
			},
			expected: (20 + 4*10 + 10) * 2, // (BASE + 4 chars * MULT + operator) * 2
		},
		"Manual strength modifier division": {
			entry: &Entry{
				Type:        "string",
				Test:        "test",
				Operator:    "=",
				Level:       0,
				StrengthMod: "/2",
			},
			expected: (20 + 4*10 + 10) / 2, // (BASE + 4 chars * MULT + operator) / 2
		},
		"Search type with default range": {
			entry: &Entry{
				Type:     "search",
				Test:     "MAGIC",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 5*10 + 10 + (10 - 24), // BASE + 5 chars * MULT + operator + (10 - log2(4096)*2)
		},
		"Search type with custom range": {
			entry: &Entry{
				Type:     "search/256",
				Test:     "MAGIC",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 5*10 + 10 + (10 - 16), // BASE + 5 chars * MULT + operator + (10 - log2(256)*2)
		},
		"Regex type with literals": {
			entry: &Entry{
				Type:     "regex",
				Test:     "^Hello.*World$",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + (10*10)/2 + 10, // BASE + (10 literals * MULT)/2 + operator
		},
		"Indirect type": {
			entry: &Entry{
				Type:     "indirect",
				Test:     "(&0.l)",
				Operator: "=",
				Level:    0,
			},
			expected: 20 + 30 + 10, // BASE + indirect(30) + operator
		},
		"Bitwise XOR operator": {
			entry: &Entry{
				Type:     "long",
				Test:     "0xAA55",
				Operator: "^",
				Level:    0,
			},
			expected: 20 + 4*10 + (-10), // BASE + 4 bytes * MULT + operator(^)
		},
		"Negation operator": {
			entry: &Entry{
				Type:     "byte",
				Test:     "0xFF",
				Operator: "~",
				Level:    0,
			},
			expected: 20 + 1*10 + (-10), // BASE + 1 byte * MULT + operator(~)
		},
		"Test inversion operator": {
			entry: &Entry{
				Type:     "string",
				Test:     "test",
				Operator: "!",
				Level:    0,
			},
			expected: 1, // ! operator has minimal strength
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			strength := tt.entry.CalculateStrength()
			if strength != tt.expected {
				t.Errorf("Expected strength %d, got %d (type: %s, test: %s, operator: %s)",
					tt.expected, strength, tt.entry.Type, tt.entry.Test, tt.entry.Operator)
			}
		})
	}
}

func TestParse(t *testing.T) {
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

	err := parser.Parse(reader, "test.magic")
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	db := parser.GetDatabase()
	if len(db.Entries) != 3 {
		t.Errorf("Expected 3 top-level entries, got %d", len(db.Entries))
	}

	// Check first entry
	png := db.Entries[0]
	if png.Message != "PNG image data" {
		t.Errorf("Expected PNG message, got %s", png.Message)
	}
	if png.MimeType != "image/png" {
		t.Errorf("Expected image/png MIME, got %s", png.MimeType)
	}

	// Check nested entry
	test := db.Entries[2]
	if len(test.Children) != 1 {
		t.Errorf("Expected 1 child, got %d", len(test.Children))
	}
	if test.Children[0].Message != "with data" {
		t.Errorf("Expected child message 'with data', got %s", test.Children[0].Message)
	}
	if len(test.Children[0].Children) != 1 {
		t.Errorf("Expected 1 grandchild, got %d", len(test.Children[0].Children))
	}
}

func TestParseOperator(t *testing.T) {
	parser := NewParser()

	tests := map[string]struct {
		test          string
		expectedOp    string
		expectedValue string
	}{
		"Exact match (default)": {
			test:          "TESTDATA",
			expectedOp:    "=",
			expectedValue: "TESTDATA",
		},
		"Explicit equal": {
			test:          "=TESTDATA",
			expectedOp:    "=",
			expectedValue: "TESTDATA",
		},
		"Not equal": {
			test:          "!=123",
			expectedOp:    "!=",
			expectedValue: "123",
		},
		"Greater than": {
			test:          ">100",
			expectedOp:    ">",
			expectedValue: "100",
		},
		"Less than": {
			test:          "<256",
			expectedOp:    "<",
			expectedValue: "256",
		},
		"Bitwise AND": {
			test:          "&0xff00",
			expectedOp:    "&",
			expectedValue: "0xff00",
		},
		"Bitwise XOR": {
			test:          "^0x0f0f",
			expectedOp:    "^",
			expectedValue: "0x0f0f",
		},
		"Negation": {
			test:          "~0x01",
			expectedOp:    "~",
			expectedValue: "0x01",
		},
		"Any value (x)": {
			test:          "x",
			expectedOp:    "x",
			expectedValue: "",
		},
		"Test inversion": {
			test:          "!test",
			expectedOp:    "!",
			expectedValue: "test",
		},
		"Less than or equal": {
			test:          "<=512",
			expectedOp:    "<=",
			expectedValue: "512",
		},
		"Greater than or equal": {
			test:          ">=1024",
			expectedOp:    ">=",
			expectedValue: "1024",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entry := &Entry{Test: tt.test}
			parser.parseOperator(entry)

			if entry.Operator != tt.expectedOp {
				t.Errorf("Operator: expected %s, got %s", tt.expectedOp, entry.Operator)
			}
			if entry.Test != tt.expectedValue {
				t.Errorf("Test value: expected %s, got %s", tt.expectedValue, entry.Test)
			}
		})
	}
}

func TestParseStringFlags(t *testing.T) {
	parser := NewParser()

	tests := map[string]struct {
		typeField     string
		expectedType  string
		expectedFlags []string
	}{
		"String with no flags": {
			typeField:     "string",
			expectedType:  "string",
			expectedFlags: []string{},
		},
		"String with case-insensitive": {
			typeField:     "string/c",
			expectedType:  "string",
			expectedFlags: []string{"c"},
		},
		"String with multiple flags": {
			typeField:     "string/cWT",
			expectedType:  "string",
			expectedFlags: []string{"c", "W", "T"},
		},
		"String with uppercase case flag": {
			typeField:     "string/C",
			expectedType:  "string",
			expectedFlags: []string{"C"},
		},
		"String with whitespace flags": {
			typeField:     "string/wW",
			expectedType:  "string",
			expectedFlags: []string{"w", "W"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			entry := &Entry{Type: tt.typeField, Flags: []string{}}
			parser.parseStringFlags(entry)

			if entry.Type != tt.expectedType {
				t.Errorf("Type: expected %s, got %s", tt.expectedType, entry.Type)
			}

			if len(entry.Flags) != len(tt.expectedFlags) {
				t.Errorf("Flags count: expected %d, got %d", len(tt.expectedFlags), len(entry.Flags))
			}

			for i, flag := range tt.expectedFlags {
				if i >= len(entry.Flags) || entry.Flags[i] != flag {
					t.Errorf("Flag %d: expected %s, got %v", i, flag, entry.Flags)
				}
			}
		})
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

	err := parser.Parse(reader, "test.magic")
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
		t.Logf("Binary entry: type=%s, test=%s, message=%s", entry.Type, entry.Test, entry.Message)
	}
	for _, entry := range set0.TextEntries {
		t.Logf("Text entry: type=%s, test=%s, message=%s", entry.Type, entry.Test, entry.Message)
	}

	if len(set0.BinaryEntries) != 2 {
		t.Errorf("Expected 2 binary entries in set 0, got %d", len(set0.BinaryEntries))
	}
	if len(set0.TextEntries) != 2 {
		t.Errorf("Expected 2 text entries in set 0, got %d", len(set0.TextEntries))
	}
}

func TestStrengthCalculationAdvanced(t *testing.T) {
	// Test cases based on test_advanced.magic to ensure compatibility with file command
	tests := map[string]struct {
		magicLine        string
		expectedStrength int
		description      string
	}{
		// Test operator strength calculations
		"Not equal operator": {
			magicLine:        "0	string	!TEST	Not equal string",
			expectedStrength: 1, // ! operator has minimal strength
			description:      "Not equal operator should have minimal strength (1)",
		},
		"Any value operator": {
			magicLine:        "0	long	x	Any long value",
			expectedStrength: 1, // x operator has minimal strength
			description:      "Any value operator should have minimal strength (1)",
		},
		"Exact match string": {
			magicLine:        "0	string	=TEST	Exact match string",
			expectedStrength: 70, // 20 + 4*10 + 10
			description:      "Exact match string should have normal strength",
		},

		// Test string flag modifiers (should not affect strength)
		"Case insensitive flag": {
			magicLine:        "0	string/c	test	Case insensitive string",
			expectedStrength: 70, // Flags should not affect strength
			description:      "Case insensitive flag should not affect strength",
		},
		"Whitespace compaction flag": {
			magicLine:        "0	string/W	test	Whitespace compaction",
			expectedStrength: 70, // Flags should not affect strength
			description:      "Whitespace compaction flag should not affect strength",
		},
		"Multiple flags": {
			magicLine:        "0	string/cW	test	Multiple flags",
			expectedStrength: 70, // Flags should not affect strength
			description:      "Multiple flags should not affect strength",
		},

		// Test manual strength modifiers
		"Manual strength addition": {
			magicLine:        "0	string	manual	Manual test\n!:strength +50",
			expectedStrength: 140, // 20 + 6*10 + 10 + 50 = 90 + 50
			description:      "Manual strength addition should work correctly",
		},
		"Manual strength subtraction": {
			magicLine:        "0	string	manual	Manual test\n!:strength -20",
			expectedStrength: 70, // 20 + 6*10 + 10 - 20 = 90 - 20
			description:      "Manual strength subtraction should work correctly",
		},
		"Manual strength multiplication": {
			magicLine:        "0	string	manual	Manual test\n!:strength *2",
			expectedStrength: 180, // (20 + 6*10 + 10) * 2 = 90 * 2
			description:      "Manual strength multiplication should work correctly",
		},
		"Manual strength division": {
			magicLine:        "0	string	manual	Manual test\n!:strength /3",
			expectedStrength: 30, // (20 + 6*10 + 10) / 3 = 90 / 3
			description:      "Manual strength division should work correctly",
		},

		// Test comparison operators
		"Greater than operator": {
			magicLine:        "0	long	>100	Greater than test",
			expectedStrength: 40, // 20 + 4*10 - 20
			description:      "Greater than operator should reduce strength",
		},
		"Less than operator": {
			magicLine:        "0	long	<1000	Less than test",
			expectedStrength: 40, // 20 + 4*10 - 20
			description:      "Less than operator should reduce strength",
		},

		// Test bitwise operators
		"Bitwise AND operator": {
			magicLine:        "0	long	&0xff00	Bitwise AND test",
			expectedStrength: 50, // 20 + 4*10 - 10
			description:      "Bitwise AND operator should moderately reduce strength",
		},
		"Bitwise XOR operator": {
			magicLine:        "0	long	^0x0f0f	Bitwise XOR test",
			expectedStrength: 50, // 20 + 4*10 - 10
			description:      "Bitwise XOR operator should moderately reduce strength",
		},
	}

	parser := NewParser()

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Parse the magic line(s)
			lines := strings.Split(tt.magicLine, "\n")
			var entry *Entry

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				if strings.HasPrefix(line, "!:") {
					// Apply directive to the last entry
					if entry != nil {
						parser.parseDirective(line, entry)
						// Recalculate strength after applying directive
						if strings.HasPrefix(line, "!:strength") {
							entry.Strength = entry.CalculateStrength()
						}
					}
				} else {
					// Parse the main pattern line
					parsedLine, err := parser.parseLine(line, 1)
					if err != nil {
						t.Fatalf("Failed to parse magic line: %s, error: %v", line, err)
					}

					// Create entry from parsed line (following the same logic as Parse method)
					entry = &Entry{
						Level:      parsedLine.Level,
						Offset:     parsedLine.Offset,
						Type:       parsedLine.Type,
						Test:       parsedLine.Test,
						Message:    parsedLine.Message,
						LineNumber: 1,
						Children:   make([]*Entry, 0),
					}

					// Parse operator from test field
					parser.parseOperator(entry)

					// Parse string flags if it's a string type
					parser.parseStringFlags(entry)

					// Calculate initial strength
					entry.Strength = entry.CalculateStrength()
				}
			}

			if entry == nil {
				t.Fatalf("No entry was parsed from magic line(s): %s", tt.magicLine)
			}

			// Calculate strength
			strength := entry.CalculateStrength()

			// Check if the strength matches expected
			if strength != tt.expectedStrength {
				t.Errorf("Expected strength %d, got %d. %s",
					tt.expectedStrength, strength, tt.description)
			}
		})
	}
}
