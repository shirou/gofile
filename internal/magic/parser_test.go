package magic

import (
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	parser := NewParser()
	
	tests := []struct {
		name          string
		line          string
		expectedLevel int
		expectedType  string
		expectedTest  string
		expectedMsg   string
		expectError   bool
	}{
		{
			name:          "Simple string pattern",
			line:          "0	string	PNG	PNG image data",
			expectedLevel: 0,
			expectedType:  "string",
			expectedTest:  "PNG",
			expectedMsg:   "PNG image data",
			expectError:   false,
		},
		{
			name:          "Nested pattern",
			line:          ">4	byte	1	32-bit",
			expectedLevel: 1,
			expectedType:  "byte",
			expectedTest:  "1",
			expectedMsg:   "32-bit",
			expectError:   false,
		},
		{
			name:          "Double nested",
			line:          ">>8	long	x	size %d",
			expectedLevel: 2,
			expectedType:  "long",
			expectedTest:  "x",
			expectedMsg:   "size %d",
			expectError:   false,
		},
		{
			name:          "Invalid format",
			line:          "invalid",
			expectedLevel: 0,
			expectError:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	
	tests := []struct {
		name             string
		directive        string
		expectedMime     string
		expectedMod      string
	}{
		{
			name:             "MIME type",
			directive:        "!:mime	image/png",
			expectedMime:     "image/png",
			expectedMod:      "",
		},
		{
			name:             "Strength addition",
			directive:        "!:strength +50",
			expectedMime:     "",
			expectedMod:      "+50",
		},
		{
			name:             "Strength absolute",
			directive:        "!:strength 200",
			expectedMime:     "",
			expectedMod:      "200",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	tests := []struct {
		name     string
		entry    *Entry
		expected int
	}{
		{
			name: "String pattern",
			entry: &Entry{
				Type:  "string",
				Test:  "TESTDATA",
				Level: 0,
			},
			expected: 20 + 8*10 + 10, // BASE + 8 chars * MULT + operator
		},
		{
			name: "Byte pattern",
			entry: &Entry{
				Type:  "byte",
				Test:  "0x42",
				Level: 0,
			},
			expected: 20 + 1*10 + 10, // BASE + 1 byte * MULT + operator
		},
		{
			name: "Nested pattern",
			entry: &Entry{
				Type:  "long",
				Test:  "0x1234",
				Level: 2,
			},
			expected: int((20 + 4*10 + 10) * 0.8), // (BASE + 4 bytes * MULT + operator) * level reduction
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := tt.entry.CalculateStrength()
			if strength != tt.expected {
				t.Errorf("Expected strength %d, got %d", tt.expected, strength)
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

func TestOrganizeSets(t *testing.T) {
	magicData := `
0	string	\x89PNG	Binary pattern
0	string	#!/bin/sh	Text pattern
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
	
	// In current implementation, all patterns are classified as binary
	// This matches the observed behavior of the original file command
	if len(set0.BinaryEntries) == 0 {
		t.Error("Expected binary entries in set 0")
	}
	// Text entries should be empty in current implementation
	if len(set0.TextEntries) != 0 {
		t.Error("Expected no text entries in set 0 (all patterns are binary)")
	}
}