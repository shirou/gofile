package magic

import (
	"fmt"
	"strconv"
	"strings"
)

// Entry represents a single magic entry from a magic file
type Entry struct {
	Level       int      // Indentation level (0 for primary, >0 for continuation)
	Offset      string   // Offset specification (can be complex expression)
	Type        string   // Data type (byte, short, long, string, etc.)
	Operator    string   // Comparison operator (=, !=, <, >, &, ^, ~, x, !)
	Test        string   // Test value
	Message     string   // Message to output when matched
	Strength    int      // Calculated strength value
	StrengthMod string   // Strength modifier from !:strength directive
	LineNumber  int      // Line number in source file
	SourceFile  string   // Source file name
	Flags       []string // Modifier flags
	MimeType    string   // MIME type if specified
	Extensions  []string // File extensions if specified
	Flag        TestType // BINTEST or TEXTTEST
	IsNameType  bool     // True if this is a FILE_NAME type pattern
	Children    []*Entry // Child entries (continuation lines)
}

// Database represents a collection of magic entries
type Database struct {
	Entries []*Entry // All top-level entries
	Sets    []Set    // Organized sets of patterns
}

// Set represents a set of magic patterns (binary and text)
type Set struct {
	Number        int
	BinaryEntries []*Entry
	TextEntries   []*Entry
}

// ParsedLine represents a single parsed line from a magic file
type ParsedLine struct {
	Level      int
	Offset     string
	Type       string
	Test       string
	Message    string
	LineNumber int
	Raw        string // Original line for debugging
}

// StrengthInfo holds strength calculation information
type StrengthInfo struct {
	Value      int
	LineNumber int
	Message    string
	MimeType   string
}

// String returns a formatted string for --list output
func (s *StrengthInfo) String() string {
	// Always include brackets for MIME type, even if empty
	mime := fmt.Sprintf(" [%s]", s.MimeType)
	// Format strength value with padding for alignment
	return fmt.Sprintf("Strength = %3d@%d: %s%s", s.Value, s.LineNumber, s.Message, mime)
}

// getStringFlagModifier returns strength modifiers for string flags
func (e *Entry) getStringFlagModifier() int {
	// String flags do not affect strength in the original file command
	// They only affect how the string matching is performed
	// (case sensitivity, whitespace handling, etc.)
	return 0
}

// GetTestType determines whether this entry represents a binary or text pattern
// This implements the same logic as the original file command's set_test_type function
func (e *Entry) GetTestType() TestType {
	// Handle types with parameters (e.g., search/256)
	baseType := e.Type
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	// Numeric types are all BINTEST (matching original file command)
	switch baseType {
	case TypeByte, TypeUbyte, TypeShort, TypeUshort, TypeBeshort, TypeLeshort,
		TypeLong, TypeUlong, TypeBelong, TypeLelong, TypeMelong,
		TypeQuad, TypeBequad, TypeLequad,
		TypeFloat, TypeBefloat, TypeLefloat,
		TypeDouble, TypeBedouble, TypeLedouble,
		TypeDate, TypeBedate, TypeLedate, TypeLdate, TypeBeldate, TypeLeldate,
		TypeMedate, TypeMeldate, TypeQdate, TypeLeqdate, TypeBeqdate,
		TypeQldate, TypeLeqldate, TypeBeqldate, TypeQwdate, TypeLeqwdate, TypeBeqwdate,
		TypeMsdosdate, TypeBemsdosdate, TypeLemsdosdate,
		TypeMsdostime, TypeBemsdostime, TypeLemsdostime,
		TypeBevarint, TypeLevarint, TypeDer, TypeGuid, TypeOffset, TypeOctal:
		return BINTEST

	case TypeString, TypePstring, TypeBestring16, TypeLestring16:
		// Check for 't' flag which forces TEXTTEST
		for _, flag := range e.Flags {
			if flag == "t" || flag == "T" {
				return TEXTTEST
			}
		}
		// Regular strings default to binary (matching original file command)
		return BINTEST

	case TypeRegex, TypeSearch:
		// For regex and search types, use UTF-8 validity check
		// (matching original file command's file_looks_utf8 logic)
		if e.Test != "" {
			// Check if content looks like valid UTF-8 / printable text
			if containsBinaryBytes(e.Test) {
				return BINTEST
			}
			// If it's mostly printable, classify as text
			if isPrintableText(e.Test) {
				return TEXTTEST
			}
		}
		return BINTEST

	default:
		// Default to binary (matching original file command behavior)
		return BINTEST
	}
}

// containsBinaryBytes checks if a string contains binary escape sequences
func containsBinaryBytes(test string) bool {
	// Check for hex escapes that indicate binary data
	if strings.Contains(test, "\\x") {
		i := 0
		for i < len(test) {
			if i+3 < len(test) && test[i:i+2] == "\\x" {
				// Parse hex value
				hexStr := test[i+2 : i+4]
				if val, err := strconv.ParseInt(hexStr, 16, 16); err == nil {
					// Non-printable characters indicate binary
					if val < 32 || val > 126 {
						return true
					}
				}
				i += 4
			} else {
				i++
			}
		}
	}

	// Check for null bytes or other binary indicators
	binaryIndicators := []string{
		"\\0",
		"\\177", // DEL character
	}
	for _, binIndicator := range binaryIndicators {
		if strings.Contains(test, binIndicator) {
			return true
		}
	}

	return false
}

// isPrintableText checks if a string is mostly printable text
func isPrintableText(test string) bool {
	if test == "" {
		return false
	}

	// Count printable characters (excluding escape sequences)
	printableCount := 0
	totalChars := 0
	i := 0
	for i < len(test) {
		if test[i] == '\\' && i+1 < len(test) {
			// Skip escape sequences
			if test[i+1] == 'x' && i+3 < len(test) {
				// Hex escape
				hexStr := test[i+2 : i+4]
				if val, err := strconv.ParseInt(hexStr, 16, 16); err == nil {
					if val >= 32 && val <= 126 {
						printableCount++
					}
				}
				totalChars++
				i += 4
			} else if test[i+1] >= '0' && test[i+1] <= '7' {
				// Octal escape
				j := i + 1
				for j < i+4 && j < len(test) && test[j] >= '0' && test[j] <= '7' {
					j++
				}
				i = j
				totalChars++
			} else {
				// Other escapes like \n, \t, etc. are considered printable
				i += 2
				printableCount++
				totalChars++
			}
		} else {
			ch := test[i]
			if ch >= 32 && ch <= 126 {
				printableCount++
			}
			totalChars++
			i++
		}
	}

	// If more than 80% printable, likely text
	return totalChars > 0 && float64(printableCount)/float64(totalChars) > 0.8
}

// calculateValueLength calculates the actual byte length of the test value
func (e *Entry) calculateValueLength() int {
	// Handle types with parameters (e.g., search/256)
	baseType := e.Type
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	if baseType != TypeString && baseType != TypePstring && baseType != TypeSearch {
		return 0
	}

	// Parse escape sequences to get actual byte count
	length := 0
	i := 0
	for i < len(e.Test) {
		if e.Test[i] == '\\' && i+1 < len(e.Test) {
			next := e.Test[i+1]
			switch next {
			case 'x': // Hex escape \xHH
				if i+3 < len(e.Test) {
					i += 4 // Skip \xHH
					length++
				} else {
					i++
				}
			case '0', '1', '2', '3', '4', '5', '6', '7': // Octal escape \nnn
				j := i + 1
				for j < len(e.Test) && j < i+4 && e.Test[j] >= '0' && e.Test[j] <= '7' {
					j++
				}
				i = j
				length++
			case 'n', 't', 'r', 'b', 'f', 'v', 'a', '\\': // Standard escapes
				i += 2
				length++
			default:
				i += 2
				length++
			}
		} else {
			i++
			length++
		}
	}

	return length
}
