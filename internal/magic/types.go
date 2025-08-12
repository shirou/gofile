package magic

import (
	"fmt"
	"strconv"
	"strings"
)

// Constants matching file.h definitions
const (
	MAXDESC   = 64  // Maximum length of text description
	MAXMIME   = 80  // Maximum length of MIME type
	MAXstring = 128 // Maximum length of string types
)

// ValueType represents the union VALUETYPE from file.h
type ValueType struct {
	// Numeric values
	B  uint8  // unsigned byte
	H  uint16 // unsigned short
	L  uint32 // unsigned long
	Q  uint64 // unsigned quad
	Sb int8   // signed byte
	Sh int16  // signed short
	Sl int32  // signed long
	Sq int64  // signed quad

	// Fixed-endian arrays (for explicit byte order)
	Hs [2]uint8 // 2 bytes of fixed-endian "short"
	Hl [4]uint8 // 4 bytes of fixed-endian "long"
	Hq [8]uint8 // 8 bytes of fixed-endian "quad"

	// String/pattern values
	S  [MAXstring]byte // Search string or regex pattern
	Us [MAXstring]byte // Unsigned version for binary data

	// GUID
	Guid [2]uint64

	// Floating point
	F float32
	D float64
}

// Magic represents the struct magic from file.h
// This is the core structure that holds a single magic pattern
type Magic struct {
	// Word 1
	Flag      uint16 // Flags like INDIR, OFFADD, UNSIGNED, etc.
	ContLevel uint8  // Level of ">" continuation
	Factor    uint8  // Strength factor

	// Word 2
	Reln   uint8 // Relation (0=eq, '>'=gt, etc)
	Vallen uint8 // Length of string value, if any
	Type   uint8 // Comparison type (FILE_*)
	InType uint8 // Type of indirection

	// Word 3
	InOp     uint8 // Operator for indirection
	MaskOp   uint8 // Operator for mask
	Cond     uint8 // Conditional type (or dummy if not enabled)
	FactorOp uint8 // Operator for factor

	// Word 4
	Offset int32 // Offset to magic number

	// Word 5
	InOffset int32 // Offset from indirection

	// Word 6
	Lineno uint32 // Line number in magic file

	// Word 7,8 - Union for mask/count/flags
	Mask  uint64 // For use with numeric and date types
	Count uint32 // Repeat/line count
	Flags uint32 // Modifier flags

	// Words 9-24
	Value ValueType // Either number or string

	// Words 25-40
	Desc [MAXDESC]byte // Description

	// Words 41-60
	Mimetype [MAXMIME]byte // MIME type

	// Words 61-62
	Apple [8]byte // APPLE CREATOR/TYPE

	// Words 63-78
	Ext [64]byte // Extensions

	// Additional Go-specific fields for parsing convenience
	Strength   int      // Calculated strength value
	SourceFile string   // Source file name (for debugging)
	TestType   TestType // BINTEST or TEXTTEST
	IsNameType bool     // True if this is a FILE_NAME type pattern

	// Original parsed values (for easier handling)
	OffsetStr   string   // Original offset specification (can be complex expression)
	TypeStr     string   // Original type string (before conversion to uint8)
	OperatorStr string   // Original operator string
	TestStr     string   // Original test value string
	MessageStr  string   // Original message string
	StrengthMod string   // Strength modifier from !:strength directive
	Extensions  []string // Parsed file extensions
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

// GetTestType determines whether this magic represents a binary or text pattern
// This implements the same logic as the original file command's set_test_type function
func (m *Magic) GetTestType() TestType {
	// Handle types with parameters (e.g., search/256)
	baseType := m.TypeStr
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
		if m.Flags&STRING_TEXTTEST != 0 {
			return TEXTTEST
		}
		// Check for 'b' flag which forces BINTEST
		if m.Flags&STRING_BINTEST != 0 {
			return BINTEST
		}
		// Default to binary (matching original file command)
		return BINTEST

	case TypeRegex, TypeSearch:
		// For regex and search types, use UTF-8 validity check
		// (matching original file command's file_looks_utf8 logic)
		if m.TestStr != "" {
			// Check if content looks like valid UTF-8 / printable text
			if containsBinaryBytes(m.TestStr) {
				return BINTEST
			}
			// If it's mostly printable, classify as text
			if isPrintableText(m.TestStr) {
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
func (m *Magic) calculateValueLength() int {
	// Handle types with parameters (e.g., search/256)
	baseType := m.TypeStr
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	if baseType != TypeString && baseType != TypePstring && baseType != TypeSearch {
		return 0
	}

	// Parse escape sequences to get actual byte count
	length := 0
	i := 0
	for i < len(m.TestStr) {
		if m.TestStr[i] == '\\' && i+1 < len(m.TestStr) {
			next := m.TestStr[i+1]
			switch next {
			case 'x': // Hex escape \xHH
				if i+3 < len(m.TestStr) {
					i += 4 // Skip \xHH
					length++
				} else {
					i++
				}
			case '0', '1', '2', '3', '4', '5', '6', '7': // Octal escape \nnn
				j := i + 1
				for j < len(m.TestStr) && j < i+4 && m.TestStr[j] >= '0' && m.TestStr[j] <= '7' {
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
