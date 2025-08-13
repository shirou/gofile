package magic

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseOpModifier parses operation modifiers for magic entries
// This is ported from parse_op_modifier in apprentice.c
func ParseOpModifier(m *Magic, input *string, op uint8) {
	if input == nil || *input == "" {
		return
	}
	
	l := *input
	
	// Skip the operator character
	if len(l) > 0 {
		l = l[1:]
	}
	
	// Set the mask operation
	m.MaskOp |= op
	
	// Parse the numeric value
	val := parseNumericValue(&l)
	
	// Apply sign extension if needed
	m.Mask = signExtend(m, val)
	
	// Skip size modifiers (eatsize equivalent)
	eatSize(&l)
	
	// Update the input pointer
	*input = l
}

// parseNumericValue parses a numeric value from the input string
// Supports hex (0x...), octal (0...), and decimal formats
func parseNumericValue(input *string) uint64 {
	if input == nil || *input == "" {
		return 0
	}
	
	l := strings.TrimSpace(*input)
	
	// Find the end of the numeric value
	endIdx := 0
	if strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0X") {
		// Hex number
		endIdx = 2
		for endIdx < len(l) && isHexDigit(l[endIdx]) {
			endIdx++
		}
	} else if len(l) > 0 && l[0] == '0' {
		// Octal number
		endIdx = 0
		for endIdx < len(l) && l[endIdx] >= '0' && l[endIdx] <= '7' {
			endIdx++
		}
		// If no valid octal digits, try decimal
		if endIdx == 0 || endIdx == 1 {
			endIdx = 0
			for endIdx < len(l) && isDigit(l[endIdx]) {
				endIdx++
			}
		}
	} else {
		// Decimal number (including negative)
		if l[0] == '-' || l[0] == '+' {
			endIdx = 1
		}
		for endIdx < len(l) && isDigit(l[endIdx]) {
			endIdx++
		}
	}
	
	if endIdx == 0 {
		return 0
	}
	
	numStr := l[:endIdx]
	*input = l[endIdx:]
	
	// Parse the number
	if strings.HasPrefix(numStr, "0x") || strings.HasPrefix(numStr, "0X") {
		if val, err := strconv.ParseUint(numStr[2:], 16, 64); err == nil {
			return val
		}
	} else if len(numStr) > 1 && numStr[0] == '0' {
		// Try octal first
		if val, err := strconv.ParseUint(numStr, 8, 64); err == nil {
			return val
		}
		// Fall back to decimal
		if val, err := strconv.ParseUint(numStr, 10, 64); err == nil {
			return val
		}
	} else {
		// Decimal (handle both signed and unsigned)
		if val, err := strconv.ParseInt(numStr, 10, 64); err == nil {
			return uint64(val)
		}
		if val, err := strconv.ParseUint(numStr, 10, 64); err == nil {
			return val
		}
	}
	
	return 0
}

// signExtend performs sign extension based on the magic type
// This is ported from file_signextend in apprentice.c
func signExtend(m *Magic, v uint64) uint64 {
	// If the UNSIGNED flag is set, no sign extension
	if m.Flag&UNSIGNED != 0 {
		return v
	}
	
	// Handle types with parameters (e.g., search/256)
	baseType := m.TypeStr
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}
	
	// Sign extend based on type
	switch MagicTypeFromString(baseType) {
	case TypeByte, TypeUbyte:
		// Sign extend from 8 bits
		return uint64(int64(int8(v)))
		
	case TypeShort, TypeBeshort, TypeLeshort, TypeUshort:
		// Sign extend from 16 bits
		return uint64(int64(int16(v)))
		
	case TypeLong, TypeBelong, TypeLelong, TypeMelong, TypeUlong,
		TypeDate, TypeBedate, TypeLedate, TypeMedate,
		TypeLdate, TypeBeldate, TypeLeldate, TypeMeldate,
		TypeFloat, TypeBefloat, TypeLefloat,
		TypeMsdosdate, TypeBemsdosdate, TypeLemsdosdate,
		TypeMsdostime, TypeBemsdostime, TypeLemsdostime:
		// Sign extend from 32 bits
		return uint64(int64(int32(v)))
		
	case TypeQuad, TypeBequad, TypeLequad,
		TypeQdate, TypeQldate, TypeQwdate,
		TypeBeqdate, TypeBeqldate, TypeBeqwdate,
		TypeLeqdate, TypeLeqldate, TypeLeqwdate,
		TypeDouble, TypeBedouble, TypeLedouble,
		TypeOffset, TypeBevarint, TypeLevarint:
		// Sign extend from 64 bits (no-op)
		return uint64(int64(v))
		
	default:
		// No sign extension for other types
		return v
	}
}

// eatSize skips size modifiers in the input
// This is ported from eatsize in apprentice.c
func eatSize(input *string) {
	if input == nil || *input == "" {
		return
	}
	
	l := *input
	
	// Skip 'u' for unsigned
	if len(l) > 0 && (l[0] == 'u' || l[0] == 'U') {
		l = l[1:]
	}
	
	// Skip size specifier
	if len(l) > 0 {
		switch l[0] {
		case 'l', 'L': // long
			l = l[1:]
		case 's', 'S': // short
			l = l[1:]
		case 'h', 'H': // short
			l = l[1:]
		case 'b', 'B': // byte
			l = l[1:]
		case 'c', 'C': // char
			l = l[1:]
		}
	}
	
	*input = l
}

// Constants for magic flags (matching file.h definitions)
const (
	UNSIGNED      uint16 = 0x08  // Comparison is unsigned
	OFFADD        uint16 = 0x04  // Offset is relative to previous match
	INDIROFFADD   uint16 = 0x08  // Offset is relative to previous match (indirect)
	INDIR         uint16 = 0x10  // Indirect offset
	OFFNEGATIVE   uint16 = 0x20  // Negative offset
	OFFPOSITIVE   uint16 = 0x40  // Positive offset  
	NOSPACE       uint16 = 0x80  // No space before description
	FILE_OPSIGNED uint8  = 0x01  // Signed operation
	INDIRECT_RELATIVE uint32 = 1 << 13  // Relative indirect offset
)

// isHexDigit checks if a character is a valid hex digit
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || 
		(c >= 'a' && c <= 'f') || 
		(c >= 'A' && c <= 'F')
}

// isDigit checks if a character is a decimal digit
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// ParseStringModifier parses string type modifiers for magic entries
// This is a complete port of parse_string_modifier from apprentice.c
// It directly modifies the Magic struct's str_flags and str_range fields
func ParseStringModifier(m *Magic, input *string) error {
	if input == nil || *input == "" {
		return nil
	}
	
	l := *input
	haveRange := false
	
	// Skip first character and process until whitespace
	if len(l) > 0 {
		l = l[1:] // Skip first character
	}
	
	for len(l) > 0 && !isSpace(l[0]) {
		ch := l[0]
		
		switch ch {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// Parse numeric range
			if haveRange {
				// Multiple ranges warning - but continue
			}
			haveRange = true
			
			// Find end of number
			endIdx := 0
			for endIdx < len(l) && isDigit(l[endIdx]) {
				endIdx++
			}
			
			if endIdx > 0 {
				if val, err := strconv.ParseUint(l[:endIdx], 10, 32); err == nil {
					m.Count = uint32(val)  // str_range maps to Count field
					if m.Count == 0 {
						// Zero range warning
					}
				}
				l = l[endIdx-1:] // -1 because we'll increment at loop end
			}
			
		case 'W': // CHAR_COMPACT_WHITESPACE
			m.Flags |= STRING_COMPACT_WHITESPACE
			
		case 'w': // CHAR_COMPACT_OPTIONAL_WHITESPACE  
			m.Flags |= STRING_COMPACT_OPTIONAL_WHITESPACE
			
		case 'c': // CHAR_IGNORE_LOWERCASE
			m.Flags |= STRING_IGNORE_LOWERCASE
			
		case 'C': // CHAR_IGNORE_UPPERCASE
			m.Flags |= STRING_IGNORE_UPPERCASE
			
		case 's': // CHAR_REGEX_OFFSET_START
			m.Flags |= REGEX_OFFSET_START
			
		case 'b': // CHAR_BINTEST
			m.Flags |= STRING_BINTEST
			
		case 't': // CHAR_TEXTTEST
			m.Flags |= STRING_TEXTTEST
			
		case 'T': // CHAR_TRIM
			m.Flags |= STRING_TRIM
			
		case 'f': // CHAR_FULL_WORD
			m.Flags |= STRING_FULL_WORD
			
		case 'B': // CHAR_PSTRING_1_BE or CHAR_PSTRING_1_LE (same char)
			// For pstring type, this is 1-byte length
			// Note: in C code, both BE and LE use 'B' 
			if m.TypeStr == "pstring" {
				m.Flags = (m.Flags &^ PSTRING_LEN) | PSTRING_1_LE
			} else {
				// For other types, treat as binary test flag
				m.Flags |= STRING_BINTEST
			}
			
		case 'H': // CHAR_PSTRING_2_BE
			if m.TypeStr != "pstring" {
				return fmt.Errorf("'H' modifier only allowed for pstring")
			}
			m.Flags = (m.Flags &^ PSTRING_LEN) | PSTRING_2_BE
			
		case 'h': // CHAR_PSTRING_2_LE
			if m.TypeStr != "pstring" {
				return fmt.Errorf("'h' modifier only allowed for pstring")
			}
			m.Flags = (m.Flags &^ PSTRING_LEN) | PSTRING_2_LE
			
		case 'L': // CHAR_PSTRING_4_BE
			if m.TypeStr != "pstring" {
				return fmt.Errorf("'L' modifier only allowed for pstring")
			}
			m.Flags = (m.Flags &^ PSTRING_LEN) | PSTRING_4_BE
			
		case 'l': // CHAR_PSTRING_4_LE
			// Can be used for both pstring and regex
			if m.TypeStr == "pstring" || m.TypeStr == "regex" {
				m.Flags = (m.Flags &^ PSTRING_LEN) | PSTRING_4_LE
			} else {
				return fmt.Errorf("'l' modifier only allowed for pstring or regex")
			}
			
		case 'J': // CHAR_PSTRING_LENGTH_INCLUDES_ITSELF
			if m.TypeStr != "pstring" {
				return fmt.Errorf("'J' modifier only allowed for pstring")
			}
			m.Flags |= PSTRING_LENGTH_INCLUDES_ITSELF
			
		case '/':
			// Allow multiple '/' for readability (matching C implementation)
			// Skip this character if not followed by whitespace
			if len(l) > 1 && !isSpace(l[1]) {
				// Continue to next character
			} else {
				// If followed by whitespace or end of string, stop parsing
				goto done
			}
			
		default:
			// Unknown modifier - could be an error
			return fmt.Errorf("unknown string modifier '%c'", ch)
		}
		
		l = l[1:]
	}
	
done:
	*input = l
	return nil
}

// isSpace checks if a character is whitespace
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// Additional string flag constants for pstring length encoding
const (
	// Pstring length encoding flags (mutually exclusive)
	PSTRING_LEN                      uint32 = 0xF0000000
	PSTRING_1_LE                     uint32 = 0x10000000 
	PSTRING_1_BE                     uint32 = 0x10000000 // Same as LE for 1 byte
	PSTRING_2_BE                     uint32 = 0x20000000
	PSTRING_2_LE                     uint32 = 0x30000000
	PSTRING_4_BE                     uint32 = 0x40000000
	PSTRING_4_LE                     uint32 = 0x50000000
	PSTRING_LENGTH_INCLUDES_ITSELF  uint32 = 0x00100000
	
	// Regex line count flag (same position as PSTRING_4_LE)
	REGEX_LINE_COUNT                uint32 = 0x50000000
)