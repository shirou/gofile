package magic

import (
	"fmt"
	"strings"
)

// Entry represents a single magic entry from a magic file
type Entry struct {
	Level           int         // Indentation level (0 for primary, >0 for continuation)
	Offset          string      // Offset specification (can be complex expression)
	Type            string      // Data type (byte, short, long, string, etc.)
	Test            string      // Test value or operator
	Message         string      // Message to output when matched
	Strength        int         // Calculated strength value
	StrengthMod     string      // Strength modifier from !:strength directive
	LineNumber      int         // Line number in source file
	SourceFile      string      // Source file name
	Flags           []string    // Modifier flags
	MimeType        string      // MIME type if specified
	Extensions      []string    // File extensions if specified
	Binary          bool        // True if this is a binary pattern
	IsNameType      bool        // True if this is a FILE_NAME type pattern
	Children        []*Entry    // Child entries (continuation lines)
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

// CalculateStrength calculates the strength value for an entry
func (e *Entry) CalculateStrength() int {
	const (
		BASE_STRENGTH = 20
		MULT          = 10
	)
	
	strength := BASE_STRENGTH
	
	// Calculate value length for string types
	valueLen := e.calculateValueLength()
	
	// Base strength by type
	switch strings.ToLower(e.Type) {
	case "string", "pstring":
		// String length contributes to strength
		strength += valueLen * MULT
		
	case "byte", "ubyte":
		strength += 1 * MULT // 1 byte
		
	case "short", "ushort", "beshort", "leshort", "beshort16", "leshort16":
		strength += 2 * MULT // 2 bytes
		
	case "long", "ulong", "belong", "lelong", "melong":
		strength += 4 * MULT // 4 bytes
		
	case "quad", "uquad", "bequad", "lequad":
		strength += 8 * MULT // 8 bytes
		
	case "float", "befloat", "lefloat":
		strength += 4 * MULT // 4 bytes
		
	case "double", "bedouble", "ledouble":
		strength += 8 * MULT // 8 bytes
		
	case "regex":
		// Count literal characters in regex
		literals := 0
		escaped := false
		for _, ch := range e.Test {
			if escaped {
				literals++
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if strings.ContainsRune("^$.*+?[]{}()|", ch) {
				// Regex metacharacters don't count
			} else {
				literals++
			}
		}
		strength += (literals * MULT) / 2
		
	case "search":
		strength += valueLen * MULT
		// Search has additional penalty based on range (not implemented yet)
		
	case "default", "clear":
		return 0 // These have no strength
		
	default:
		// Unknown types get base strength only
	}
	
	// Add operator modifier (default is exact match)
	// For now, assume exact match (+10) for all tests
	strength += 10
	
	// Apply continuation level penalty
	if e.Level > 0 {
		reduction := 1.0 - (0.1 * float64(e.Level))
		if reduction < 0 {
			reduction = 0
		}
		strength = int(float64(strength) * reduction)
	}
	
	// Apply manual strength modifier if present
	if e.StrengthMod != "" {
		mod := e.StrengthMod
		if strings.HasPrefix(mod, "+") {
			var modifier int
			fmt.Sscanf(mod[1:], "%d", &modifier)  // Skip the '+' sign
			strength += modifier
		} else if strings.HasPrefix(mod, "-") {
			var modifier int
			fmt.Sscanf(mod[1:], "%d", &modifier)  // Skip the '-' sign
			strength -= modifier  // Subtract the absolute value
		} else if strings.HasPrefix(mod, "*") {
			var multiplier int
			fmt.Sscanf(mod[1:], "%d", &multiplier)
			strength *= multiplier
		} else if strings.HasPrefix(mod, "/") {
			var divisor int
			fmt.Sscanf(mod[1:], "%d", &divisor)
			if divisor != 0 {
				strength /= divisor
			}
		} else {
			// Absolute value
			var absolute int
			fmt.Sscanf(mod, "%d", &absolute)
			strength = absolute
		}
	}
	
	return strength
}

// calculateValueLength calculates the actual byte length of the test value
func (e *Entry) calculateValueLength() int {
	if e.Type != "string" && e.Type != "pstring" && e.Type != "search" {
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