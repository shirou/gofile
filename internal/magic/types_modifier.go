package magic

import (
	"fmt"
	"strings"
)

// getOperatorModifier returns the strength modifier for the operator
func (e *Entry) getOperatorModifier() int {
	switch e.Operator {
	case "=", "": // Exact match (default)
		return 10
	case "!=": // Not equal
		return 0 // No modifier for not equal (proper strength calculation)
	case ">", "<": // Greater/less than
		return -20 // Much less specific
	case "&": // Bitwise AND
		return -10
	case "^": // Bitwise XOR
		return -10
	case "~": // Negation/NOT
		return -10
	case "x": // Always matches (any value)
		return 0 // No strength for 'any' match
	case "!": // Test inversion
		return 0
	default:
		return 10 // Default to exact match modifier
	}
}

// getValueModifier returns strength modifiers based on the test value
func (e *Entry) getValueModifier() int {
	// Value modifiers only apply to exact match operators
	if e.Operator != "=" && e.Operator != "" {
		return 0
	}

	modifier := 0

	// Handle types with parameters (e.g., search/256)
	baseType := strings.ToLower(e.Type)
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	// Check for numeric types
	switch baseType {
	case "byte", "ubyte", "short", "ushort", "beshort", "leshort",
		"long", "ulong", "belong", "lelong", "melong",
		"quad", "uquad", "bequad", "lequad":
		// Parse numeric value
		var val int64
		if strings.HasPrefix(e.Test, "0x") || strings.HasPrefix(e.Test, "0X") {
			fmt.Sscanf(e.Test[2:], "%x", &val)
		} else if strings.HasPrefix(e.Test, "0") && len(e.Test) > 1 {
			fmt.Sscanf(e.Test[1:], "%o", &val)
		} else {
			fmt.Sscanf(e.Test, "%d", &val)
		}

		// Zero value penalty
		if val == 0 {
			modifier -= 10
		} else {
			// Power of 2 penalty (excluding zero)
			if (val & (val - 1)) == 0 {
				modifier -= 5
			}

			// Small value penalty (excluding zero)
			if val > 0 && val < 256 {
				modifier -= 5
			}
		}

	case "string", "pstring":
		// Empty string penalty
		if e.Test == "" {
			modifier -= 20
		} else {
			// Single character penalty
			if len(e.Test) == 1 {
				modifier -= 10
			}

			// Common words penalty (only for lowercase exact matches)
			commonWords := []string{"data", "text", "file", "the", "and", "or", "is", "of"}
			for _, word := range commonWords {
				if e.Test == word {
					modifier -= 5
					break
				}
			}
		}

	case "search":
		// Empty string penalty
		if e.Test == "" {
			modifier -= 20
		} else {
			// Single character penalty
			if len(e.Test) == 1 {
				modifier -= 10
			}

			// Common words penalty (only for lowercase exact matches)
			commonWords := []string{"data", "text", "file", "the", "and", "or", "is", "of"}
			for _, word := range commonWords {
				if e.Test == word {
					modifier -= 5
					break
				}
			}
		}
	}

	return modifier
}
