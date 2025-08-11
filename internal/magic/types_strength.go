package magic

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

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
	// Handle types with parameters (e.g., search/256)
	baseType := strings.ToLower(e.Type)
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	switch baseType {
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
		// Search has penalty based on range
		// Default range is 4096 if not specified
		searchRange := 4096
		// Extract range from type if present (e.g., "search/1024")
		if strings.Contains(e.Type, "/") {
			parts := strings.Split(e.Type, "/")
			if len(parts) > 1 {
				if r, err := strconv.Atoi(parts[1]); err == nil && r > 0 {
					searchRange = r
				}
			}
		}
		// Apply range penalty: 10 - (log2(range) * 2)
		if searchRange > 1 {
			rangePenalty := int(math.Log2(float64(searchRange)) * 2)
			strength += 10 - rangePenalty
		}

	case "default", "clear":
		return 0 // These have no strength

	case "der":
		strength += 50 // DER (Distinguished Encoding Rules) has fixed strength

	case "guid":
		strength += 50 // GUID has fixed strength

	case "offset":
		strength += 10 // Offset type has minimal strength

	case "indirect":
		// Indirect type strength depends on the referenced test
		// For now, give it a moderate strength
		strength += 30

	default:
		// Unknown types get base strength only
	}

	// Add operator modifier based on the operator type
	strength += e.getOperatorModifier()

	// Add value-based modifiers
	strength += e.getValueModifier()

	// Add string flag modifiers
	strength += e.getStringFlagModifier()

	// Apply continuation level penalty
	if e.Level > 0 {
		reduction := 1.0 - (0.1 * float64(e.Level))
		if reduction < 0 {
			reduction = 0
		}
		strength = int(float64(strength) * reduction)
	}

	// Apply manual strength modifier if present (before special operator handling)
	if e.StrengthMod != "" {
		mod := e.StrengthMod
		if strings.HasPrefix(mod, "+") {
			var modifier int
			fmt.Sscanf(mod[1:], "%d", &modifier) // Skip the '+' sign
			strength += modifier
		} else if strings.HasPrefix(mod, "-") {
			var modifier int
			fmt.Sscanf(mod[1:], "%d", &modifier) // Skip the '-' sign
			strength -= modifier                 // Subtract the absolute value
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
		}
		// Note: Absolute value setting is not supported by original file command
		// Only +, -, *, / operators are allowed
	}

	// Special case: !, !=, and x operators have minimal strength
	// These operators match almost anything, so they should have lowest priority
	// This is applied AFTER manual strength modifiers to allow overriding if needed
	if e.Operator == "!" || e.Operator == "!=" || e.Operator == "x" {
		// Only apply if no manual strength modifier was specified
		if e.StrengthMod == "" {
			strength = 1 // Minimal strength for these operators
		}
	}

	return strength
}
