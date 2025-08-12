package magic

import (
	"fmt"
	"strconv"
	"strings"
)

// nonmagic counts non-magic (literal) characters in a regex pattern
// This is a port of the nonmagic function from apprentice.c
func (m *Magic) nonmagic(str string) int {
	rv := 0
	i := 0

	for i < len(str) {
		switch str[i] {
		case '\\':
			// Escaped character - count it
			if i+1 < len(str) {
				i++
			}
			rv++
		case '?', '*', '.', '+', '^', '$':
			// Regex metacharacters - don't count
		case '[':
			// Character class - skip until ']'
			for i < len(str) && str[i] != ']' {
				i++
			}
			if i > 0 {
				i--
			}
		case '{':
			// Repetition - skip until '}'
			for i < len(str) && str[i] != '}' {
				i++
			}
			if i >= len(str) {
				i--
			}
		default:
			// Regular character - count it
			rv++
		}
		i++
	}

	if rv == 0 {
		return 1
	}
	return rv
}

// apprenticeMagicStrength calculates the strength value for a magic pattern
// This is a port of apprentice_magic_strength_1 from apprentice.c
func (m *Magic) apprenticeMagicStrength() int {
	const MULT = 10
	const BASE = 20 // baseline strength (same as 2 * MULT)
	val := BASE

	// Calculate Vallen if not already set (for string types)
	if m.Vallen == 0 && (m.TypeStr == TypeString.ToString() || m.TypeStr == TypePstring.ToString() || 
		m.TypeStr == TypeSearch.ToString() || strings.HasPrefix(m.TypeStr, "search/")) {
		m.Vallen = uint8(m.calculateValueLength())
	}

	// Handle types with parameters (e.g., search/256)
	baseType := strings.ToLower(m.TypeStr)
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	// Calculate strength based on type
	switch MagicTypeFromString(baseType) {
	case TypeDefault:
		// Default type has no strength regardless of factor_op
		return 0

	case TypeByte, TypeUbyte:
		val += 1 * MULT

	case TypeShort, TypeUshort, TypeBeshort, TypeLeshort, TypeBeshort16, TypeLeshort16,
		TypeMsdosdate, TypeBemsdosdate, TypeLemsdosdate,
		TypeMsdostime, TypeBemsdostime, TypeLemsdostime:
		val += 2 * MULT

	case TypeLong, TypeUlong, TypeBelong, TypeLelong, TypeMelong,
		TypeFloat, TypeBefloat, TypeLefloat,
		TypeDate, TypeBedate, TypeLedate, TypeLdate, TypeBeldate, TypeLeldate,
		TypeMedate, TypeMeldate:
		val += 4 * MULT

	case TypeQuad, TypeUquad, TypeBequad, TypeLequad,
		TypeDouble, TypeBedouble, TypeLedouble,
		TypeQdate, TypeLeqdate, TypeBeqdate,
		TypeQldate, TypeLeqldate, TypeBeqldate,
		TypeQwdate, TypeLeqwdate, TypeBeqwdate:
		val += 8 * MULT

	case TypePstring, TypeString, TypeOctal:
		// Use vallen (actual value length) * MULT
		val += int(m.Vallen) * MULT

	case TypeBestring16, TypeLestring16:
		// String16 types use half the value length
		val += int(m.Vallen) * MULT / 2

	case TypeSearch:
		if m.Vallen == 0 {
			break
		}
		// Use vallen * MAX(MULT / vallen, 1)
		multiplier := int(MULT) / int(m.Vallen)
		if multiplier < 1 {
			multiplier = 1
		}
		val += int(m.Vallen) * multiplier

	case TypeRegex:
		// Count non-magic characters in regex
		v := m.nonmagic(m.TestStr)
		if v == 0 {
			v = 1
		}
		multiplier := int(MULT) / int(v)
		if multiplier < 1 {
			multiplier = 1
		}
		val += int(v) * multiplier

	case TypeGuid, TypeDer:
		// These have a fixed moderate strength
		val += 5 * MULT

	case TypeIndirect, TypeName, TypeUse:
		// These have a fixed moderate strength
		val += 3 * MULT

	case TypeOffset:
		// Offset type has minimal strength
		val += 1 * MULT

	case TypeClear:
		// Clear has no strength
		return 0

	default:
		// Unknown types get base strength only
		// Keep the baseline val = 2 * MULT
	}

	// Convert OperatorStr to Reln if Reln is not set
	if m.Reln == 0 && m.OperatorStr != "" {
		switch m.OperatorStr {
		case "x":
			m.Reln = 'x'
		case "!":
			m.Reln = '!'
		case "!=":
			m.Reln = '!' // != is treated like ! for strength
		case "=", "":
			m.Reln = '='
		case ">":
			m.Reln = '>'
		case "<":
			m.Reln = '<'
		case "&":
			m.Reln = '&'
		case "^":
			m.Reln = '^'
		case "~":
			m.Reln = '~'
		default:
			m.Reln = '='
		}
	}

	// Adjust strength based on relation/operator
	switch m.Reln {
	case 'x', '!': // matches anything/almost anything - penalize
		val = 0
	case '=', 0: // Exact match - prefer
		val += MULT
	case '>', '<': // comparison match - reduce strength
		val -= 2 * MULT
	case '^', '&', '~': // masking bits
		val -= MULT
	default:
		// Keep current value for unknown operators
	}

	// Ensure non-negative before applying factor operations
	if val < 0 {
		val = 0
	}

	// Apply manual strength modifier if present
	if m.FactorOp != FILE_FACTOR_OP_NONE || m.Factor != 0 {
		switch m.FactorOp {
		case FILE_FACTOR_OP_PLUS:
			val += int(m.Factor)
		case FILE_FACTOR_OP_MINUS:
			val -= int(m.Factor)
			if val < 0 {
				val = 0
			}
		case FILE_FACTOR_OP_TIMES:
			val *= int(m.Factor)
		case FILE_FACTOR_OP_DIV:
			if m.Factor != 0 {
				val /= int(m.Factor)
			}
		case FILE_FACTOR_OP_NONE:
			// Absolute value - set strength directly (when Factor is non-zero)
			if m.Factor != 0 {
				val = int(m.Factor)
			}
		}
	}

	// Apply continuation level penalty if specified
	if m.ContLevel > 0 {
		// Each level reduces strength by 20%
		reduction := 1.0 - (0.2 * float64(m.ContLevel))
		if reduction < 0 {
			reduction = 0
		}
		val = int(float64(val) * reduction)
	}

	return val
}

// ParseStrength parses a strength modifier line from a magic file
// This is a port of the parse_strength function from apprentice.c
// The line format is: !:strength [op]factor
// where op can be +, -, *, / or nothing (for absolute value)
func (m *Magic) ParseStrength(line string) error {
	// Check if strength is already set
	if m.FactorOp != FILE_FACTOR_OP_NONE {
		return fmt.Errorf("current entry already has a strength type: %c %d", m.FactorOp, m.Factor)
	}

	// Disallow strength for name entries (FILE_NAME type)
	if m.TypeStr == "name" || m.IsNameType {
		return fmt.Errorf("strength setting is not supported in \"name\" magic entries")
	}

	// Trim leading/trailing whitespace
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("empty strength value")
	}

	// Parse operator
	var factorStr string
	switch line[0] {
	case '+':
		m.FactorOp = FILE_FACTOR_OP_PLUS
		factorStr = strings.TrimSpace(line[1:])
	case '-':
		m.FactorOp = FILE_FACTOR_OP_MINUS
		factorStr = strings.TrimSpace(line[1:])
	case '*':
		m.FactorOp = FILE_FACTOR_OP_TIMES
		factorStr = strings.TrimSpace(line[1:])
	case '/':
		m.FactorOp = FILE_FACTOR_OP_DIV
		factorStr = strings.TrimSpace(line[1:])
	default:
		// No operator means absolute value (FILE_FACTOR_OP_NONE = 0)
		m.FactorOp = FILE_FACTOR_OP_NONE
		factorStr = line
	}

	// Parse factor value
	factor, err := strconv.ParseUint(factorStr, 0, 8) // 0 for auto-detect base, 8 bits max
	if err != nil {
		return fmt.Errorf("bad factor '%s': %w", factorStr, err)
	}

	// Check factor range (must be 0-255)
	if factor > 255 {
		return fmt.Errorf("too large factor %d (must be 0-255)", factor)
	}

	m.Factor = uint8(factor)

	// Store the original strength modifier string for reference
	if m.FactorOp == FILE_FACTOR_OP_NONE {
		m.StrengthMod = fmt.Sprintf("=%d", m.Factor)
	} else {
		m.StrengthMod = fmt.Sprintf("%c%d", m.FactorOp, m.Factor)
	}

	return nil
}
