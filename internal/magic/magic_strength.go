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

// fileMagicStrength calculates the strength of a magic entry
func fileMagicStrength(m *Magic, entry *Entry) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("nil magic entry")
	}

	// Get the base strength from the Magic struct
	val, err := m.apprenticeMagicStrength()
	if err != nil {
		return 0, fmt.Errorf("error calculating magic strength: %w", err)
	}

	// Apply manual strength modifier if present
	switch m.FactorOp {
	case FILE_FACTOR_OP_NONE:
		break
	case FILE_FACTOR_OP_PLUS:
		val += int(m.Factor)
	case FILE_FACTOR_OP_MINUS:
		val -= int(m.Factor)
	case FILE_FACTOR_OP_TIMES:
		val *= int(m.Factor)
	case FILE_FACTOR_OP_DIV:
		if m.Factor == 0 {
			return 0, fmt.Errorf("division by zero in magic strength calculation")
		}
		val /= int(m.Factor)
	}

	// Ensure we only return 0 for FILE_DEFAULT
	if val <= 0 {
		val = 1
	}

	// Magic entries with no description get a bonus
	if m.Desc[0] == 0 {
		val += 1
	}

	return val, nil
}

// apprenticeMagicStrength calculates the strength value for a magic pattern
// This is a port of apprentice_magic_strength_1 from apprentice.c
func (m *Magic) apprenticeMagicStrength() (int, error) {
	const MULT = 10
	const BASE = 2 * MULT // baseline strength
	val := BASE

	// Handle types with parameters (e.g., search/256)
	baseType := strings.ToLower(m.TypeStr)
	if idx := strings.Index(baseType, "/"); idx > 0 {
		baseType = baseType[:idx]
	}

	// Calculate strength based on type
	magicType := MagicTypeFromString(baseType)
	switch magicType {
	case TypeDefault:
		// Default type has no strength regardless of factor_op
		return 0, nil

	case TypeByte, TypeShort, TypeLeshort, TypeBeshort,
		TypeMsdosdate, TypeBemsdosdate, TypeLemsdosdate,
		TypeMsdostime, TypeBemsdostime, TypeLemsdostime,
		TypeLong, TypeLelong, TypeBelong, TypeMelong,
		TypeDate, TypeLedate, TypeBedate, TypeMedate,
		TypeLdate, TypeLeldate, TypeBeldate, TypeMeldate,
		TypeFloat, TypeBefloat, TypeLefloat,
		TypeBeid3, TypeLeid3,
		TypeQuad, TypeBequad, TypeLequad,
		TypeQdate, TypeLeqdate, TypeBeqdate,
		TypeQldate, TypeLeqldate, TypeBeqldate,
		TypeQwdate, TypeLeqwdate, TypeBeqwdate,
		TypeDouble, TypeBedouble, TypeLedouble,
		TypeOffset, TypeBevarint, TypeLevarint,
		TypeGuid:
		ts := magicType.Size()
		if ts == 0 {
			return 0, fmt.Errorf("Invalid type size for type %s", magicType)
		}
		val += ts * MULT
	case TypePstring, TypeString, TypeOctal:
		// Use vallen (actual value length) * MULT
		// If vallen is 0, use the TestStr length as fallback
		vallen := m.Vallen
		if vallen == 0 && m.TestStr != "" {
			vallen = uint8(len(m.TestStr))
			if vallen > MAXstring {
				vallen = MAXstring
			}
		}
		val += int(vallen) * MULT
	case TypeBestring16, TypeLestring16:
		// String16 types use half the value length
		if m.Vallen == 0 {
			return 0, fmt.Errorf("Zero vallen for type %s", magicType)
		}
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
	case TypeIndirect, TypeName, TypeUse, TypeClear:
		break
	case TypeDer:
		// DER type adds exactly MULT (matches original file command)
		val += MULT
	default:
		// Unknown types get base strength only
		return 0, fmt.Errorf("unknown magic type %s", m.TypeStr)
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

	return val, nil
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
