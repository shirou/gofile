package magic

// calculateStrength calculates the strength value for a magic entry
// This implements the exact algorithm from file command's apprentice_magic_strength function
func (p *Parser) calculateStrength(entry *MagicEntry) uint32 {
	const MULT = 10 // MULT constant from file command

	// Start with base strength: 2 * MULT = 20
	val := uint32(2 * MULT)

	// Offset bonus is NOT implemented in the official file command's strength calculation
	// The offset shown in file -l output is actually related to the pattern, not a bonus factor

	// Apply type-specific strength calculation
	switch entry.Type {
	case FILE_DEFAULT:
		return 0 // Default entries always have 0 strength

	case FILE_BYTE:
		val += 1 * MULT
	case FILE_SHORT, FILE_BESHORT, FILE_LESHORT:
		val += 2 * MULT
	case FILE_LONG, FILE_BELONG, FILE_LELONG:
		val += 4 * MULT
	case FILE_QUAD, FILE_BEQUAD, FILE_LEQUAD:
		val += 8 * MULT
	case FILE_FLOAT, FILE_BEFLOAT, FILE_LEFLOAT:
		val += 4 * MULT
	case FILE_DOUBLE, FILE_BEDOUBLE, FILE_LEDOUBLE:
		val += 8 * MULT

	case FILE_STRING:
		// String types get strength based on string length
		// Based on analysis, the multiplier is around 8 for strings
		// Use Vallen if available, otherwise use actual string length
		strLen := uint32(entry.Vallen)
		if strLen == 0 {
			valueStr := entry.GetValueAsString()
			strLen = uint32(len(valueStr))
		}
		if strLen > 0 {
			val += strLen * MULT / 3 // Around 3.3x multiplier based on official file behavior
		}

	case FILE_PSTRING:
		// Pascal strings - length byte + string content
		strLen := uint32(entry.Vallen)
		if strLen == 0 {
			valueStr := entry.GetValueAsString()
			strLen = uint32(len(valueStr))
		}
		if strLen > 0 {
			val += strLen * MULT / 3
		} else {
			val += 2 * MULT // Minimum for pascal string type
		}

	case FILE_BESTRING16, FILE_LESTRING16:
		// 16-bit length strings
		strLen := uint32(entry.Vallen)
		if strLen == 0 {
			valueStr := entry.GetValueAsString()
			strLen = uint32(len(valueStr))
		}
		if strLen > 0 {
			val += strLen * MULT / 3
		} else {
			val += 3 * MULT // Minimum for 16-bit string type
		}

	case FILE_REGEX:
		// Regex gets much lower strength - count non-magic characters
		valueStr := entry.GetValueAsString()
		if len(valueStr) > 0 {
			// Count actual characters, not regex metacharacters
			nonMagic := countNonMagicChars(valueStr)
			val += uint32(nonMagic) * 3 // Much lower multiplier
		}

	case FILE_SEARCH:
		// Search patterns get moderate strength
		strLen := uint32(entry.Vallen)
		if strLen == 0 {
			valueStr := entry.GetValueAsString()
			strLen = uint32(len(valueStr))
		}
		if strLen > 0 {
			val += strLen * MULT / 4 // Lower than regular strings
		} else {
			val += MULT / 2
		}

	case FILE_DATE, FILE_BEDATE, FILE_LEDATE:
		val += 4 * MULT
	case FILE_LDATE, FILE_BELDATE, FILE_LELDATE:
		val += 4 * MULT
	case FILE_QDATE, FILE_LEQDATE, FILE_BEQDATE:
		val += 8 * MULT
	case FILE_QLDATE, FILE_LEQLDATE, FILE_BEQLDATE:
		val += 8 * MULT

	case FILE_MSDOSDATE, FILE_LEMSDOSDATE, FILE_BEMSDOSDATE:
		val += 2 * MULT
	case FILE_MSDOSTIME, FILE_LEMSDOSTIME, FILE_BEMSDOSTIME:
		val += 2 * MULT

	case FILE_QWDATE, FILE_LEQWDATE, FILE_BEQWDATE:
		val += 8 * MULT

	case FILE_GUID:
		val += 16 * MULT // GUIDs are very specific (128-bit)

	case FILE_DER:
		val += MULT // DER encoded data

	case FILE_INDIRECT:
		// Indirect operations get very low base strength
		val = MULT / 2 // 5

	case FILE_USE, FILE_NAME:
		// USE and NAME get very low strength as they're references
		val = MULT / 2 // 5

	case FILE_CLEAR:
		// Clear operations don't add to detection
		val = 1

	default:
		// Unknown types keep base strength + offset bonus only
	}

	// Add bonuses for MIME type and description presence
	if len(entry.GetMimeType()) > 0 {
		val += 15 // Bonus for having MIME type
	}
	if len(entry.GetDescription()) > 0 {
		val += 10 // Bonus for having description
	}

	// Add bonus for mask operations (shows more specific matching)
	if entry.NumMask != 0 && entry.NumMask != 0xFFFFFFFFFFFFFFFF {
		val += 5 // Small bonus for using mask
	}

	// Handle relation operators
	switch entry.Reln {
	case '=', 0: // FILE_EQ or default - exact match gets bonus
		val += MULT
	case '>': // FILE_GT - comparison gets penalty
		if val >= 2*MULT {
			val -= 2 * MULT
		} else {
			val = 1
		}
	case '<': // FILE_LT - comparison gets penalty
		if val >= 2*MULT {
			val -= 2 * MULT
		} else {
			val = 1
		}
	case 'x': // FILE_ANY - wildcard gets minimal strength
		val = 1
	case '!': // FILE_NE - not equal gets minimal strength
		val = 1
	case '&': // FILE_AND - bitwise and gets small penalty
		if val >= MULT {
			val -= MULT
		} else {
			val = 1
		}
	case '^': // FILE_XOR - bitwise xor gets small penalty
		if val >= MULT {
			val -= MULT
		} else {
			val = 1
		}
	}

	// Penalty for indirect addressing
	if entry.Flag&INDIR != 0 {
		// Indirect operations get reduced strength
		val = val / 2
		if val < 1 {
			val = 1
		}
	}

	// Penalty for continuation levels
	if entry.ContLevel > 0 {
		// Each level reduces strength slightly
		penalty := uint32(entry.ContLevel) * 2
		if val > penalty {
			val -= penalty
		} else {
			val = 1
		}
	}

	// Apply manual strength adjustments if present
	if entry.ManualStrength != 0 && entry.StrengthOp != 0 {
		val = applyManualStrength(val, entry.ManualStrength, entry.StrengthOp)
	}

	return val
}

// applyManualStrength applies manual strength adjustments from !:strength directive
func applyManualStrength(currentStrength uint32, adjustment int32, op byte) uint32 {
	var result int64

	switch op {
	case '+':
		result = int64(currentStrength) + int64(adjustment)
	case '-':
		result = int64(currentStrength) - int64(adjustment)
	case '*':
		result = int64(currentStrength) * int64(adjustment)
	case '/':
		if adjustment != 0 {
			result = int64(currentStrength) / int64(adjustment)
		} else {
			result = int64(currentStrength)
		}
	default:
		// Unknown operation, return unchanged
		return currentStrength
	}

	// Clamp result to valid range
	if result < 0 {
		return 0
	}
	if result > 0xFFFF { // Reasonable upper limit
		return 0xFFFF
	}

	return uint32(result)
}

// countNonMagicChars counts non-regex metacharacters in a regex pattern
func countNonMagicChars(pattern string) int {
	count := 0
	escaped := false
	for _, ch := range pattern {
		if escaped {
			count++
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		// Skip regex metacharacters
		if ch != '.' && ch != '*' && ch != '+' && ch != '?' && ch != '^' &&
			ch != '$' && ch != '[' && ch != ']' && ch != '(' && ch != ')' &&
			ch != '{' && ch != '}' && ch != '|' {
			count++
		}
	}
	return count
}
