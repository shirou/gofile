package magic

import "bytes"

// MULT is the multiplier used in strength calculation, matching the C code.
const strengthMULT = 10

// compareMagicEntry compares two MagicEntry values field-by-field in the same
// order as the C struct magic layout (used by memcmp in apprentice_sort).
// Returns positive if a should sort before b, negative if after, 0 if equal.
func compareMagicEntry(a, b *MagicEntry) int {
	// C struct order: flag, cont_level, factor(unused), reln, vallen, type, in_type, ...
	if a.Flag != b.Flag {
		return int(a.Flag) - int(b.Flag)
	}
	if a.ContLevel != b.ContLevel {
		return int(a.ContLevel) - int(b.ContLevel)
	}
	// factor: mapped from StrengthOp
	fa, fb := strengthOpToByte(a.StrengthOp), strengthOpToByte(b.StrengthOp)
	if fa != fb {
		return int(fa) - int(fb)
	}
	if a.Relation != b.Relation {
		return int(a.Relation) - int(b.Relation)
	}
	// vallen
	va, vb := len(a.Value.Str), len(b.Value.Str)
	if va > 255 {
		va = 255
	}
	if vb > 255 {
		vb = 255
	}
	if va != vb {
		return va - vb
	}
	if a.Type != b.Type {
		return int(a.Type) - int(b.Type)
	}
	if a.InType != b.InType {
		return int(a.InType) - int(b.InType)
	}
	if a.InOp != b.InOp {
		return int(a.InOp) - int(b.InOp)
	}
	if a.MaskOp != b.MaskOp {
		return int(a.MaskOp) - int(b.MaskOp)
	}
	if a.Offset != b.Offset {
		return int(a.Offset) - int(b.Offset)
	}
	if a.InOffset != b.InOffset {
		return int(a.InOffset) - int(b.InOffset)
	}
	// lineno is zeroed in C comparison — skip
	if a.NumMask != b.NumMask {
		if a.NumMask < b.NumMask {
			return -1
		}
		return 1
	}
	// value comparison
	if c := bytes.Compare(a.Value.Str, b.Value.Str); c != 0 {
		return c
	}
	if a.Value.Numeric != b.Value.Numeric {
		if a.Value.Numeric < b.Value.Numeric {
			return -1
		}
		return 1
	}
	// desc, mimetype, apple, ext
	if a.Desc != b.Desc {
		if a.Desc < b.Desc {
			return -1
		}
		return 1
	}
	if a.MimeType != b.MimeType {
		if a.MimeType < b.MimeType {
			return -1
		}
		return 1
	}
	if a.Apple != b.Apple {
		if a.Apple < b.Apple {
			return -1
		}
		return 1
	}
	if a.Ext != b.Ext {
		if a.Ext < b.Ext {
			return -1
		}
		return 1
	}
	return 0
}

// vallen returns the string value length capped at 255 (uint8),
// matching the C struct magic.vallen field.
func vallen(entry *MagicEntry) int {
	l := len(entry.Value.Str)
	if l > 255 {
		l = 255
	}
	return l
}

// nonmagic counts the number of non-magic (literal) characters in a regex
// pattern, matching the C file(1) nonmagic() function from apprentice.c.
func nonmagic(pattern []byte) int {
	rv := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\': // Escaped anything counts 1
			if i+1 < len(pattern) {
				i++
			}
			rv++
		case '?', '*', '.', '+', '^', '$': // Magic characters count 0
			continue
		case '[': // Bracketed expressions count 1 at the ']'
			for i+1 < len(pattern) && pattern[i+1] != ']' {
				i++
			}
			// Don't skip past the ']' — the outer loop's i++ will land on it,
			// matching C's p-- after the while loop.
		case '{': // Braced expressions count 0
			for i < len(pattern) && pattern[i] != '}' {
				i++
			}
			if i >= len(pattern) {
				i--
			}
		default: // Anything else counts 1
			rv++
		}
	}
	if rv == 0 {
		return 1
	}
	return rv
}

func strengthOpToByte(op byte) byte {
	switch op {
	case '+':
		return 1
	case '-':
		return 2
	case '*':
		return 3
	case '/':
		return 4
	default:
		return 0
	}
}

// calcStrength computes the match strength for a top-level magic entry.
// Higher strength = higher priority = matched first.
// Port of file_magic_strength() / apprentice_magic_strength_1() from apprentice.c.
func calcStrength(entry *MagicEntry) int {
	val := 2 * strengthMULT // baseline

	switch entry.Type {
	case TypeByte:
		val += 1 * strengthMULT
	case TypeShort, TypeBEShort, TypeLEShort,
		TypeLEMSDOSDate, TypeLEMSDOSTime, TypeBEMSDOSDate, TypeBEMSDOSTime:
		val += 2 * strengthMULT
	case TypeLong, TypeBELong, TypeLELong, TypeMELong,
		TypeDate, TypeBEDate, TypeLEDate, TypeMEDate,
		TypeLDate, TypeBELDate, TypeLELDate, TypeMELDate,
		TypeFloat, TypeBEFloat, TypeLEFloat,
		TypeBEID3, TypeLEID3:
		val += 4 * strengthMULT
	case TypeQuad, TypeBEQuad, TypeLEQuad,
		TypeDouble, TypeBEDouble, TypeLEDouble,
		TypeQDate, TypeBEQDate, TypeLEQDate,
		TypeQLDate, TypeBEQLDate, TypeLEQLDate,
		TypeQWDate, TypeBEQWDate, TypeLEQWDate,
		TypeOffset:
		val += 8 * strengthMULT
	case TypeGUID:
		val += 16 * strengthMULT
	case TypeString, TypePString, TypeOctal:
		val += vallen(entry) * strengthMULT
	case TypeBEString16, TypeLEString16:
		val += vallen(entry) * strengthMULT / 2
	case TypeSearch:
		l := vallen(entry)
		if l > 0 {
			m := strengthMULT / l
			if m < 1 {
				m = 1
			}
			val += l * m
		}
	case TypeRegex:
		l := nonmagic(entry.Value.Str)
		if l > 0 {
			m := strengthMULT / l
			if m < 1 {
				m = 1
			}
			val += l * m
		}
	case TypeDER:
		val += strengthMULT
	case TypeDefault, TypeClear:
		val = 0
	case TypeIndirect, TypeName, TypeUse:
		val = 0
	}

	// Relation adjustments
	switch entry.Relation {
	case '=':
		val += strengthMULT
	case '!':
		val = 0
	case 'x':
		val = 0
	case '>', '<':
		val -= 2 * strengthMULT
	case '&', '^':
		val -= strengthMULT
	}

	// Apply strength modifier (!:strength +N, -N, *N, /N)
	if entry.StrengthOp != 0 {
		switch entry.StrengthOp {
		case '+':
			val += entry.StrengthDelta
		case '-':
			val -= entry.StrengthDelta
		case '*':
			val *= entry.StrengthDelta
		case '/':
			if entry.StrengthDelta != 0 {
				val /= entry.StrengthDelta
			}
		}
	}

	// Clamp: ensure we only return 0 for FILE_DEFAULT (matching C)
	if val <= 0 {
		val = 1
	}

	// Empty description bonus (applied after factor and clamp, matching C)
	if entry.Desc == "" {
		val++
	}

	return val
}
