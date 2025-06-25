package magic

// MULT is the multiplier used in strength calculation, matching the C code.
const strengthMULT = 10

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
		val += len(entry.Value.Str) * strengthMULT
	case TypeBEString16, TypeLEString16:
		val += len(entry.Value.Str) * strengthMULT / 2
	case TypeSearch:
		l := len(entry.Value.Str)
		if l > 0 {
			m := strengthMULT / l
			if m < 1 {
				m = 1
			}
			val += l * m
		}
	case TypeRegex:
		l := len(entry.Value.Str)
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

	// Empty description bonus
	if entry.Desc == "" {
		val++
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

	// Clamp: non-default entries never go below 1
	if val <= 0 {
		switch entry.Type {
		case TypeDefault, TypeClear:
			val = 0
		default:
			if entry.Relation == 'x' || entry.Relation == '!' {
				val = 0
			} else {
				val = 1
			}
		}
	}

	return val
}
