package magic

// TestType represents the test type for pattern matching
type TestType int

const (
	BINTEST TestType = iota
	TEXTTEST
)

type MagicType int8

// Base type constants for magic file types
const (
	// Invalid type
	TypeInvalid MagicType = iota
	
	// Numeric types
	TypeByte
	TypeShort
	TypeDefault
	TypeLong
	TypeString
	TypeDate
	TypeBeshort
	TypeBelong
	TypeBedate
	TypeLeshort
	TypeLelong
	TypeLedate
	TypePstring
	TypeLdate
	TypeBeldate
	TypeLeldate
	TypeRegex
	TypeBestring16
	TypeLestring16
	TypeSearch
	TypeMedate
	TypeMeldate
	TypeMelong
	TypeQuad
	TypeLequad
	TypeBequad
	TypeQdate
	TypeLeqdate
	TypeBeqdate
	TypeQldate
	TypeLeqldate
	TypeBeqldate
	TypeFloat
	TypeBefloat
	TypeLefloat
	TypeDouble
	TypeBedouble
	TypeLedouble
	TypeLeid3
	TypeBeid3
	TypeIndirect
	TypeQwdate
	TypeLeqwdate
	TypeBeqwdate
	TypeName
	TypeUse
	TypeClear
	TypeDer
	TypeGuid
	TypeOffset
	TypeBevarint
	TypeLevarint
	TypeMsdosdate
	TypeLemsdosdate
	TypeBemsdosdate
	TypeMsdostime
	TypeLemsdostime
	TypeBemsdostime
	TypeOctal
	
	// Additional types not in FILE_* constants
	TypeUbyte
	TypeUshort
	TypeBeshort16
	TypeLeshort16
	TypeUlong
	TypeUquad
)

// ToString returns the string representation of a MagicType
func (t MagicType) ToString() string {
	switch t {
	case TypeInvalid:
		return "invalid"
	case TypeByte:
		return "byte"
	case TypeShort:
		return "short"
	case TypeDefault:
		return "default"
	case TypeLong:
		return "long"
	case TypeString:
		return "string"
	case TypeDate:
		return "date"
	case TypeBeshort:
		return "beshort"
	case TypeBelong:
		return "belong"
	case TypeBedate:
		return "bedate"
	case TypeLeshort:
		return "leshort"
	case TypeLelong:
		return "lelong"
	case TypeLedate:
		return "ledate"
	case TypePstring:
		return "pstring"
	case TypeLdate:
		return "ldate"
	case TypeBeldate:
		return "beldate"
	case TypeLeldate:
		return "leldate"
	case TypeRegex:
		return "regex"
	case TypeBestring16:
		return "bestring16"
	case TypeLestring16:
		return "lestring16"
	case TypeSearch:
		return "search"
	case TypeMedate:
		return "medate"
	case TypeMeldate:
		return "meldate"
	case TypeMelong:
		return "melong"
	case TypeQuad:
		return "quad"
	case TypeLequad:
		return "lequad"
	case TypeBequad:
		return "bequad"
	case TypeQdate:
		return "qdate"
	case TypeLeqdate:
		return "leqdate"
	case TypeBeqdate:
		return "beqdate"
	case TypeQldate:
		return "qldate"
	case TypeLeqldate:
		return "leqldate"
	case TypeBeqldate:
		return "beqldate"
	case TypeFloat:
		return "float"
	case TypeBefloat:
		return "befloat"
	case TypeLefloat:
		return "lefloat"
	case TypeDouble:
		return "double"
	case TypeBedouble:
		return "bedouble"
	case TypeLedouble:
		return "ledouble"
	case TypeLeid3:
		return "leid3"
	case TypeBeid3:
		return "beid3"
	case TypeIndirect:
		return "indirect"
	case TypeQwdate:
		return "qwdate"
	case TypeLeqwdate:
		return "leqwdate"
	case TypeBeqwdate:
		return "beqwdate"
	case TypeName:
		return "name"
	case TypeUse:
		return "use"
	case TypeClear:
		return "clear"
	case TypeDer:
		return "der"
	case TypeGuid:
		return "guid"
	case TypeOffset:
		return "offset"
	case TypeBevarint:
		return "bevarint"
	case TypeLevarint:
		return "levarint"
	case TypeMsdosdate:
		return "msdosdate"
	case TypeLemsdosdate:
		return "lemsdosdate"
	case TypeBemsdosdate:
		return "bemsdosdate"
	case TypeMsdostime:
		return "msdostime"
	case TypeLemsdostime:
		return "lemsdostime"
	case TypeBemsdostime:
		return "bemsdostime"
	case TypeOctal:
		return "octal"
	case TypeUbyte:
		return "ubyte"
	case TypeUshort:
		return "ushort"
	case TypeBeshort16:
		return "beshort16"
	case TypeLeshort16:
		return "leshort16"
	case TypeUlong:
		return "ulong"
	case TypeUquad:
		return "uquad"
	default:
		return "unknown"
	}
}

// MagicTypeFromString converts a string to a MagicType
func MagicTypeFromString(s string) MagicType {
	switch s {
	case "invalid":
		return TypeInvalid
	case "byte":
		return TypeByte
	case "short":
		return TypeShort
	case "default":
		return TypeDefault
	case "long":
		return TypeLong
	case "string":
		return TypeString
	case "date":
		return TypeDate
	case "beshort":
		return TypeBeshort
	case "belong":
		return TypeBelong
	case "bedate":
		return TypeBedate
	case "leshort":
		return TypeLeshort
	case "lelong":
		return TypeLelong
	case "ledate":
		return TypeLedate
	case "pstring":
		return TypePstring
	case "ldate":
		return TypeLdate
	case "beldate":
		return TypeBeldate
	case "leldate":
		return TypeLeldate
	case "regex":
		return TypeRegex
	case "bestring16":
		return TypeBestring16
	case "lestring16":
		return TypeLestring16
	case "search":
		return TypeSearch
	case "medate":
		return TypeMedate
	case "meldate":
		return TypeMeldate
	case "melong":
		return TypeMelong
	case "quad":
		return TypeQuad
	case "lequad":
		return TypeLequad
	case "bequad":
		return TypeBequad
	case "qdate":
		return TypeQdate
	case "leqdate":
		return TypeLeqdate
	case "beqdate":
		return TypeBeqdate
	case "qldate":
		return TypeQldate
	case "leqldate":
		return TypeLeqldate
	case "beqldate":
		return TypeBeqldate
	case "float":
		return TypeFloat
	case "befloat":
		return TypeBefloat
	case "lefloat":
		return TypeLefloat
	case "double":
		return TypeDouble
	case "bedouble":
		return TypeBedouble
	case "ledouble":
		return TypeLedouble
	case "leid3":
		return TypeLeid3
	case "beid3":
		return TypeBeid3
	case "indirect":
		return TypeIndirect
	case "qwdate":
		return TypeQwdate
	case "leqwdate":
		return TypeLeqwdate
	case "beqwdate":
		return TypeBeqwdate
	case "name":
		return TypeName
	case "use":
		return TypeUse
	case "clear":
		return TypeClear
	case "der":
		return TypeDer
	case "guid":
		return TypeGuid
	case "offset":
		return TypeOffset
	case "bevarint":
		return TypeBevarint
	case "levarint":
		return TypeLevarint
	case "msdosdate":
		return TypeMsdosdate
	case "lemsdosdate":
		return TypeLemsdosdate
	case "bemsdosdate":
		return TypeBemsdosdate
	case "msdostime":
		return TypeMsdostime
	case "lemsdostime":
		return TypeLemsdostime
	case "bemsdostime":
		return TypeBemsdostime
	case "octal":
		return TypeOctal
	case "ubyte":
		return TypeUbyte
	case "ushort":
		return TypeUshort
	case "beshort16":
		return TypeBeshort16
	case "leshort16":
		return TypeLeshort16
	case "ulong":
		return TypeUlong
	case "uquad":
		return TypeUquad
	default:
		return TypeInvalid
	}
}

// Mask operation constants (matching file command's FILE_OPS_* definitions)
const (
	FILE_OPS_MASK   uint8 = 0x07 // Mask for operator flags
	FILE_OPINVERSE  uint8 = 0x40 // Inverse flag
	FILE_OPINDIRECT uint8 = 0x80 // Indirect flag

	// Specific operators
	FILE_OPAND      uint8 = 0 // &
	FILE_OPOR       uint8 = 1 // |
	FILE_OPXOR      uint8 = 2 // ^
	FILE_OPADD      uint8 = 3 // +
	FILE_OPMINUS    uint8 = 4 // -
	FILE_OPMULTIPLY uint8 = 5 // *
	FILE_OPDIVIDE   uint8 = 6 // /
	FILE_OPMODULO   uint8 = 7 // %
)

// String flag constants (for the Flags field in Magic struct)
// These match the C implementation's string flags
const (
	STRING_COMPACT_WHITESPACE          uint32 = 1 << 0 // 'W' flag
	STRING_COMPACT_OPTIONAL_WHITESPACE uint32 = 1 << 1 // 'w' flag
	STRING_IGNORE_LOWERCASE            uint32 = 1 << 2 // 'c' flag
	STRING_IGNORE_UPPERCASE            uint32 = 1 << 3 // 'C' flag
	STRING_IGNORE_CASE                        = STRING_IGNORE_LOWERCASE | STRING_IGNORE_UPPERCASE
	REGEX_OFFSET_START                 uint32 = 1 << 4 // 's' flag for regex
	STRING_BINTEST                     uint32 = 1 << 5 // 'b' flag
	STRING_TEXTTEST                    uint32 = 1 << 6 // 't' flag
	STRING_TRIM                        uint32 = 1 << 7 // 'T' flag
	STRING_FULL_WORD                   uint32 = 1 << 8 // 'f' flag

	// Old names kept for compatibility (deprecated)
	STRING_FLAG_COMPACT_WHITESPACE                 = STRING_COMPACT_WHITESPACE
	STRING_FLAG_COMPACT_OPTIONAL_WHITESPACE        = STRING_COMPACT_OPTIONAL_WHITESPACE
	STRING_FLAG_BLANK                       uint32 = 1 << 9  // 'b' flag (old)
	STRING_FLAG_OPTIONAL_BLANK              uint32 = 1 << 10 // 'B' flag (old)
	STRING_FLAG_CASE_INSENSITIVE                   = STRING_IGNORE_CASE
	STRING_FLAG_TEXT                               = STRING_TEXTTEST
	STRING_FLAG_TRIM                               = STRING_TRIM
	STRING_FLAG_NOSPACE                     uint32 = 1 << 11 // 'R' flag (old)
	STRING_FLAG_BINTEST                            = STRING_BINTEST
	STRING_FLAG_TEXTTEST                           = STRING_TEXTTEST
	STRING_FLAG_LINE                        uint32 = 1 << 12 // 'l' flag (old)
	STRING_FLAG_FULL_WORD                          = STRING_FULL_WORD
)

// Factor operation constants (for strength modifiers)
const (
	FILE_FACTOR_OP_NONE  uint8 = 0   // '\0' - no operation
	FILE_FACTOR_OP_PLUS  uint8 = '+' // '+' - addition
	FILE_FACTOR_OP_MINUS uint8 = '-' // '-' - subtraction
	FILE_FACTOR_OP_TIMES uint8 = '*' // '*' - multiplication
	FILE_FACTOR_OP_DIV   uint8 = '/' // '/' - division
)

// Note: File type constants have been replaced by MagicType constants above
