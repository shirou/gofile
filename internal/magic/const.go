package magic

// TestType represents the test type for pattern matching
type TestType int

const (
	BINTEST TestType = iota
	TEXTTEST
)

// Base type constants for magic file types
const (
	// Numeric types
	TypeByte      = "byte"
	TypeUbyte     = "ubyte"
	TypeShort     = "short"
	TypeUshort    = "ushort"
	TypeBeshort   = "beshort"
	TypeLeshort   = "leshort"
	TypeBeshort16 = "beshort16"
	TypeLeshort16 = "leshort16"
	TypeLong      = "long"
	TypeUlong     = "ulong"
	TypeBelong    = "belong"
	TypeLelong    = "lelong"
	TypeMelong    = "melong"
	TypeQuad      = "quad"
	TypeUquad     = "uquad"
	TypeBequad    = "bequad"
	TypeLequad    = "lequad"
	TypeFloat     = "float"
	TypeBefloat   = "befloat"
	TypeLefloat   = "lefloat"
	TypeDouble    = "double"
	TypeBedouble  = "bedouble"
	TypeLedouble  = "ledouble"

	// Date types
	TypeDate        = "date"
	TypeBedate      = "bedate"
	TypeLedate      = "ledate"
	TypeLdate       = "ldate"
	TypeBeldate     = "beldate"
	TypeLeldate     = "leldate"
	TypeMedate      = "medate"
	TypeMeldate     = "meldate"
	TypeQdate       = "qdate"
	TypeLeqdate     = "leqdate"
	TypeBeqdate     = "beqdate"
	TypeQldate      = "qldate"
	TypeLeqldate    = "leqldate"
	TypeBeqldate    = "beqldate"
	TypeQwdate      = "qwdate"
	TypeLeqwdate    = "leqwdate"
	TypeBeqwdate    = "beqwdate"
	TypeMsdosdate   = "msdosdate"
	TypeBemsdosdate = "bemsdosdate"
	TypeLemsdosdate = "lemsdosdate"
	TypeMsdostime   = "msdostime"
	TypeBemsdostime = "bemsdostime"
	TypeLemsdostime = "lemsdostime"

	// Variable-length integer types
	TypeBevarint = "bevarint"
	TypeLevarint = "levarint"

	// Special types
	TypeDer      = "der"
	TypeGuid     = "guid"
	TypeOffset   = "offset"
	TypeOctal    = "octal"
	TypeIndirect = "indirect"
	TypeDefault  = "default"
	TypeClear    = "clear"
	TypeName     = "name"
	TypeUse      = "use"

	// String types
	TypeString     = "string"
	TypePstring    = "pstring"
	TypeBestring16 = "bestring16"
	TypeLestring16 = "lestring16"
	TypeRegex      = "regex"
	TypeSearch     = "search"
)

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
	STRING_COMPACT_WHITESPACE          uint32 = 1 << 0  // 'W' flag
	STRING_COMPACT_OPTIONAL_WHITESPACE uint32 = 1 << 1  // 'w' flag
	STRING_IGNORE_LOWERCASE            uint32 = 1 << 2  // 'c' flag
	STRING_IGNORE_UPPERCASE            uint32 = 1 << 3  // 'C' flag
	STRING_IGNORE_CASE                 = STRING_IGNORE_LOWERCASE | STRING_IGNORE_UPPERCASE
	REGEX_OFFSET_START                 uint32 = 1 << 4  // 's' flag for regex
	STRING_BINTEST                     uint32 = 1 << 5  // 'b' flag
	STRING_TEXTTEST                    uint32 = 1 << 6  // 't' flag
	STRING_TRIM                        uint32 = 1 << 7  // 'T' flag
	STRING_FULL_WORD                   uint32 = 1 << 8  // 'f' flag
	
	// Old names kept for compatibility (deprecated)
	STRING_FLAG_COMPACT_WHITESPACE          = STRING_COMPACT_WHITESPACE
	STRING_FLAG_COMPACT_OPTIONAL_WHITESPACE = STRING_COMPACT_OPTIONAL_WHITESPACE
	STRING_FLAG_BLANK                       uint32 = 1 << 9  // 'b' flag (old)
	STRING_FLAG_OPTIONAL_BLANK              uint32 = 1 << 10 // 'B' flag (old)
	STRING_FLAG_CASE_INSENSITIVE            = STRING_IGNORE_CASE
	STRING_FLAG_TEXT                        = STRING_TEXTTEST
	STRING_FLAG_TRIM                        = STRING_TRIM
	STRING_FLAG_NOSPACE                     uint32 = 1 << 11 // 'R' flag (old)
	STRING_FLAG_BINTEST                     = STRING_BINTEST
	STRING_FLAG_TEXTTEST                    = STRING_TEXTTEST
	STRING_FLAG_LINE                        uint32 = 1 << 12 // 'l' flag (old)
	STRING_FLAG_FULL_WORD                   = STRING_FULL_WORD
)

// Factor operation constants (for strength modifiers)
const (
	FILE_FACTOR_OP_NONE  uint8 = 0    // '\0' - no operation
	FILE_FACTOR_OP_PLUS  uint8 = '+'  // '+' - addition
	FILE_FACTOR_OP_MINUS uint8 = '-'  // '-' - subtraction
	FILE_FACTOR_OP_TIMES uint8 = '*'  // '*' - multiplication
	FILE_FACTOR_OP_DIV   uint8 = '/'  // '/' - division
)

// File type constants (numeric values for Magic.Type field)
const (
	FILE_INVALID uint8 = iota
	FILE_BYTE
	FILE_SHORT
	FILE_DEFAULT
	FILE_LONG
	FILE_STRING
	FILE_DATE
	FILE_BESHORT
	FILE_BELONG
	FILE_BEDATE
	FILE_LESHORT
	FILE_LELONG
	FILE_LEDATE
	FILE_PSTRING
	FILE_LDATE
	FILE_BELDATE
	FILE_LELDATE
	FILE_REGEX
	FILE_BESTRING16
	FILE_LESTRING16
	FILE_SEARCH
	FILE_MEDATE
	FILE_MELDATE
	FILE_MELONG
	FILE_QUAD
	FILE_LEQUAD
	FILE_BEQUAD
	FILE_QDATE
	FILE_LEQDATE
	FILE_BEQDATE
	FILE_QLDATE
	FILE_LEQLDATE
	FILE_BEQLDATE
	FILE_FLOAT
	FILE_BEFLOAT
	FILE_LEFLOAT
	FILE_DOUBLE
	FILE_BEDOUBLE
	FILE_LEDOUBLE
	FILE_LEID3
	FILE_BEID3
	FILE_INDIRECT
	FILE_QWDATE
	FILE_LEQWDATE
	FILE_BEQWDATE
	FILE_NAME
	FILE_USE
	FILE_CLEAR
	FILE_DER
	FILE_GUID
	FILE_OFFSET
	FILE_BEVARINT
	FILE_LEVARINT
	FILE_MSDOSDATE
	FILE_LEMSDOSDATE
	FILE_BEMSDOSDATE
	FILE_MSDOSTIME
	FILE_LEMSDOSTIME
	FILE_BEMSDOSTIME
	FILE_OCTAL
)
