package magic

// TestType represents the test type for pattern matching
type TestType int

const (
	BINTEST TestType = iota
	TEXTTEST
)

type MagicType string

// Base type constants for magic file types
const (
	// Numeric types
	TypeByte               MagicType = "byte"
	TypeUbyte              MagicType = "ubyte"
	TypeShort              MagicType = "short"
	TypeUshort             MagicType = "ushort"
	TypeBeshort            MagicType = "beshort"
	TypeLeshort            MagicType = "leshort"
	TypeBeshort16 MagicType = "beshort16"
	TypeLeshort16 MagicType = "leshort16"
	TypeLong               MagicType = "long"
	TypeUlong              MagicType = "ulong"
	TypeBelong             MagicType = "belong"
	TypeLelong             MagicType = "lelong"
	TypeMelong             MagicType = "melong"
	TypeQuad               MagicType = "quad"
	TypeUquad              MagicType = "uquad"
	TypeBequad             MagicType = "bequad"
	TypeLequad             MagicType = "lequad"
	TypeFloat              MagicType = "float"
	TypeBefloat            MagicType = "befloat"
	TypeLefloat            MagicType = "lefloat"
	TypeDouble             MagicType = "double"
	TypeBedouble           MagicType = "bedouble"
	TypeLedouble           MagicType = "ledouble"
	// Date types
	TypeDate        MagicType = "date"
	TypeBedate      MagicType = "bedate"
	TypeLedate      MagicType = "ledate"
	TypeLdate       MagicType = "ldate"
	TypeBeldate     MagicType = "beldate"
	TypeLeldate     MagicType = "leldate"
	TypeMedate      MagicType = "medate"
	TypeMeldate     MagicType = "meldate"
	TypeQdate       MagicType = "qdate"
	TypeLeqdate     MagicType = "leqdate"
	TypeBeqdate     MagicType = "beqdate"
	TypeQldate      MagicType = "qldate"
	TypeLeqldate    MagicType = "leqldate"
	TypeBeqldate    MagicType = "beqldate"
	TypeQwdate      MagicType = "qwdate"
	TypeLeqwdate    MagicType = "leqwdate"
	TypeBeqwdate    MagicType = "beqwdate"
	TypeMsdosdate   MagicType = "msdosdate"
	TypeBemsdosdate MagicType = "bemsdosdate"
	TypeLemsdosdate MagicType = "lemsdosdate"
	TypeMsdostime   MagicType = "msdostime"
	TypeBemsdostime MagicType = "bemsdostime"
	TypeLemsdostime MagicType = "lemsdostime"

	// Variable-length integer types
	TypeBevarint MagicType = "bevarint"
	TypeLevarint MagicType = "levarint"

	// Special types
	TypeDer      MagicType = "der"
	TypeGuid     MagicType = "guid"
	TypeOffset   MagicType = "offset"
	TypeOctal    MagicType = "octal"
	TypeIndirect MagicType = "indirect"
	TypeDefault  MagicType = "default"
	TypeClear    MagicType = "clear"
	TypeName     MagicType = "name"
	TypeUse      MagicType = "use"

	// String types
	TypeString     MagicType = "string"
	TypePstring    MagicType = "pstring"
	TypeBestring16 MagicType = "bestring16"
	TypeLestring16 MagicType = "lestring16"
	TypeRegex      MagicType = "regex"
	TypeSearch     MagicType = "search"
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
