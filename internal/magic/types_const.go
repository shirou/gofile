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
	TypeByte     = "byte"
	TypeUbyte    = "ubyte"
	TypeShort    = "short"
	TypeUshort   = "ushort"
	TypeBeshort  = "beshort"
	TypeLeshort  = "leshort"
	TypeLong     = "long"
	TypeUlong    = "ulong"
	TypeBelong   = "belong"
	TypeLelong   = "lelong"
	TypeMelong   = "melong"
	TypeQuad     = "quad"
	TypeBequad   = "bequad"
	TypeLequad   = "lequad"
	TypeFloat    = "float"
	TypeBefloat  = "befloat"
	TypeLefloat  = "lefloat"
	TypeDouble   = "double"
	TypeBedouble = "bedouble"
	TypeLedouble = "ledouble"

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
	TypeDer    = "der"
	TypeGuid   = "guid"
	TypeOffset = "offset"
	TypeOctal  = "octal"

	// String types
	TypeString     = "string"
	TypePstring    = "pstring"
	TypeBestring16 = "bestring16"
	TypeLestring16 = "lestring16"
	TypeRegex      = "regex"
	TypeSearch     = "search"
)
