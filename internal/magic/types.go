package magic

// FileType represents the data type to read at the offset.
type FileType uint8

const (
	TypeInvalid FileType = iota
	TypeByte             // 1
	TypeShort            // 2
	TypeDefault          // 3
	TypeLong             // 4
	TypeString           // 5
	TypeDate             // 6
	TypeBEShort          // 7
	TypeBELong           // 8
	TypeBEDate           // 9
	TypeLEShort          // 10
	TypeLELong           // 11
	TypeLEDate           // 12
	TypePString          // 13
	TypeLDate            // 14
	TypeBELDate          // 15
	TypeLELDate          // 16
	TypeRegex            // 17
	TypeBEString16       // 18
	TypeLEString16       // 19
	TypeSearch           // 20
	TypeMEDate           // 21
	TypeMELDate          // 22
	TypeMELong           // 23
	TypeQuad             // 24
	TypeLEQuad           // 25
	TypeBEQuad           // 26
	TypeQDate            // 27
	TypeLEQDate          // 28
	TypeBEQDate          // 29
	TypeQLDate           // 30
	TypeLEQLDate         // 31
	TypeBEQLDate         // 32
	TypeFloat            // 33
	TypeBEFloat          // 34
	TypeLEFloat          // 35
	TypeDouble           // 36
	TypeBEDouble         // 37
	TypeLEDouble         // 38
	TypeBEID3            // 39
	TypeLEID3            // 40
	TypeIndirect         // 41
	TypeQWDate           // 42
	TypeLEQWDate         // 43
	TypeBEQWDate         // 44
	TypeName             // 45
	TypeUse              // 46
	TypeClear            // 47
	TypeDER              // 48
	TypeGUID             // 49
	TypeOffset           // 50
	TypeOctal            // 51
	TypeLEMSDOSDate      // 52
	TypeLEMSDOSTime      // 53
	TypeBEMSDOSDate      // 54
	TypeBEMSDOSTime      // 55
)

// Value holds the parsed test value.
type Value struct {
	Numeric  uint64
	Float    float64
	Str      []byte
	IsString bool
}

// MagicGroup is a top-level entry plus its continuations.
type MagicGroup struct {
	Entries  []*MagicEntry // [0] is top-level, rest are continuations
	Strength int
}

// MagicSet holds all loaded magic rules.
type MagicSet struct {
	Entries    []*MagicEntry
	Groups     []MagicGroup
	NamedRules map[string]int // name -> group index for "name"/"use" references
}

// MagicEntry represents one parsed magic rule line.
type MagicEntry struct {
	ContLevel uint8
	Offset    int32
	Type      FileType
	Unsigned  bool
	Relation  byte
	Value     Value
	Desc      string
	MimeType  string
	Ext       string
	Apple     string
	LineNo    int

	// For search type: range to search within
	StrRange uint32
	// For string types: matching flags
	StrFlags uint32
	// Numeric mask
	NumMask  uint64
	MaskOp   byte // '&', '|', '^', '+', '-', '*', '/', '%'
	HasMask  bool

	// Indirect offset
	Flag     uint16
	InType   FileType
	InOp     byte
	InOffset int32

	// Strength modifier
	StrengthOp    byte // '+', '-', '*', '/'
	StrengthDelta int

	// Date bias (e.g., leldate+631065600 adds bias before formatting)
	DateBias int64
}
