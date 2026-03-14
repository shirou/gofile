package magic

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

// .mgc compiled magic file format constants.
const (
	mgcMagicLE = 0xF11E041C // Little-endian magic number

	// Known entry sizes by version. Computed from file_size / (total_entries + 1).
	mgcMinEntrySize = 296
	mgcMaxEntrySize = 512

	// Field offsets within an entry (consistent across versions).
	offContLevel = 0 // uint16
	offFlag      = 2 // uint8
	offFactor    = 3 // uint8
	offReln      = 4 // uint8
	offVallen    = 5 // uint8
	offType      = 6 // uint8
	offInType    = 7 // uint8
	offInOp      = 8 // uint8
	offMaskOp    = 9 // uint8
	// offCond = 10 // uint8 (conditional matching not yet supported)
	offFactorOp = 11  // uint8
	offOffset   = 12  // int32
	offInOffset = 16  // int32
	offLineno   = 20  // uint32
	offNumMask  = 24  // uint64 (or str_range + str_flags for string types)
	offValue    = 32  // 128-byte union
	offDesc     = 160 // 64-byte null-terminated string
	offMimeType = 224 // 80-byte null-terminated string
	offApple    = 304 // 8-byte null-terminated string
	offExt      = 312 // variable-length null-terminated string (fills remaining)

	maxValueLen = 128
	descLen     = 64
	mimeTypeLen = 80
	appleLen    = 8
)

// mgcHeader holds parsed .mgc file header information.
type mgcHeader struct {
	version   uint32
	numBinary uint32
	numText   uint32
	entrySize int
	swapped   bool // true if bytes need swapping
}

// ParseMgcFile reads and parses a compiled .mgc file.
func ParseMgcFile(path string) (*MagicSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading mgc file: %w", err)
	}
	return ParseMgcBytes(data)
}

// ParseMgcBytes parses compiled .mgc data from a byte slice.
func ParseMgcBytes(data []byte) (*MagicSet, error) {
	hdr, err := parseMgcHeader(data)
	if err != nil {
		return nil, err
	}

	total := int(hdr.numBinary + hdr.numText)
	expectedSize := (total + 1) * hdr.entrySize
	if len(data) < expectedSize {
		return nil, fmt.Errorf("mgc file too small: %d < %d", len(data), expectedSize)
	}

	set := &MagicSet{NamedRules: make(map[string]int)}

	for i := 0; i < total; i++ {
		off := (i + 1) * hdr.entrySize // skip header entry
		entryData := data[off : off+hdr.entrySize]
		entry := parseMgcEntry(entryData, hdr)
		if entry != nil {
			set.Entries = append(set.Entries, entry)
		}
	}

	set.buildGroups()
	return set, nil
}

// parseMgcHeader parses the .mgc file header and determines entry size.
func parseMgcHeader(data []byte) (*mgcHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("mgc file too small for header")
	}

	magic := binary.LittleEndian.Uint32(data[0:4])
	swapped := false

	if magic != mgcMagicLE {
		// Try byte-swapped
		magic = binary.BigEndian.Uint32(data[0:4])
		if magic != mgcMagicLE {
			return nil, fmt.Errorf("invalid mgc magic: 0x%08X", binary.LittleEndian.Uint32(data[0:4]))
		}
		swapped = true
	}

	var readU32 func([]byte) uint32
	if swapped {
		readU32 = binary.BigEndian.Uint32
	} else {
		readU32 = binary.LittleEndian.Uint32
	}

	version := readU32(data[4:8])
	numBinary := readU32(data[8:12])
	numText := readU32(data[12:16])

	total := int(numBinary + numText)
	if total == 0 {
		return nil, fmt.Errorf("mgc file has no entries")
	}

	// Compute entry size from file size.
	entrySize := len(data) / (total + 1)
	if entrySize < mgcMinEntrySize || entrySize > mgcMaxEntrySize {
		return nil, fmt.Errorf("computed entry size %d out of range [%d, %d]",
			entrySize, mgcMinEntrySize, mgcMaxEntrySize)
	}

	return &mgcHeader{
		version:   version,
		numBinary: numBinary,
		numText:   numText,
		entrySize: entrySize,
		swapped:   swapped,
	}, nil
}

// parseMgcEntry converts a raw .mgc entry into a MagicEntry.
func parseMgcEntry(raw []byte, hdr *mgcHeader) *MagicEntry {
	if len(raw) < offExt {
		return nil
	}

	var (
		readU16 func([]byte) uint16
		readU32 func([]byte) uint32
		readU64 func([]byte) uint64
	)
	if hdr.swapped {
		readU16 = binary.BigEndian.Uint16
		readU32 = binary.BigEndian.Uint32
		readU64 = binary.BigEndian.Uint64
	} else {
		readU16 = binary.LittleEndian.Uint16
		readU32 = binary.LittleEndian.Uint32
		readU64 = binary.LittleEndian.Uint64
	}

	contLevel := readU16(raw[offContLevel:])
	flag := raw[offFlag]
	factor := raw[offFactor]
	reln := raw[offReln]
	vallen := raw[offVallen]
	typ := FileType(raw[offType])
	inType := FileType(raw[offInType])
	inOp := raw[offInOp]
	maskOp := raw[offMaskOp]
	factorOp := raw[offFactorOp]

	offset := int32(readU32(raw[offOffset:]))
	inOffset := int32(readU32(raw[offInOffset:]))
	lineno := readU32(raw[offLineno:])

	entry := &MagicEntry{
		ContLevel: uint8(contLevel),
		Offset:    offset,
		Type:      typ,
		Relation:  reln,
		LineNo:    int(lineno),
		InType:    inType,
		InOp:      inOp,
		InOffset:  inOffset,
	}

	// Map flag bits
	entry.Flag = mapMgcFlag(flag)
	entry.Unsigned = flag&0x08 != 0 // UNSIGNED

	// Map mask_op
	entry.MaskOp = mapMaskOp(maskOp)
	entry.HasMask = maskOp != 0

	// Map StrFlags from flag bits (BINTEST/TEXTTEST)
	if flag&0x20 != 0 {
		entry.StrFlags |= StrFlagBinaryTest
	}
	if flag&0x40 != 0 {
		entry.StrFlags |= StrFlagTextTest
	}

	// Map strength modifier
	entry.StrengthOp = mapFactorOp(factorOp)
	entry.StrengthDelta = int(factor)

	// Parse value and num_mask based on type
	if isStringType(typ) {
		// For string types, num_mask is split: str_range (4 bytes) + str_flags (4 bytes)
		entry.StrRange = readU32(raw[offNumMask:])
		strFlags := readU32(raw[offNumMask+4:])
		entry.StrFlags |= strFlags

		// Value is a string up to vallen bytes
		vl := int(vallen)
		if vl > maxValueLen {
			vl = maxValueLen
		}
		entry.Value.Str = make([]byte, vl)
		copy(entry.Value.Str, raw[offValue:offValue+vl])
		entry.Value.IsString = true
	} else if typ == TypeGUID {
		// GUID: 16-byte value stored as raw bytes in Value.Str
		entry.Value.Str = make([]byte, 16)
		copy(entry.Value.Str, raw[offValue:offValue+16])
		entry.Value.IsString = true
	} else if typ == TypeName || typ == TypeUse {
		// Name/Use: value is a string
		vl := int(vallen)
		if vl > maxValueLen {
			vl = maxValueLen
		}
		if vl > 0 {
			entry.Value.Str = make([]byte, vl)
			copy(entry.Value.Str, raw[offValue:offValue+vl])
		} else {
			// Read null-terminated string from value field
			entry.Value.Str = []byte(readCString(raw[offValue : offValue+maxValueLen]))
		}
		entry.Value.IsString = true
	} else {
		// Numeric types
		entry.NumMask = readU64(raw[offNumMask:])
		entry.HasMask = entry.NumMask != 0

		// Read numeric value based on type size
		entry.Value.Numeric = readNumericValue(raw[offValue:], typ, readU16, readU32, readU64)

		// For float/double types, also store float value
		switch typ {
		case TypeFloat, TypeBEFloat, TypeLEFloat:
			entry.Value.Float = float64(math.Float32frombits(uint32(entry.Value.Numeric)))
		case TypeDouble, TypeBEDouble, TypeLEDouble:
			entry.Value.Float = math.Float64frombits(entry.Value.Numeric)
		}
	}

	// Read string fields
	entry.Desc = readCString(raw[offDesc : offDesc+descLen])
	entry.MimeType = readCString(raw[offMimeType : offMimeType+mimeTypeLen])
	entry.Apple = readCString(raw[offApple : offApple+appleLen])

	// ext field size depends on entry size
	extEnd := hdr.entrySize
	if offExt < extEnd {
		entry.Ext = readCString(raw[offExt:extEnd])
	}

	return entry
}

// readNumericValue reads a numeric value from the value union based on type.
func readNumericValue(val []byte, typ FileType,
	readU16 func([]byte) uint16,
	readU32 func([]byte) uint32,
	readU64 func([]byte) uint64) uint64 {

	if len(val) < 8 {
		return 0
	}

	switch typ {
	case TypeByte:
		return uint64(val[0])
	case TypeShort, TypeBEShort, TypeLEShort,
		TypeLEMSDOSDate, TypeLEMSDOSTime, TypeBEMSDOSDate, TypeBEMSDOSTime:
		return uint64(readU16(val))
	case TypeLong, TypeBELong, TypeLELong, TypeMELong,
		TypeDate, TypeBEDate, TypeLEDate, TypeMEDate,
		TypeLDate, TypeBELDate, TypeLELDate, TypeMELDate,
		TypeFloat, TypeBEFloat, TypeLEFloat,
		TypeBEID3, TypeLEID3:
		return uint64(readU32(val))
	case TypeQuad, TypeBEQuad, TypeLEQuad,
		TypeDouble, TypeBEDouble, TypeLEDouble,
		TypeQDate, TypeBEQDate, TypeLEQDate,
		TypeQLDate, TypeBEQLDate, TypeLEQLDate,
		TypeQWDate, TypeBEQWDate, TypeLEQWDate,
		TypeOffset:
		return readU64(val)
	default:
		return uint64(readU32(val))
	}
}

// mapMgcFlag converts .mgc flag byte to gofile Flag uint16.
func mapMgcFlag(f byte) uint16 {
	var flag uint16
	if f&0x01 != 0 {
		flag |= FlagIndir
	}
	if f&0x02 != 0 {
		flag |= FlagOffAdd
	}
	if f&0x04 != 0 {
		flag |= FlagNegative
	}
	if f&0x10 != 0 {
		flag |= FlagNoSpace
	}
	return flag
}

// mapMaskOp converts .mgc mask_op byte to gofile MaskOp character.
func mapMaskOp(op byte) byte {
	switch op {
	case 0:
		return 0
	case 1:
		return '&'
	case 2:
		return '^'
	case 3:
		return '|'
	case 4:
		return '+'
	case 5:
		return '-'
	case 6:
		return '*'
	case 7:
		return '/'
	case 8:
		return '%'
	default:
		return 0
	}
}

// mapFactorOp converts .mgc factor_op byte to strength modifier character.
func mapFactorOp(op byte) byte {
	switch op {
	case 1:
		return '+'
	case 2:
		return '-'
	case 3:
		return '*'
	case 4:
		return '/'
	default:
		return 0
	}
}

// readCString reads a null-terminated string from a byte slice.
func readCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// NewFromMgcFile creates a FileIdentifier from a compiled .mgc file.
func NewFromMgcFile(path string, opts Options) (*FileIdentifier, error) {
	set, err := ParseMgcFile(path)
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{
		set:     set,
		matcher: NewMatcher(set),
		options: opts,
	}, nil
}
