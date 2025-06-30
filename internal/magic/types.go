package magic

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// Magic constants from file/file implementation
const (
	MAGICNO    = 0xF11E041C // Magic number for .mgc files
	VERSIONNO  = 20         // Expected version number
	MIN_VERSION = 18        // Minimum supported version
	MAGIC_SETS = 2          // Number of magic sets

	// Maximum sizes
	MAXDESC = 64  // Maximum description length
	MAXMIME = 80  // Maximum MIME type length  
	MAXEXT  = 96  // Maximum extension length (v18)
)

// File type constants (from file.h)
const (
	FILE_INVALID    = 0
	FILE_BYTE       = 1
	FILE_SHORT      = 2
	FILE_DEFAULT    = 3
	FILE_LONG       = 4
	FILE_STRING     = 5
	FILE_DATE       = 6
	FILE_BESHORT    = 7
	FILE_BELONG     = 8
	FILE_BEDATE     = 9
	FILE_LESHORT    = 10
	FILE_LELONG     = 11
	FILE_LEDATE     = 12
	FILE_PSTRING    = 13
	FILE_LDATE      = 14
	FILE_BELDATE    = 15
	FILE_LELDATE    = 16
	FILE_REGEX      = 17
	FILE_BESTRING16 = 18
	FILE_LESTRING16 = 19
	FILE_SEARCH     = 20
	FILE_MEDATE     = 21
	FILE_MELDATE    = 22
	FILE_MELONG     = 23
	FILE_QUAD       = 24
	FILE_LEQUAD     = 25
	FILE_BEQUAD     = 26
	FILE_QDATE      = 27
	FILE_LEQDATE    = 28
	FILE_BEQDATE    = 29
	FILE_QLDATE     = 30
	FILE_LEQLDATE   = 31
	FILE_BEQLDATE   = 32
	FILE_FLOAT      = 33
	FILE_BEFLOAT    = 34
	FILE_LEFLOAT    = 35
	FILE_DOUBLE     = 36
	FILE_BEDOUBLE   = 37
	FILE_LEDOUBLE   = 38
	FILE_BEID3      = 39
	FILE_LEID3      = 40
	FILE_INDIRECT   = 41
	FILE_QWDATE     = 42
	FILE_LEQWDATE   = 43
	FILE_BEQWDATE   = 44
	FILE_NAME       = 45
	FILE_USE        = 46
	FILE_CLEAR      = 47
	FILE_DER        = 48
	FILE_GUID       = 49
	FILE_OFFSET     = 50
	FILE_BEVARINT   = 51
	FILE_LEVARINT   = 52
	FILE_MSDOSDATE  = 53
	FILE_LEMSDOSDATE = 54
	FILE_BEMSDOSDATE = 55
	FILE_MSDOSTIME  = 56
	FILE_LEMSDOSTIME = 57
	FILE_BEMSDOSTIME = 58
	FILE_OCTAL      = 59
	FILE_NAMES_SIZE = 60
)

// Flag constants
const (
	INDIR        = 0x01  // if '(...)' appears
	OFFADD       = 0x02  // if '>&' or '>...(&' appears  
	INDIROFFADD  = 0x04  // if '>&(' appears
	UNSIGNED     = 0x08  // comparison is unsigned
	NOSPACE      = 0x10  // suppress space character before output
	BINTEST      = 0x20  // test is for a binary type
	TEXTTEST     = 0x40  // for passing to file_softmagic
	OFFNEGATIVE  = 0x80  // relative to the end of file
	OFFPOSITIVE  = 0x100 // relative to the beginning of file
	LITTLE_ENDIAN = 0x200 // little endian byte order
)

// Condition constants
const (
	COND_NONE = 0
	COND_IF   = 1
	COND_ELIF = 2
	COND_ELSE = 3
)

// MagicEntry represents a single magic entry (376 bytes in version 18, 432 in version 20)
// Layout based on official file.h struct magic definition for version 18
type MagicEntry struct {
	// Core fields (32 bytes) - CORRECT
	Flag      uint16 // Offset 0: Flags (INDIR, OFFADD, etc.)
	ContLevel uint8  // Offset 2: Continuation level
	Factor    uint8  // Offset 3: Factor
	
	Reln   uint8 // Offset 4: Relation (=, >, <, etc.)
	Vallen uint8 // Offset 5: Length of string value
	Type   uint8 // Offset 6: Comparison type (FILE_*)
	InType uint8 // Offset 7: Type of indirection
	
	InOp     uint8 // Offset 8: Operator for indirection
	MaskOp   uint8 // Offset 9: Operator for mask
	Cond     uint8 // Offset 10: Conditional type
	FactorOp uint8 // Offset 11: Factor operator
	
	Offset   int32  // Offset 12: File offset to check
	InOffset int32  // Offset 16: Indirection offset
	Lineno   uint32 // Offset 20: Line number in magic file
	
	// Union for masks/counts (8 bytes at offset 24)
	NumMask  uint64 // For numeric types (or StrRange/StrFlags for strings)
	
	// CORRECTED FIELD ORDER for version 18 (376 bytes total):
	Value    [96]byte       // Offset 32: Value field (96 bytes for v18)
	Desc     [MAXDESC]byte  // Offset 128: Description (64 bytes)
	MimeType [MAXMIME]byte  // Offset 192: MIME type (80 bytes)
	Apple    [8]byte        // Offset 272: Apple/format info (8 bytes)
	Ext      [96]byte       // Offset 280: Extensions (96 bytes for v18)
}

// MagicDatabase represents the loaded magic database
type MagicDatabase struct {
	Magic   [MAGIC_SETS][]*MagicEntry // Magic entries by set
	NMagic  [MAGIC_SETS]uint32        // Number of entries per set
	Version uint32                    // Version number
}

// MagicHeader represents the header of a .mgc file
type MagicHeader struct {
	Magic   uint32            // Magic number (MAGICNO)
	Version uint32            // Version number
	NMagic  [MAGIC_SETS]uint32 // Number of entries per set
}

// GetDescription returns the description as a string
func (m *MagicEntry) GetDescription() string {
	return cStringToString(m.Desc[:])
}

// GetMimeType returns the MIME type as a string
func (m *MagicEntry) GetMimeType() string {
	return cStringToString(m.MimeType[:])
}

// GetExtensions returns the extensions as a string
func (m *MagicEntry) GetExtensions() string {
	return cStringToString(m.Ext[:])
}

// GetApple returns the Apple type as a string
func (m *MagicEntry) GetApple() string {
	return cStringToString(m.Apple[:])
}

// IsString returns true if the type is a string type
func (m *MagicEntry) IsString() bool {
	switch m.Type {
	case FILE_STRING, FILE_PSTRING, FILE_BESTRING16, FILE_LESTRING16,
		 FILE_REGEX, FILE_SEARCH, FILE_INDIRECT, FILE_NAME, FILE_USE, FILE_OCTAL:
		return true
	default:
		return false
	}
}

// GetValueAsString returns the value as a string (for string types)
func (m *MagicEntry) GetValueAsString() string {
	if !m.IsString() {
		return ""
	}
	
	// For FILE_STRING, check if Value field has data
	valueStr := cStringToString(m.Value[:])
	if len(valueStr) > 0 {
		return valueStr
	}
	
	// If Value is empty, extract pattern from Description using Vallen
	// Many magic entries store the pattern in the first part of Description
	if m.Vallen > 0 && int(m.Vallen) <= len(m.Desc) {
		return cStringToString(m.Desc[:m.Vallen])
	}
	
	// Fallback: use entire description as pattern
	desc := m.GetDescription()
	if len(desc) > 0 {
		return desc
	}
	
	return ""
}

// GetValueAsUint64 returns the value as uint64 (for numeric types)
func (m *MagicEntry) GetValueAsUint64() uint64 {
	if m.IsString() {
		return 0
	}
	return binary.LittleEndian.Uint64(m.Value[:8])
}

// GetValueAsInt64 returns the value as int64 (for numeric types)
func (m *MagicEntry) GetValueAsInt64() int64 {
	if m.IsString() {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(m.Value[:8]))
}

// GetValueAsFloat64 returns the value as float64 (for float types)
func (m *MagicEntry) GetValueAsFloat64() float64 {
	if m.IsString() {
		return 0
	}
	bits := binary.LittleEndian.Uint64(m.Value[:8])
	return *(*float64)(unsafe.Pointer(&bits))
}

// String returns a string representation of the magic entry
func (m *MagicEntry) String() string {
	return fmt.Sprintf("MagicEntry{Type: %d, Offset: %d, Desc: %s, MIME: %s}", 
		m.Type, m.Offset, m.GetDescription(), m.GetMimeType())
}

// cStringToString converts a C-style null-terminated byte array to a Go string
func cStringToString(data []byte) string {
	// Find the null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	// If no null terminator found, return the whole array as string
	return string(data)
}
