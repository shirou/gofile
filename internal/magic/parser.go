package magic

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Parser handles parsing of magic.mgc files
type Parser struct {
	byteOrder binary.ByteOrder
}

// NewParser creates a new magic file parser
func NewParser() *Parser {
	return &Parser{
		byteOrder: binary.LittleEndian, // Default to little endian
	}
}

// ParseFile parses a magic.mgc file and returns a MagicDatabase
func (p *Parser) ParseFile(filename string) (*MagicDatabase, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open magic file %s: %w", filename, err)
	}
	defer file.Close()

	return p.Parse(file)
}

// Parse parses magic data from a reader
func (p *Parser) Parse(r io.Reader) (*MagicDatabase, error) {
	// Read the entire file into memory for easier parsing
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read magic data: %w", err)
	}

	const headerSize = 16 // Magic (4) + Version (4) + NMagic[2] (8)
	if len(data) < headerSize {
		return nil, fmt.Errorf("magic file too small: %d bytes", len(data))
	}

	// Parse header
	header, err := p.parseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Calculate expected size
	totalEntries := uint32(1) // Header entry
	for i := 0; i < MAGIC_SETS; i++ {
		totalEntries += header.NMagic[i]
	}

	// Calculate minimum expected size based on data in file
	// Version 18 uses 376 bytes, version 20+ uses 432 bytes
	var entrySize uint32
	if header.Version >= 20 {
		entrySize = 432
	} else {
		entrySize = 376
	}
	minExpectedSize := totalEntries * entrySize

	if uint32(len(data)) < minExpectedSize {
		return nil, fmt.Errorf("file too small: expected at least %d, got %d", minExpectedSize, len(data))
	}

	// Parse magic entries
	db := &MagicDatabase{
		Version: header.Version,
		NMagic:  header.NMagic,
	}

	// Magic entry size depends on version: 376 for v18, 432 for v20
	var actualEntrySize uint32
	if header.Version >= 20 {
		actualEntrySize = 432 // Version 20+
	} else {
		actualEntrySize = 376 // Version 18-19 (still uses smaller struct)
	}

	// Data starts at offset 376 based on analysis
	actualDataStart := uint32(376) // Correct offset found through analysis

	offset := actualDataStart
	for set := 0; set < MAGIC_SETS; set++ {
		db.Magic[set] = make([]*MagicEntry, header.NMagic[set])

		for i := uint32(0); i < header.NMagic[set]; i++ {
			if offset+actualEntrySize > uint32(len(data)) {
				return nil, fmt.Errorf("unexpected end of file while parsing entries")
			}

			entry, err := p.parseEntry(data[offset:], header.Version)
			if err != nil {
				return nil, fmt.Errorf("failed to parse entry %d in set %d: %w", i, set, err)
			}

			// Calculate strength for this entry (after parsing is complete)
			entry.Strength = p.calculateStrength(entry)

			db.Magic[set][i] = entry
			offset += actualEntrySize
		}
	}

	return db, nil
}

// parseHeader parses the magic file header
func (p *Parser) parseHeader(data []byte) (*MagicHeader, error) {
	const headerSize = 16 // Magic (4) + Version (4) + NMagic[2] (8)
	if len(data) < headerSize {
		return nil, fmt.Errorf("insufficient data for header")
	}

	// Read magic number to determine byte order
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic == MAGICNO {
		p.byteOrder = binary.LittleEndian
	} else if magic == swapUint32(MAGICNO) {
		p.byteOrder = binary.BigEndian
		magic = MAGICNO
	} else {
		return nil, fmt.Errorf("invalid magic number: 0x%08x", magic)
	}

	header := &MagicHeader{
		Magic:   magic,
		Version: p.byteOrder.Uint32(data[4:8]),
	}

	// Check version
	if header.Version < MIN_VERSION || header.Version > VERSIONNO {
		return nil, fmt.Errorf("unsupported version: %d (supported range: %d-%d)",
			header.Version, MIN_VERSION, VERSIONNO)
	}

	// Read number of entries per set
	for i := 0; i < MAGIC_SETS; i++ {
		offset := 8 + i*4
		header.NMagic[i] = p.byteOrder.Uint32(data[offset : offset+4])
	}

	return header, nil
}

// parseEntry parses a single magic entry according to the official C struct layout
func (p *Parser) parseEntry(data []byte, version uint32) (*MagicEntry, error) {
	// The binary size varies by version: 376 for v18, 432 for v20
	// We need at least 376 bytes to parse any entry
	const minBinarySize = 376
	if len(data) < minBinarySize {
		return nil, fmt.Errorf("insufficient data for magic entry")
	}

	entry := &MagicEntry{}

	// Parse fields according to official struct magic layout from file.h
	offset := 0

	// Word 1 (4 bytes): flag, cont_level, factor
	entry.Flag = p.byteOrder.Uint16(data[offset : offset+2])
	entry.ContLevel = data[offset+2]
	entry.Factor = data[offset+3]
	offset += 4

	// Word 2 (4 bytes): reln, vallen, type, in_type
	entry.Reln = data[offset]
	entry.Vallen = data[offset+1]
	entry.Type = data[offset+2]
	entry.InType = data[offset+3]
	offset += 4

	// Word 3 (4 bytes): in_op, mask_op, cond, factor_op
	entry.InOp = data[offset]
	entry.MaskOp = data[offset+1]
	entry.Cond = data[offset+2]
	entry.FactorOp = data[offset+3]
	offset += 4

	// Word 4 (4 bytes): offset
	entry.Offset = int32(p.byteOrder.Uint32(data[offset : offset+4]))
	offset += 4

	// Word 5 (4 bytes): in_offset
	entry.InOffset = int32(p.byteOrder.Uint32(data[offset : offset+4]))
	offset += 4

	// Word 6 (4 bytes): lineno
	entry.Lineno = p.byteOrder.Uint32(data[offset : offset+4])
	offset += 4

	// Word 7-8 (8 bytes): union _u (num_mask or str_range/str_flags)
	entry.NumMask = p.byteOrder.Uint64(data[offset : offset+8])
	offset += 8

	// Words 9-24 (128 bytes): union VALUETYPE value
	copy(entry.Value[:], data[offset:offset+128])
	// Convert multi-byte values according to byte order if needed
	if !entry.IsString() {
		p.convertValueByteOrder(entry)
	}
	offset += 128

	// Words 25-40 (64 bytes): char desc[MAXDESC]
	copy(entry.Desc[:], data[offset:offset+MAXDESC])
	offset += MAXDESC

	// Words 41-60 (80 bytes): char mimetype[MAXMIME]
	copy(entry.MimeType[:], data[offset:offset+MAXMIME])
	offset += MAXMIME

	// Words 61-62 (8 bytes): char apple[8]
	copy(entry.Apple[:], data[offset:offset+8])
	offset += 8

	// Words 63-78: char ext[] - size depends on version
	// Version 18: 64 bytes, Version 20+: 120 bytes 
	var extSize int
	if version >= 20 {
		extSize = 120 // MAXEXT for v20+
	} else {
		extSize = 64  // MAXEXT for v18
	}
	
	// Clear the entire Ext field first, then copy available data
	for i := range entry.Ext {
		entry.Ext[i] = 0
	}
	copy(entry.Ext[:extSize], data[offset:offset+extSize])

	return entry, nil
}

// convertValueByteOrder converts multi-byte values in the Value field according to byte order
func (p *Parser) convertValueByteOrder(entry *MagicEntry) {
	if p.byteOrder == binary.LittleEndian {
		return // Already in correct order
	}

	// Convert based on type
	switch entry.Type {
	case FILE_SHORT, FILE_BESHORT, FILE_LESHORT:
		// 16-bit values
		for i := 0; i < len(entry.Value); i += 2 {
			if i+1 < len(entry.Value) {
				val := binary.BigEndian.Uint16(entry.Value[i : i+2])
				binary.LittleEndian.PutUint16(entry.Value[i:i+2], val)
			}
		}
	case FILE_LONG, FILE_BELONG, FILE_LELONG, FILE_DATE, FILE_BEDATE, FILE_LEDATE,
		FILE_LDATE, FILE_BELDATE, FILE_LELDATE, FILE_MEDATE, FILE_MELDATE, FILE_MELONG:
		// 32-bit values
		for i := 0; i < len(entry.Value); i += 4 {
			if i+3 < len(entry.Value) {
				val := binary.BigEndian.Uint32(entry.Value[i : i+4])
				binary.LittleEndian.PutUint32(entry.Value[i:i+4], val)
			}
		}
	case FILE_QUAD, FILE_LEQUAD, FILE_BEQUAD, FILE_QDATE, FILE_LEQDATE, FILE_BEQDATE,
		FILE_QLDATE, FILE_LEQLDATE, FILE_BEQLDATE, FILE_QWDATE, FILE_LEQWDATE, FILE_BEQWDATE:
		// 64-bit values
		for i := 0; i < len(entry.Value); i += 8 {
			if i+7 < len(entry.Value) {
				val := binary.BigEndian.Uint64(entry.Value[i : i+8])
				binary.LittleEndian.PutUint64(entry.Value[i:i+8], val)
			}
		}
	case FILE_FLOAT, FILE_BEFLOAT, FILE_LEFLOAT:
		// 32-bit float
		for i := 0; i < len(entry.Value); i += 4 {
			if i+3 < len(entry.Value) {
				val := binary.BigEndian.Uint32(entry.Value[i : i+4])
				binary.LittleEndian.PutUint32(entry.Value[i:i+4], val)
			}
		}
	case FILE_DOUBLE, FILE_BEDOUBLE, FILE_LEDOUBLE:
		// 64-bit double
		for i := 0; i < len(entry.Value); i += 8 {
			if i+7 < len(entry.Value) {
				val := binary.BigEndian.Uint64(entry.Value[i : i+8])
				binary.LittleEndian.PutUint64(entry.Value[i:i+8], val)
			}
		}
	}
}

// swapUint32 swaps the byte order of a uint32
func swapUint32(val uint32) uint32 {
	return ((val & 0xFF) << 24) |
		((val & 0xFF00) << 8) |
		((val & 0xFF0000) >> 8) |
		((val & 0xFF000000) >> 24)
}
