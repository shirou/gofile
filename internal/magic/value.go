package magic

import (
	"encoding/binary"
	"fmt"
)

// extractValue reads a value from buf at the given offset using the entry's type.
func extractValue(buf []byte, offset int, entry *MagicEntry) (Value, error) {
	if offset < 0 || offset >= len(buf) {
		return Value{}, fmt.Errorf("offset %d out of bounds (len=%d)", offset, len(buf))
	}

	switch entry.Type {
	case TypeByte:
		return Value{Numeric: uint64(buf[offset])}, nil

	case TypeBEShort:
		if offset+2 > len(buf) {
			return Value{}, fmt.Errorf("need 2 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: uint64(binary.BigEndian.Uint16(buf[offset:]))}, nil

	case TypeLEShort, TypeShort:
		if offset+2 > len(buf) {
			return Value{}, fmt.Errorf("need 2 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: uint64(binary.LittleEndian.Uint16(buf[offset:]))}, nil

	case TypeBELong:
		if offset+4 > len(buf) {
			return Value{}, fmt.Errorf("need 4 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: uint64(binary.BigEndian.Uint32(buf[offset:]))}, nil

	case TypeLELong, TypeLong:
		if offset+4 > len(buf) {
			return Value{}, fmt.Errorf("need 4 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: uint64(binary.LittleEndian.Uint32(buf[offset:]))}, nil

	case TypeBEQuad:
		if offset+8 > len(buf) {
			return Value{}, fmt.Errorf("need 8 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: binary.BigEndian.Uint64(buf[offset:])}, nil

	case TypeLEQuad, TypeQuad:
		if offset+8 > len(buf) {
			return Value{}, fmt.Errorf("need 8 bytes at offset %d, have %d", offset, len(buf))
		}
		return Value{Numeric: binary.LittleEndian.Uint64(buf[offset:])}, nil

	case TypeString:
		return extractString(buf, offset, entry)

	case TypePString:
		return extractPString(buf, offset, entry)

	case TypeLEString16:
		return extractString16(buf, offset, entry, true)

	case TypeBEString16:
		return extractString16(buf, offset, entry, false)

	case TypeSearch:
		// Search for the pattern within StrRange bytes from offset.
		// StrRange limits how far from offset the match can START, not end.
		searchRange := int(entry.StrRange)
		if searchRange == 0 {
			searchRange = len(buf) - offset
		}
		// The match can start at any position from offset to offset+searchRange,
		// but the pattern can extend beyond the search range.
		endSearch := offset + searchRange + len(entry.Value.Str)*4
		if endSearch > len(buf) {
			endSearch = len(buf)
		}
		pattern := entry.Value.Str
		region := buf[offset:endSearch]
		wsFlags := entry.StrFlags & (StrFlagOptionalWS | StrFlagCompactWS)
		if wsFlags != 0 {
			idx, consumed := searchStringWS(region, pattern, searchRange, entry.StrFlags)
			if idx < 0 {
				return Value{}, fmt.Errorf("search pattern not found")
			}
			return Value{Str: pattern, IsString: true, Numeric: uint64(offset + idx + consumed)}, nil
		}
		caseInsensitive := entry.StrFlags&(StrFlagIgnoreLower|StrFlagIgnoreUpper) != 0
		var idx int
		if caseInsensitive {
			idx = bytesIndexCI(region, pattern)
		} else {
			idx = bytesIndex(region, pattern)
		}
		if idx < 0 || idx > searchRange {
			return Value{}, fmt.Errorf("search pattern not found")
		}
		return Value{Str: pattern, IsString: true, Numeric: uint64(offset + idx + len(pattern))}, nil

	case TypeRegex:
		return Value{}, fmt.Errorf("regex type not yet implemented")

	case TypeBEDate, TypeLEDate, TypeDate,
		TypeBELDate, TypeLELDate, TypeLDate,
		TypeMEDate, TypeMELDate:
		if offset+4 > len(buf) {
			return Value{}, fmt.Errorf("need 4 bytes at offset %d, have %d", offset, len(buf))
		}
		var v uint32
		switch entry.Type {
		case TypeBEDate, TypeBELDate:
			v = binary.BigEndian.Uint32(buf[offset:])
		case TypeMEDate, TypeMELDate:
			v = melong(buf[offset:])
		default:
			v = binary.LittleEndian.Uint32(buf[offset:])
		}
		return Value{Numeric: uint64(v)}, nil

	case TypeBEQDate, TypeLEQDate, TypeQDate,
		TypeBEQLDate, TypeLEQLDate, TypeQLDate,
		TypeBEQWDate, TypeLEQWDate, TypeQWDate:
		if offset+8 > len(buf) {
			return Value{}, fmt.Errorf("need 8 bytes at offset %d, have %d", offset, len(buf))
		}
		var v uint64
		switch entry.Type {
		case TypeBEQDate, TypeBEQLDate, TypeBEQWDate:
			v = binary.BigEndian.Uint64(buf[offset:])
		default:
			v = binary.LittleEndian.Uint64(buf[offset:])
		}
		return Value{Numeric: v}, nil

	case TypeOffset:
		return Value{Numeric: uint64(offset)}, nil

	case TypeGUID:
		if offset+16 > len(buf) {
			return Value{}, fmt.Errorf("need 16 bytes at offset %d for GUID, have %d", offset, len(buf))
		}
		data := make([]byte, 16)
		copy(data, buf[offset:offset+16])
		return Value{Str: data, IsString: true}, nil

	case TypeLEMSDOSDate, TypeLEMSDOSTime, TypeBEMSDOSDate, TypeBEMSDOSTime:
		if offset+2 > len(buf) {
			return Value{}, fmt.Errorf("need 2 bytes at offset %d", offset)
		}
		var v uint16
		switch entry.Type {
		case TypeBEMSDOSDate, TypeBEMSDOSTime:
			v = binary.BigEndian.Uint16(buf[offset:])
		default:
			v = binary.LittleEndian.Uint16(buf[offset:])
		}
		return Value{Numeric: uint64(v)}, nil

	default:
		return Value{}, fmt.Errorf("unsupported type %d", entry.Type)
	}
}

// melong reads a 4-byte middle-endian (PDP-11) value.
func melong(b []byte) uint32 {
	return uint32(b[1])<<24 | uint32(b[0])<<16 | uint32(b[3])<<8 | uint32(b[2])
}

// compare checks the extracted value against the entry's test value using the relation.
func compare(extracted Value, entry *MagicEntry) bool {
	if entry.Relation == 'x' {
		return true
	}

	if extracted.IsString || entry.Value.IsString {
		return compareString(extracted.Str, entry.Value.Str, entry.Relation)
	}

	return compareNumeric(extracted.Numeric, entry.Value.Numeric, entry.Relation)
}

func compareNumeric(v, test uint64, rel byte) bool {
	switch rel {
	case '=':
		return v == test
	case '!':
		return v != test
	case '<':
		return v < test
	case '>':
		return v > test
	case '&':
		return v&test == test
	case '^':
		return v&test != test
	default:
		return false
	}
}

// bytesIndex finds the first occurrence of pattern in data.
func bytesIndex(data, pattern []byte) int {
	if len(pattern) == 0 {
		return 0
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// extractString extracts a string value from the buffer.
// When relation is 'x' or comparison-based ('>', '<', '!'), reads until null byte
// to provide full string for display. Otherwise reads len(test) bytes for exact match.
func extractString(buf []byte, offset int, entry *MagicEntry) (Value, error) {
	if entry.Relation == 'x' || entry.Relation == '>' || entry.Relation == '<' || entry.Relation == '!' {
		// Read until null byte, newline, or end of buffer, max 8192 bytes
		maxLen := 8192
		end := offset + maxLen
		if end > len(buf) {
			end = len(buf)
		}
		data := buf[offset:end]
		// Find null terminator or newline
		for i, b := range data {
			if b == 0 || b == '\n' || b == '\r' {
				data = data[:i]
				break
			}
		}
		// Trim leading and trailing whitespace if T flag is set
		if entry.StrFlags&StrFlagTrim != 0 {
			// Trim leading whitespace
			start := 0
			for start < len(data) && (data[start] == ' ' || data[start] == '\t' ||
				data[start] == '\n' || data[start] == '\r') {
				start++
			}
			if start > 0 {
				data = data[start:]
			}
			// Trim trailing whitespace
			for len(data) > 0 && (data[len(data)-1] == ' ' || data[len(data)-1] == '\t' ||
				data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
				data = data[:len(data)-1]
			}
		}
		result := make([]byte, len(data))
		copy(result, data)
		return Value{Str: result, IsString: true}, nil
	}
	// Check for whitespace flags
	wsFlags := entry.StrFlags & (StrFlagOptionalWS | StrFlagCompactWS)
	if wsFlags != 0 {
		// Whitespace-aware matching: need to read more data than pattern length
		// since whitespace in data may differ from pattern
		maxRead := len(entry.Value.Str) * 4
		if maxRead < 256 {
			maxRead = 256
		}
		end := offset + maxRead
		if end > len(buf) {
			end = len(buf)
		}
		_, ok := matchStringWS(buf[offset:end], entry.Value.Str, entry.StrFlags)
		if !ok {
			return Value{}, fmt.Errorf("whitespace-aware string match failed")
		}
		// Use pattern length for matchEnd (continuation offsets are relative to pattern)
		return Value{Str: entry.Value.Str, IsString: true}, nil
	}

	// Exact match: read len(test) bytes
	vlen := len(entry.Value.Str)
	if vlen == 0 {
		vlen = 1
	}
	end := offset + vlen
	if end > len(buf) {
		end = len(buf)
	}
	data := make([]byte, end-offset)
	copy(data, buf[offset:end])
	return Value{Str: data, IsString: true}, nil
}

// extractPString extracts a pascal-style string (length-prefixed).
// Supports /H (2-byte BE length), /h (2-byte LE length),
// /L (4-byte BE length), /l (4-byte LE length). Default: 1-byte length.
func extractPString(buf []byte, offset int, entry *MagicEntry) (Value, error) {
	prefixSize := 1
	var strLen int

	// Determine prefix size from string flags
	// We use StrFlags bits to encode pstring variant
	switch {
	case entry.StrFlags&StrFlagPStringH != 0:
		prefixSize = 2
	case entry.StrFlags&StrFlagPStringh != 0:
		prefixSize = 2
	case entry.StrFlags&StrFlagPStringL != 0:
		prefixSize = 4
	case entry.StrFlags&StrFlagPStringl != 0:
		prefixSize = 4
	}

	if offset+prefixSize > len(buf) {
		return Value{}, fmt.Errorf("pstring: need %d bytes for length prefix at offset %d", prefixSize, offset)
	}

	switch prefixSize {
	case 1:
		strLen = int(buf[offset])
	case 2:
		if entry.StrFlags&StrFlagPStringH != 0 {
			strLen = int(binary.BigEndian.Uint16(buf[offset:]))
		} else {
			strLen = int(binary.LittleEndian.Uint16(buf[offset:]))
		}
	case 4:
		if entry.StrFlags&StrFlagPStringL != 0 {
			strLen = int(binary.BigEndian.Uint32(buf[offset:]))
		} else {
			strLen = int(binary.LittleEndian.Uint32(buf[offset:]))
		}
	}

	dataStart := offset + prefixSize
	dataEnd := dataStart + strLen
	if dataEnd > len(buf) {
		dataEnd = len(buf)
	}
	if dataStart > len(buf) {
		return Value{}, fmt.Errorf("pstring: offset out of bounds")
	}

	data := make([]byte, dataEnd-dataStart)
	copy(data, buf[dataStart:dataEnd])
	// Trim trailing null bytes (common in pstring formats)
	trimmed := 0
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
		trimmed++
	}
	// matchEnd accounts for prefix + string content (without trailing nulls)
	matchEnd := dataEnd - trimmed
	return Value{Str: data, IsString: true, Numeric: uint64(matchEnd)}, nil
}

// bytesIndexCI finds the first case-insensitive occurrence of pattern in data.
func bytesIndexCI(data, pattern []byte) int {
	if len(pattern) == 0 {
		return 0
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			a, b := data[i+j], pattern[j]
			if a != b {
				// Case insensitive compare
				if a >= 'A' && a <= 'Z' {
					a += 'a' - 'A'
				}
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				if a != b {
					match = false
					break
				}
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func compareString(v, test []byte, rel byte) bool {
	n := len(test)
	if n > len(v) {
		n = len(v)
	}
	cmp := 0
	for i := 0; i < n; i++ {
		if v[i] != test[i] {
			if v[i] < test[i] {
				cmp = -1
			} else {
				cmp = 1
			}
			break
		}
	}
	if cmp == 0 && len(v) < len(test) {
		cmp = -1
	}

	switch rel {
	case '=':
		return cmp == 0
	case '!':
		return cmp != 0
	case '<':
		return cmp < 0
	case '>':
		return cmp > 0
	default:
		return false
	}
}

// isSpace returns true if b is a whitespace character (space or tab).
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

// matchStringWS performs whitespace-aware string matching following the C file(1) semantics.
// For OptionalWS (/w): each whitespace in pattern matches zero or more whitespace chars in data.
// For CompactWS (/W): each whitespace in pattern must match at least one whitespace in data,
// and when the next pattern char is non-space, all remaining whitespace in data is consumed.
// Returns the number of bytes consumed from data and whether the match succeeded.
func matchStringWS(data, pattern []byte, flags uint32) (consumed int, matched bool) {
	caseInsensitive := flags&(StrFlagIgnoreLower|StrFlagIgnoreUpper) != 0
	di := 0 // data index
	pi := 0 // pattern index

	for pi < len(pattern) {
		if isSpace(pattern[pi]) {
			if flags&StrFlagOptionalWS != 0 {
				// /w: skip this space in pattern, consume zero or more whitespace in data
				pi++
				for di < len(data) && isSpace(data[di]) {
					di++
				}
			} else if flags&StrFlagCompactWS != 0 {
				// /W: pattern space must match at least one whitespace in data
				pi++
				if di >= len(data) || !isSpace(data[di]) {
					return 0, false
				}
				di++
				// If next pattern char is not space, consume remaining whitespace
				if pi >= len(pattern) || !isSpace(pattern[pi]) {
					for di < len(data) && isSpace(data[di]) {
						di++
					}
				}
			}
		} else {
			if di >= len(data) {
				return 0, false
			}
			a, b := data[di], pattern[pi]
			if caseInsensitive {
				if a >= 'A' && a <= 'Z' {
					a += 'a' - 'A'
				}
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
			}
			if a != b {
				return 0, false
			}
			di++
			pi++
		}
	}

	// Full word check: next char in data must be space or end
	if flags&StrFlagFullWord != 0 {
		if di < len(data) && !isSpace(data[di]) {
			return 0, false
		}
	}

	return di, true
}

// extractString16 extracts a UTF-16 LE or BE string and converts it to single-byte
// for comparison with the ASCII test pattern.
func extractString16(buf []byte, offset int, entry *MagicEntry, littleEndian bool) (Value, error) {
	testLen := len(entry.Value.Str)
	if entry.Relation == 'x' || entry.Relation == '>' || entry.Relation == '<' || entry.Relation == '!' {
		// Read until null UTF-16 char, max 512 chars
		maxChars := 512
		end := offset + maxChars*2
		if end > len(buf) {
			end = len(buf)
		}
		var result []byte
		for p := offset; p+1 < end; p += 2 {
			var ch uint16
			if littleEndian {
				ch = uint16(buf[p]) | uint16(buf[p+1])<<8
			} else {
				ch = uint16(buf[p])<<8 | uint16(buf[p+1])
			}
			if ch == 0 {
				break
			}
			if ch < 256 {
				result = append(result, byte(ch))
			} else {
				result = append(result, '?')
			}
		}
		return Value{Str: result, IsString: true}, nil
	}

	// Exact match: read testLen*2 bytes, convert to single-byte
	need := testLen * 2
	if offset+need > len(buf) {
		return Value{}, fmt.Errorf("need %d bytes at offset %d for string16", need, offset)
	}
	result := make([]byte, testLen)
	for i := 0; i < testLen; i++ {
		p := offset + i*2
		if littleEndian {
			result[i] = buf[p] // low byte
		} else {
			result[i] = buf[p+1] // low byte for BE
		}
	}
	return Value{Str: result, IsString: true}, nil
}

// searchStringWS searches for a whitespace-aware pattern match within a range.
// Returns the index where the match starts and the number of bytes consumed, or -1 if not found.
func searchStringWS(data, pattern []byte, maxStart int, flags uint32) (idx int, consumed int) {
	for i := 0; i <= maxStart && i < len(data); i++ {
		c, ok := matchStringWS(data[i:], pattern, flags)
		if ok {
			return i, c
		}
	}
	return -1, 0
}
