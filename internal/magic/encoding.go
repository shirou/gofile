package magic

import (
	"unicode/utf8"
)

// detectEncoding determines the text encoding of a buffer.
// Returns a description like "ASCII text" or "" if not text.
func detectEncoding(buf []byte) string {
	if len(buf) == 0 {
		return "empty"
	}

	// Check for UTF-8 BOM
	hasBOM := false
	data := buf
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		hasBOM = true
		data = data[3:]
	}

	// Check for UTF-16/UTF-32 BOM
	if len(buf) >= 4 {
		if buf[0] == 0xFF && buf[1] == 0xFE && buf[2] == 0x00 && buf[3] == 0x00 {
			return "Unicode text, UTF-32, little-endian"
		}
		if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0xFE && buf[3] == 0xFF {
			return "Unicode text, UTF-32, big-endian"
		}
	}
	if len(buf) >= 2 {
		if buf[0] == 0xFF && buf[1] == 0xFE {
			return "Unicode text, UTF-16, little-endian text"
		}
		if buf[0] == 0xFE && buf[1] == 0xFF {
			return "Unicode text, UTF-16, big-endian text"
		}
	}

	// Classify content
	hasHighBit := false
	hasNull := false
	controlChars := 0
	lineEndings := detectLineEndings(data)

	for _, b := range data {
		if b == 0 {
			hasNull = true
			break
		}
		if b > 127 {
			hasHighBit = true
		}
		if b < 32 && b != '\t' && b != '\n' && b != '\r' && b != '\f' && b != 0x1b {
			controlChars++
		}
	}

	if hasNull {
		return "data" // binary
	}

	// Too many control chars = binary
	if controlChars > len(data)/10 && controlChars > 2 {
		return "data"
	}

	if !hasHighBit {
		desc := "ASCII text"
		if hasBOM {
			desc = "Unicode text, UTF-8 (with BOM)"
		}
		return desc + lineEndings
	}

	// Check if valid UTF-8
	if utf8.Valid(data) {
		desc := "Unicode text, UTF-8 text"
		if hasBOM {
			desc = "Unicode text, UTF-8 (with BOM) text"
		}
		return desc + lineEndings
	}

	return "ISO-8859 text" + lineEndings
}

// isBinaryData returns true if the buffer appears to contain binary data.
func isBinaryData(buf []byte) bool {
	enc := detectEncoding(buf)
	return enc == "data" || enc == ""
}

func detectLineEndings(data []byte) string {
	hasCR := false
	hasLF := false
	hasCRLF := false
	hasLongLines := false
	lineLen := 0

	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				hasCRLF = true
				i++ // skip the LF
			} else {
				hasCR = true
			}
			lineLen = 0
		case '\n':
			hasLF = true
			lineLen = 0
		default:
			lineLen++
			if lineLen > 300 {
				hasLongLines = true
			}
		}
	}

	// Check if file ends without newline
	if len(data) > 0 && data[len(data)-1] != '\n' && data[len(data)-1] != '\r' {
		if !hasLF && !hasCR && !hasCRLF {
			return ", with no line terminators"
		}
	}

	var suffix string
	if hasCRLF {
		suffix = ", with CRLF line terminators"
	} else if hasCR {
		suffix = ", with CR line terminators"
	}
	if hasLongLines {
		suffix += ", with very long lines"
	}
	return suffix
}
