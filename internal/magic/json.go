package magic

import (
	"bytes"
)

// detectJSON checks if the buffer contains JSON text data.
// Returns "JSON text data" or "" if not JSON.
func detectJSON(buf []byte) string {
	// Trim leading whitespace and BOM
	data := bytes.TrimLeft(buf, " \t\n\r")
	if len(data) > 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
		data = bytes.TrimLeft(data, " \t\n\r")
	}

	if len(data) == 0 {
		return ""
	}

	// Check for NDJSON first (multiple JSON objects per line)
	if data[0] == '{' && isNDJSON(data) {
		return "New Line Delimited JSON text data"
	}

	if (data[0] == '{' || data[0] == '[') && looksLikeJSON(data) {
		return "JSON text data"
	}

	return ""
}

// isNDJSON checks if data looks like Newline Delimited JSON.
func isNDJSON(data []byte) bool {
	lines := bytes.Split(bytes.TrimRight(data, "\n\r"), []byte("\n"))
	if len(lines) < 2 {
		return false
	}
	// Each line should be a JSON object
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' && line[0] != '[' {
			return false
		}
	}
	return true
}

// looksLikeJSON validates that the buffer looks like JSON.
func looksLikeJSON(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[0] != '{' && data[0] != '[' {
		return false
	}

	// Scan up to 4KB looking for balanced brackets
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	chunk := data[:limit]

	depth := 0
	inString := false
	escaped := false
	hasColon := false
	topClosed := false

	for i := 0; i < len(chunk); i++ {
		if escaped {
			escaped = false
			continue
		}
		if inString {
			switch chunk[i] {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch chunk[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
			if depth == 0 {
				// After closing the top-level bracket, check remaining
				rest := bytes.TrimSpace(chunk[i+1:])
				if len(rest) > 0 {
					return false
				}
				topClosed = true
			}
		case '"':
			inString = true
		case ':':
			hasColon = true
		case ' ', '\t', '\n', '\r', ',', '-', '+', '.':
			// ok
		default:
			c := chunk[i]
			if (c >= '0' && c <= '9') || c == '_' {
				// numbers ok
			} else if c >= 'a' && c <= 'z' {
				// Must be start of true/false/null — validate the keyword
				word := extractBareWord(chunk[i:])
				if word != "true" && word != "false" && word != "null" &&
					word != "e" && word != "E" { // exponent in numbers like 1e10
					return false
				}
				i += len(word) - 1
			} else if c >= 'A' && c <= 'Z' {
				word := extractBareWord(chunk[i:])
				if word != "E" {
					return false
				}
				i += len(word) - 1
			} else {
				return false
			}
		}
	}

	if topClosed {
		if data[0] == '{' {
			return hasColon || bytes.Equal(bytes.TrimSpace(chunk), []byte("{}"))
		}
		return true
	}
	// If we ran out of buffer before closing, still consider it JSON if it has structure
	return hasColon && depth > 0
}

// extractBareWord returns the contiguous sequence of letters starting at data[0].
func extractBareWord(data []byte) string {
	i := 0
	for i < len(data) && ((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i] <= 'Z')) {
		i++
	}
	return string(data[:i])
}
