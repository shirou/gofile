package magic

import (
	"fmt"
	"io"
)

const (
	// FILE_BADSIZE represents an invalid size, equivalent to C's ~0ul
	FILE_BADSIZE = ^uint(0)
)

// FileShowStr prints a string containing C character escapes.
// This is a port of file_showstr from apprentice.c.
//
// Parameters:
//   - w: the writer to output to (equivalent to C's FILE *fp)
//   - s: the string to print
//   - length: the length of the string, or FILE_BADSIZE to print until null terminator
func FileShowStr(w io.Writer, s string, length uint) {
	var bytesToProcess []byte
	
	if length == FILE_BADSIZE {
		// Process entire string
		bytesToProcess = []byte(s)
	} else {
		// Process up to length bytes
		strLen := uint(len(s))
		if strLen < length {
			bytesToProcess = []byte(s)
		} else {
			bytesToProcess = []byte(s[:length])
		}
	}
	
	for _, c := range bytesToProcess {
		// Check if character is printable ASCII (040-0176 octal = 32-126 decimal)
		if c >= 32 && c <= 126 {
			fmt.Fprintf(w, "%c", c)
		} else {
			// Non-printable character, escape it
			fmt.Fprint(w, "\\")
			switch c {
			case '\a': // Bell
				fmt.Fprint(w, "a")
			case '\b': // Backspace
				fmt.Fprint(w, "b")
			case '\f': // Form feed
				fmt.Fprint(w, "f")
			case '\n': // Newline
				fmt.Fprint(w, "n")
			case '\r': // Carriage return
				fmt.Fprint(w, "r")
			case '\t': // Tab
				fmt.Fprint(w, "t")
			case '\v': // Vertical tab
				fmt.Fprint(w, "v")
			default:
				// Print as octal (3 digits, & 0377 = & 0xFF to ensure byte range)
				fmt.Fprintf(w, "%.3o", c&0377)
			}
		}
	}
}

// FileShowStrToString is a convenience function that returns the escaped string
// instead of writing to an io.Writer.
func FileShowStrToString(s string, length uint) string {
	buf := &stringBuilder{}
	FileShowStr(buf, s, length)
	return buf.String()
}

// Simple string builder that implements io.Writer
type stringBuilder struct {
	data []byte
}

func (sb *stringBuilder) Write(p []byte) (n int, err error) {
	sb.data = append(sb.data, p...)
	return len(p), nil
}

func (sb *stringBuilder) String() string {
	return string(sb.data)
}