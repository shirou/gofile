package magic

import (
	"bytes"
	"testing"
)

func TestFileShowStr(t *testing.T) {
	tests := map[string]struct {
		input    string
		length   uint
		expected string
	}{
		"printable ASCII": {
			input:    "Hello World",
			length:   FILE_BADSIZE,
			expected: "Hello World",
		},
		"with newline": {
			input:    "Hello\nWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\nWorld",
		},
		"with tab": {
			input:    "Hello\tWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\tWorld",
		},
		"with carriage return": {
			input:    "Hello\rWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\rWorld",
		},
		"with backspace": {
			input:    "Hello\bWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\bWorld",
		},
		"with form feed": {
			input:    "Hello\fWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\fWorld",
		},
		"with vertical tab": {
			input:    "Hello\vWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\vWorld",
		},
		"with bell": {
			input:    "Hello\aWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\aWorld",
		},
		"with null byte": {
			input:    "Hello\x00World",
			length:   FILE_BADSIZE,
			expected: "Hello\\000World",
		},
		"with non-printable": {
			input:    "Hello\x01World",
			length:   FILE_BADSIZE,
			expected: "Hello\\001World",
		},
		"with high byte": {
			input:    "Hello\xffWorld",
			length:   FILE_BADSIZE,
			expected: "Hello\\377World",
		},
		"limited length": {
			input:    "Hello World",
			length:   5,
			expected: "Hello",
		},
		"limited length with escape": {
			input:    "Hi\nThere",
			length:   4,
			expected: "Hi\\nT",
		},
		"empty string": {
			input:    "",
			length:   FILE_BADSIZE,
			expected: "",
		},
		"all special chars": {
			input:    "\a\b\f\n\r\t\v",
			length:   FILE_BADSIZE,
			expected: "\\a\\b\\f\\n\\r\\t\\v",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			FileShowStr(&buf, tt.input, tt.length)
			got := buf.String()
			if got != tt.expected {
				t.Errorf("FileShowStr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileShowStrToString(t *testing.T) {
	tests := map[string]struct {
		input    string
		length   uint
		expected string
	}{
		"simple string": {
			input:    "Test\nString",
			length:   FILE_BADSIZE,
			expected: "Test\\nString",
		},
		"with length limit": {
			input:    "LongString",
			length:   4,
			expected: "Long",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := FileShowStrToString(tt.input, tt.length)
			if got != tt.expected {
				t.Errorf("FileShowStrToString() = %q, want %q", got, tt.expected)
			}
		})
	}
}