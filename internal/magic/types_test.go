package magic

import (
	"testing"
)

// Helper function to convert MIME string to byte array
func getMimeBytes(mime string) [MAXMIME]byte {
	var result [MAXMIME]byte
	copy(result[:], []byte(mime))
	return result
}



func TestGetTestType(t *testing.T) {
	tests := []struct {
		name     string
		entry    *Entry
		expected TestType
	}{
		// Binary patterns - regular string type (matching original file command)
		{
			name: "regular string with printable text TEST",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST",
					MessageStr: "Test string",
				},
			},
			expected: BINTEST, // Regular strings are ALWAYS binary
		},
		{
			name: "regular string with printable text DATA",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "DATA",
					MessageStr: "Data string",
				},
			},
			expected: BINTEST, // Regular strings are ALWAYS binary
		},
		{
			name: "string with binary bytes PNG signature",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "\\x89PNG\\x0d\\x0a\\x1a\\x0a",
					MessageStr: "PNG image",
				},
			},
			expected: BINTEST,
		},
		{
			name: "string with null bytes",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "\\x00\\x01\\x02",
					MessageStr: "Binary data",
				},
			},
			expected: BINTEST,
		},
		{
			name: "string with DEL character",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "test\\177data",
					MessageStr: "Data with DEL",
				},
			},
			expected: BINTEST,
		},
		{
			name: "message containing binary keyword",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST",
					MessageStr: "Binary file format",
				},
			},
			expected: BINTEST,
		},

		// Text patterns - regex type
		{
			name: "regex pattern for C source",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "regex",
					TestStr:    "^#include",
					MessageStr: "C source",
				},
			},
			expected: TEXTTEST, // Regex with printable content is text
		},
		{
			name: "regex pattern with text content",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "regex",
					TestStr:    "^#!/bin/bash",
					MessageStr: "Shell script",
				},
			},
			expected: TEXTTEST,
		},

		// Text patterns - search type with UTF-8 valid content
		{
			name: "search pattern with printable text",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "search",
					TestStr:    "BEGIN",
					MessageStr: "PEM certificate",
				},
			},
			expected: TEXTTEST, // Search with printable UTF-8 is text
		},
		{
			name: "search/256 pattern with text",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "search/256",
					TestStr:    "DOCTYPE",
					MessageStr: "HTML document",
				},
			},
			expected: TEXTTEST,
		},

		// Binary patterns - search type with binary content
		{
			name: "search pattern with binary content",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "search",
					TestStr:    "\\x00\\x01\\x02",
					MessageStr: "Binary search",
				},
			},
			expected: BINTEST,
		},

		// MIME type doesn't affect classification (matching original file command)
		{
			name: "text/plain MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST",
					MessageStr: "Plain text file",
					Mimetype:   getMimeBytes("text/plain"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "text/html MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "<html>",
					MessageStr: "HTML document",
					Mimetype:   getMimeBytes("text/html"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/json MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "{",
					MessageStr: "JSON data",
					Mimetype:   getMimeBytes("application/json"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/javascript MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "function",
					MessageStr: "JavaScript code",
					Mimetype:   getMimeBytes("application/javascript"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/xml MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "<?xml",
					MessageStr: "XML document",
					Mimetype:   getMimeBytes("application/xml"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/x-shellscript MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "#!/bin/sh",
					MessageStr: "Shell script",
					Mimetype:   getMimeBytes("application/x-shellscript"),
				},
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "image/png MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "\\x89PNG",
					MessageStr: "PNG image",
					Mimetype:   getMimeBytes("image/png"),
				},
			},
			expected: BINTEST, // Binary MIME type
		},
		{
			name: "application/octet-stream MIME type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "DATA",
					MessageStr: "Binary data",
					Mimetype:   getMimeBytes("application/octet-stream"),
				},
			},
			expected: BINTEST,
		},

		// Message content indicators (for string type, message does NOT override)
		{
			name: "message with text indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "DATA",
					MessageStr: "ASCII text file",
				},
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with script indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "#!/usr/bin/env",
					MessageStr: "Python script",
				},
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with source indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "package",
					MessageStr: "Go source file",
				},
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with code indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "function",
					MessageStr: "JavaScript code",
				},
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with UTF-8 indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST",
					MessageStr: "UTF-8 Unicode text",
				},
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},

		// Edge cases
		{
			name: "empty test value",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "",
					MessageStr: "Empty test",
				},
			},
			expected: BINTEST, // Default to binary
		},
		{
			name: "pstring type",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "pstring",
					TestStr:    "TEST",
					MessageStr: "Pascal string",
				},
			},
			expected: BINTEST, // pstring is like string, defaults to binary
		},
		{
			name: "numeric type - byte",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "byte",
					TestStr:    "0x42",
					MessageStr: "Byte value",
				},
			},
			expected: BINTEST, // Numeric types are binary
		},
		{
			name: "numeric type - short",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "short",
					TestStr:    "1234",
					MessageStr: "Short value",
				},
			},
			expected: BINTEST,
		},
		{
			name: "numeric type - float",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "float",
					TestStr:    "3.14",
					MessageStr: "Float value",
				},
			},
			expected: BINTEST,
		},
		{
			name: "string with t flag",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "#!/bin/bash",
					MessageStr: "Shell script",
					Flags:      STRING_FLAG_TEXT,
				},
			},
			expected: TEXTTEST, // 't' flag forces text
		},
		{
			name: "string with T flag",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "#!/bin/bash",
					MessageStr: "Shell script",
					Flags:      STRING_FLAG_TEXT,
				},
			},
			expected: TEXTTEST, // 'T' flag also forces text
		},
		{
			name: "string with other flags but not t",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "text",
					MessageStr: "Case insensitive",
					Flags:      STRING_FLAG_COMPACT_WHITESPACE | STRING_FLAG_COMPACT_OPTIONAL_WHITESPACE,
				},
			},
			expected: BINTEST, // Without 't' flag, still binary
		},
		{
			name: "mixed printable and non-printable",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST\\x00DATA",
					MessageStr: "Mixed content",
				},
			},
			expected: BINTEST, // Contains null byte
		},
		{
			name: "mostly printable but has one binary byte",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "This is a long text string with one \\x01 binary byte",
					MessageStr: "Mostly text",
				},
			},
			expected: BINTEST, // Has non-printable character
		},
		{
			name: "regex with binary content",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "regex",
					TestStr:    "\\x00\\x01",
					MessageStr: "Binary regex",
				},
			},
			expected: BINTEST, // Regex with binary content
		},
		// Message indicators for regex/search types (should override)
		{
			name: "regex with text message indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "regex",
					TestStr:    "^DATA",
					MessageStr: "Text file",
				},
			},
			expected: TEXTTEST, // Regex type with "text" in message
		},
		{
			name: "search with script message indicator",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "search",
					TestStr:    "#!/bin/sh",
					MessageStr: "Shell script",
				},
			},
			expected: TEXTTEST, // Search type with "script" in message
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.GetTestType()
			if result != tt.expected {
				t.Errorf("GetTestType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetTestTypeOriginalBehavior specifically tests that we match
// the original file command's behavior for the test_minimal.magic file
func TestGetTestTypeOriginalBehavior(t *testing.T) {
	// These should match the original file command's --list output
	tests := []struct {
		name     string
		entry    *Entry
		expected TestType
	}{
		{
			name: "TEST string from test_minimal.magic",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "TEST",
					MessageStr: "Test string",
					Lineno:     3,
				},
			},
			expected: BINTEST, // Original classifies as Binary
		},
		{
			name: "DATA string from test_minimal.magic",
			entry: &Entry{
				Mp: &Magic{
					TypeStr:    "string",
					TestStr:    "DATA",
					MessageStr: "Data string",
					Lineno:     6,
				},
			},
			expected: BINTEST, // Original classifies as Binary
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.GetTestType()
			if result != tt.expected {
				t.Errorf("GetTestType() = %v, want %v for %q (should match original file command)",
					result, tt.expected, tt.entry.Mp.TestStr)
			}
		})
	}
}