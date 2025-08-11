package magic

import (
	"testing"
)

func TestGetTestType(t *testing.T) {
	tests := []struct {
		name     string
		entry    Entry
		expected TestType
	}{
		// Binary patterns - regular string type (matching original file command)
		{
			name: "regular string with printable text TEST",
			entry: Entry{
				Type:    "string",
				Test:    "TEST",
				Message: "Test string",
			},
			expected: BINTEST, // Regular strings are ALWAYS binary
		},
		{
			name: "regular string with printable text DATA",
			entry: Entry{
				Type:    "string",
				Test:    "DATA",
				Message: "Data string",
			},
			expected: BINTEST, // Regular strings are ALWAYS binary
		},
		{
			name: "string with binary bytes PNG signature",
			entry: Entry{
				Type:    "string",
				Test:    "\\x89PNG\\x0d\\x0a\\x1a\\x0a",
				Message: "PNG image",
			},
			expected: BINTEST,
		},
		{
			name: "string with null bytes",
			entry: Entry{
				Type:    "string",
				Test:    "\\x00\\x01\\x02",
				Message: "Binary data",
			},
			expected: BINTEST,
		},
		{
			name: "string with DEL character",
			entry: Entry{
				Type:    "string",
				Test:    "test\\177data",
				Message: "Data with DEL",
			},
			expected: BINTEST,
		},
		{
			name: "message containing binary keyword",
			entry: Entry{
				Type:    "string",
				Test:    "TEST",
				Message: "Binary file format",
			},
			expected: BINTEST,
		},

		// Text patterns - regex type
		{
			name: "regex pattern for C source",
			entry: Entry{
				Type:    "regex",
				Test:    "^#include",
				Message: "C source",
			},
			expected: TEXTTEST, // Regex with printable content is text
		},
		{
			name: "regex pattern with text content",
			entry: Entry{
				Type:    "regex",
				Test:    "^#!/bin/bash",
				Message: "Shell script",
			},
			expected: TEXTTEST,
		},

		// Text patterns - search type with UTF-8 valid content
		{
			name: "search pattern with printable text",
			entry: Entry{
				Type:    "search",
				Test:    "BEGIN",
				Message: "PEM certificate",
			},
			expected: TEXTTEST, // Search with printable UTF-8 is text
		},
		{
			name: "search/256 pattern with text",
			entry: Entry{
				Type:    "search/256",
				Test:    "DOCTYPE",
				Message: "HTML document",
			},
			expected: TEXTTEST,
		},

		// Binary patterns - search type with binary content
		{
			name: "search pattern with binary content",
			entry: Entry{
				Type:    "search",
				Test:    "\\x00\\x01\\x02",
				Message: "Binary search",
			},
			expected: BINTEST,
		},

		// MIME type doesn't affect classification (matching original file command)
		{
			name: "text/plain MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "TEST",
				Message:  "Plain text file",
				MimeType: "text/plain",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "text/html MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "<html>",
				Message:  "HTML document",
				MimeType: "text/html",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/json MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "{",
				Message:  "JSON data",
				MimeType: "application/json",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/javascript MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "function",
				Message:  "JavaScript code",
				MimeType: "application/javascript",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/xml MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "<?xml",
				Message:  "XML document",
				MimeType: "application/xml",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "application/x-shellscript MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "#!/bin/sh",
				Message:  "Shell script",
				MimeType: "application/x-shellscript",
			},
			expected: BINTEST, // MIME doesn't override for string type
		},
		{
			name: "image/png MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "\\x89PNG",
				Message:  "PNG image",
				MimeType: "image/png",
			},
			expected: BINTEST, // Binary MIME type
		},
		{
			name: "application/octet-stream MIME type",
			entry: Entry{
				Type:     "string",
				Test:     "DATA",
				Message:  "Binary data",
				MimeType: "application/octet-stream",
			},
			expected: BINTEST,
		},

		// Message content indicators (for string type, message does NOT override)
		{
			name: "message with text indicator",
			entry: Entry{
				Type:    "string",
				Test:    "DATA",
				Message: "ASCII text file",
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with script indicator",
			entry: Entry{
				Type:    "string",
				Test:    "#!/usr/bin/env",
				Message: "Python script",
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with source indicator",
			entry: Entry{
				Type:    "string",
				Test:    "package",
				Message: "Go source file",
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with code indicator",
			entry: Entry{
				Type:    "string",
				Test:    "function",
				Message: "JavaScript code",
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},
		{
			name: "message with UTF-8 indicator",
			entry: Entry{
				Type:    "string",
				Test:    "TEST",
				Message: "UTF-8 Unicode text",
			},
			expected: BINTEST, // string type is always binary, message doesn't override
		},

		// Edge cases
		{
			name: "empty test value",
			entry: Entry{
				Type:    "string",
				Test:    "",
				Message: "Empty test",
			},
			expected: BINTEST, // Default to binary
		},
		{
			name: "pstring type",
			entry: Entry{
				Type:    "pstring",
				Test:    "TEST",
				Message: "Pascal string",
			},
			expected: BINTEST, // pstring is like string, defaults to binary
		},
		{
			name: "numeric type - byte",
			entry: Entry{
				Type:    "byte",
				Test:    "0x42",
				Message: "Byte value",
			},
			expected: BINTEST, // Numeric types are binary
		},
		{
			name: "numeric type - short",
			entry: Entry{
				Type:    "short",
				Test:    "1234",
				Message: "Short value",
			},
			expected: BINTEST,
		},
		{
			name: "numeric type - float",
			entry: Entry{
				Type:    "float",
				Test:    "3.14",
				Message: "Float value",
			},
			expected: BINTEST,
		},
		{
			name: "string with t flag",
			entry: Entry{
				Type:    "string",
				Test:    "#!/bin/bash",
				Message: "Shell script",
				Flags:   []string{"t"},
			},
			expected: TEXTTEST, // 't' flag forces text
		},
		{
			name: "string with T flag",
			entry: Entry{
				Type:    "string",
				Test:    "#!/bin/bash",
				Message: "Shell script",
				Flags:   []string{"T"},
			},
			expected: TEXTTEST, // 'T' flag also forces text
		},
		{
			name: "string with other flags but not t",
			entry: Entry{
				Type:    "string",
				Test:    "text",
				Message: "Case insensitive",
				Flags:   []string{"c", "W"},
			},
			expected: BINTEST, // Without 't' flag, still binary
		},
		{
			name: "mixed printable and non-printable",
			entry: Entry{
				Type:    "string",
				Test:    "TEST\\x00DATA",
				Message: "Mixed content",
			},
			expected: BINTEST, // Contains null byte
		},
		{
			name: "mostly printable but has one binary byte",
			entry: Entry{
				Type:    "string",
				Test:    "This is a long text string with one \\x01 binary byte",
				Message: "Mostly text",
			},
			expected: BINTEST, // Has non-printable character
		},
		{
			name: "regex with binary content",
			entry: Entry{
				Type:    "regex",
				Test:    "\\x00\\x01",
				Message: "Binary regex",
			},
			expected: BINTEST, // Regex with binary content
		},
		// Message indicators for regex/search types (should override)
		{
			name: "regex with text message indicator",
			entry: Entry{
				Type:    "regex",
				Test:    "^DATA",
				Message: "Text file",
			},
			expected: TEXTTEST, // Regex type with "text" in message
		},
		{
			name: "search with script message indicator",
			entry: Entry{
				Type:    "search",
				Test:    "#!/bin/sh",
				Message: "Shell script",
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
		entry    Entry
		expected TestType
	}{
		{
			name: "TEST string from test_minimal.magic",
			entry: Entry{
				Type:       "string",
				Test:       "TEST",
				Message:    "Test string",
				LineNumber: 3,
			},
			expected: BINTEST, // Original classifies as Binary
		},
		{
			name: "DATA string from test_minimal.magic",
			entry: Entry{
				Type:       "string",
				Test:       "DATA",
				Message:    "Data string",
				LineNumber: 6,
			},
			expected: BINTEST, // Original classifies as Binary
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.GetTestType()
			if result != tt.expected {
				t.Errorf("GetTestType() = %v, want %v for %q (should match original file command)",
					result, tt.expected, tt.entry.Test)
			}
		})
	}
}