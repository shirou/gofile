package detector

import (
	"strings"
	"unsafe"
)

// Helper functions for reading different integer types

func readUint16(data []byte, littleEndian bool) uint16 {
	if littleEndian {
		return uint16(data[0]) | uint16(data[1])<<8
	}
	return uint16(data[1]) | uint16(data[0])<<8
}

func readInt16(data []byte, littleEndian bool) int16 {
	return int16(readUint16(data, littleEndian))
}

func readUint32(data []byte, littleEndian bool) uint32 {
	if littleEndian {
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	}
	return uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
}

func readInt32(data []byte, littleEndian bool) int32 {
	return int32(readUint32(data, littleEndian))
}

func readUint64(data []byte, littleEndian bool) uint64 {
	if littleEndian {
		return uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
			uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
	}
	return uint64(data[7]) | uint64(data[6])<<8 | uint64(data[5])<<16 | uint64(data[4])<<24 |
		uint64(data[3])<<32 | uint64(data[2])<<40 | uint64(data[1])<<48 | uint64(data[0])<<56
}

func readInt64(data []byte, littleEndian bool) int64 {
	return int64(readUint64(data, littleEndian))
}

func readFloat32(data []byte, littleEndian bool) float32 {
	bits := readUint32(data, littleEndian)
	return *(*float32)(unsafe.Pointer(&bits))
}

func readFloat64(data []byte, littleEndian bool) float64 {
	bits := readUint64(data, littleEndian)
	return *(*float64)(unsafe.Pointer(&bits))
}

// compareValues compares two values based on the relation operator
func compareValues(actual, expected uint64, relation byte) bool {
	switch relation {
	case '=', 0: // Equal (default)
		return actual == expected
	case '!': // Not equal
		return actual != expected
	case '<': // Less than
		return actual < expected
	case '>': // Greater than
		return actual > expected
	case '&': // Bitwise AND
		return (actual & expected) == expected
	case '^': // Bitwise XOR
		return (actual ^ expected) != 0
	default:
		// Default to equality for unknown relations
		return actual == expected
	}
}

// compareFloats compares two float64 values based on the relation operator
func compareFloats(actual, expected float64, relation byte) bool {
	const epsilon = 1e-9 // Small tolerance for floating-point comparison

	switch relation {
	case '=', 0: // Equal (default)
		diff := actual - expected
		return diff > -epsilon && diff < epsilon
	case '!': // Not equal
		diff := actual - expected
		return diff <= -epsilon || diff >= epsilon
	case '<': // Less than
		return actual < expected
	case '>': // Greater than
		return actual > expected
	case '&': // Bitwise AND (treat as integer comparison)
		return (uint64(actual) & uint64(expected)) == uint64(expected)
	case '^': // Bitwise XOR (treat as integer comparison)
		return (uint64(actual) ^ uint64(expected)) != 0
	default:
		// Default to equality for unknown relations
		diff := actual - expected
		return diff > -epsilon && diff < epsilon
	}
}

// descriptionToMIME converts a description to MIME type
func descriptionToMIME(desc string) string {
	desc = strings.ToLower(desc)

	// Certificate and security formats (must come first to avoid substring conflicts)
	switch {
	case contains(desc, "pem certificate"):
		return "text/plain"
	case contains(desc, "asn.1 der") || contains(desc, "certificate"):
		return "application/x-x509-ca-cert"
	case contains(desc, "pem"):
		return "application/x-pem-file"
	case contains(desc, "x.509"):
		return "application/x-x509-ca-cert"
	}

	// Image formats
	switch {
	case contains(desc, "png"):
		return "image/png"
	case contains(desc, "jpeg") || contains(desc, "jpg"):
		return "image/jpeg"
	case contains(desc, "gif"):
		return "image/gif"
	case contains(desc, "webp"):
		return "image/webp"
	case contains(desc, "bmp"):
		return "image/bmp"
	case contains(desc, "tiff") || contains(desc, "tif"):
		return "image/tiff"
	case contains(desc, "svg"):
		return "image/svg+xml"
	case contains(desc, "ico"):
		return "image/x-icon"

	// Document formats
	case contains(desc, "pdf"):
		return "application/pdf"
	case contains(desc, "postscript"):
		return "application/postscript"
	case contains(desc, "microsoft word 2007"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case contains(desc, "microsoft excel 2007"):
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case contains(desc, "microsoft powerpoint 2007"):
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case contains(desc, "microsoft office 2007"):
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case contains(desc, "microsoft word") || contains(desc, "ms-word") || contains(desc, "word document"):
		return "application/msword"
	case contains(desc, "microsoft excel") || contains(desc, "excel"):
		return "application/vnd.ms-excel"
	case contains(desc, "microsoft powerpoint") || contains(desc, "powerpoint"):
		return "application/vnd.ms-powerpoint"
	case contains(desc, "openoffice") || contains(desc, "opendocument"):
		if contains(desc, "text") {
			return "application/vnd.oasis.opendocument.text"
		} else if contains(desc, "spreadsheet") {
			return "application/vnd.oasis.opendocument.spreadsheet"
		} else if contains(desc, "presentation") {
			return "application/vnd.oasis.opendocument.presentation"
		}
		return "application/vnd.oasis.opendocument.text"

	// Text formats
	case contains(desc, "html document") || contains(desc, "html"):
		return "text/html"
	case contains(desc, "xml document") || contains(desc, "xml"):
		return "text/xml"
	case contains(desc, "json"):
		return "application/json"
	case contains(desc, "yaml") || contains(desc, "yml"):
		return "text/yaml"
	case contains(desc, "csv"):
		return "text/csv"
	case contains(desc, "css"):
		return "text/css"
	case contains(desc, "javascript"):
		return "text/javascript"
	case contains(desc, "rfc 822 mail") || contains(desc, "rfc822 mail"):
		return "message/rfc822"
	case contains(desc, "dos batch file") || contains(desc, "batch file"):
		return "text/x-msdos-batch"
	case contains(desc, "ascii text") || contains(desc, "utf-8 text") || contains(desc, "text"):
		return "text/plain"

	// Archive formats (check most specific patterns first)
	case contains(desc, "7-zip"):
		return "application/x-7z-compressed"
	case contains(desc, "gzip") || contains(desc, "gz"):
		return "application/gzip"
	case contains(desc, "bzip2") || contains(desc, "bz2"):
		return "application/x-bzip2"
	case contains(desc, "tar"):
		return "application/x-tar"
	case contains(desc, "rar"):
		return "application/vnd.rar"
	case contains(desc, "zip"):
		return "application/zip"

	// Audio formats
	case contains(desc, "mp3"):
		return "audio/mpeg"
	case contains(desc, "wave audio") || contains(desc, "wav"):
		return "audio/x-wav"
	case contains(desc, "ogg"):
		return "audio/ogg"
	case contains(desc, "flac"):
		return "audio/flac"
	case contains(desc, "aac"):
		return "audio/aac"

	// Video formats
	case contains(desc, "mp4"):
		return "video/mp4"
	case contains(desc, "avi"):
		return "video/x-msvideo"
	case contains(desc, "mkv") || contains(desc, "matroska"):
		return "video/x-matroska"
	case contains(desc, "webm"):
		return "video/webm"
	case contains(desc, "mov"):
		return "video/quicktime"

	// Executable formats
	case contains(desc, "elf") && contains(desc, "executable"):
		return "application/x-executable"
	case contains(desc, "elf") && contains(desc, "shared object"):
		return "application/x-sharedlib"
	case contains(desc, "elf") && contains(desc, "relocatable"):
		return "application/x-object"
	case contains(desc, "elf") && contains(desc, "core file"):
		return "application/x-coredump"
	case contains(desc, "executable") || contains(desc, "elf"):
		return "application/x-executable"
	case contains(desc, "shared object") || contains(desc, "shared library"):
		return "application/x-sharedlib"
	case contains(desc, "pe32") || contains(desc, "ms-dos"):
		return "application/x-msdownload"

	// Script formats
	case contains(desc, "shell script") || contains(desc, "bash"):
		return "text/x-shellscript"
	case contains(desc, "python"):
		return "text/x-python"
	case contains(desc, "perl"):
		return "text/x-perl"
	case contains(desc, "ruby"):
		return "text/x-ruby"

	// Database formats
	case contains(desc, "sqlite"):
		return "application/x-sqlite3"
	case contains(desc, "composite document file"):
		return "application/x-ole-storage"

	// System formats
	case contains(desc, "empty"):
		return "inode/x-empty"
	case contains(desc, "directory"):
		return "inode/directory"
	case contains(desc, "symbolic link"):
		return "inode/symlink"

	default:
		return "application/octet-stream"
	}
}

// makeBrief creates a brief version of the description
func makeBrief(desc string) string {
	// Extract the first meaningful part of the description
	// TODO: Implement proper brief formatting
	if len(desc) > 50 {
		return desc[:47] + "..."
	}
	return desc
}

// Utility functions

func findNull(s string) int {
	for i, c := range s {
		if c == 0 {
			return i
		}
	}
	return -1
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
