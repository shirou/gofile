package detector

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

// DatabaseInterface defines the interface for magic databases
type DatabaseInterface interface {
	GetEntries() []*magic.MagicEntry
	GetEntriesSortedByStrength() []*magic.MagicEntry // Get entries sorted by strength
	FindNamedEntry(name string) *magic.MagicEntry    // For FILE_USE resolution
}

// Detector handles file type detection using magic patterns
type Detector struct {
	database DatabaseInterface
	options  *Options
	logger   *slog.Logger
}

// Options configures detection behavior
type Options struct {
	MIME        bool // Return MIME type instead of description
	Brief       bool // Return brief description
	MaxReadSize int  // Maximum bytes to read from file (default: 1MB)
	Debug       bool // Enable debug logging
}

// DefaultOptions returns default detection options
func DefaultOptions() *Options {
	return &Options{
		MIME:        false,
		Brief:       false,
		MaxReadSize: 1024 * 1024, // 1MB
	}
}

// New creates a new detector with the given magic database
func New(db DatabaseInterface, opts *Options) *Detector {
	if opts == nil {
		opts = DefaultOptions()
	}

	// Configure logger based on debug mode
	var logger *slog.Logger
	if opts.Debug {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}

	return &Detector{
		database: db,
		options:  opts,
		logger:   logger,
	}
}

// formatResult formats the detection result based on options
func (d *Detector) formatResult(desc string) string {
	if d.options.MIME {
		// Convert description to MIME type
		// This is a simplified mapping - real implementation would be more comprehensive
		return descriptionToMIME(desc)
	}

	if d.options.Brief {
		// Return brief description
		return makeBrief(desc)
	}

	return desc
}

// DetectFile detects the file type of the given file path
func (d *Detector) DetectFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if d.options.Debug {
		stat, _ := file.Stat()
		d.logger.Debug("DetectFile: Opened file",
			"path", path,
			"size", stat.Size())
	}

	return d.DetectReader(file)
}

// DetectReader detects the file type from an io.Reader
func (d *Detector) DetectReader(reader io.Reader) (string, error) {
	// Read initial bytes for analysis
	buffer := make([]byte, d.options.MaxReadSize)
	n, err := reader.Read(buffer)

	if d.options.Debug {
		d.logger.Debug("DetectReader: Read attempt",
			"bytes_read", n,
			"error", err,
			"max_read_size", d.options.MaxReadSize,
			"buffer_len", len(buffer))
		if n > 0 {
			d.logger.Debug("DetectReader: First 16 bytes",
				"hex", hex.EncodeToString(buffer[:min(16, n)]))
		}
	}

	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read data: %w", err)
	}

	// Trim buffer to actual read size
	buffer = buffer[:n]

	return d.DetectBytes(buffer)
}

// DetectBytes detects the file type from a byte slice using strength-based priority
func (d *Detector) DetectBytes(data []byte) (string, error) {
	if len(data) == 0 {
		if d.options.Debug {
			d.logger.Error("ERROR: DetectBytes received empty data")
		}
		return "empty", nil
	}

	if d.options.Debug {
		d.logger.Debug("DetectBytes: Processing data", "bytes", len(data))
	}

	// Get all magic entries sorted by strength (descending)
	entries := d.database.GetEntriesSortedByStrength()

	if d.options.Debug {
		d.logger.Debug("=== Starting strength-based detection ===",
			"data_bytes", len(data),
			"first_32_bytes", hex.EncodeToString(data[:min(32, len(data))]),
			"total_entries", len(entries))
	}

	if len(entries) == 0 {
		return "data (no magic entries loaded)", nil
	}

	// Single pass through strength-sorted entries
	matchAttempts := 0
	for i, entry := range entries {
		matchAttempts++

		// Skip entries with offsets beyond our data
		if entry.Offset >= int32(len(data)) {
			continue
		}

		if d.options.Debug && matchAttempts <= 20 {
			d.logger.Debug("Testing entry",
				"index", i,
				"strength", entry.Strength,
				"type", entry.Type,
				"offset", entry.Offset,
				"cont_level", entry.ContLevel,
				"desc", entry.GetDescription())
		}

		// Handle continuation sequences
		if d.isContinuationCandidate(entry, entries, i) {
			if match, result := d.evaluateWithContinuations(data, entries, i, data); match {
				if d.options.Debug {
					d.logger.Debug("✓ CONTINUATION MATCH",
						"entry", i,
						"strength", entry.Strength,
						"result", result)
				}

				if len(strings.TrimSpace(result)) > 0 && d.isValidDescription(result) {
					return d.formatResult(result), nil
				}
			}
		}

		// Handle deeply nested entries that might work independently
		if entry.ContLevel >= 16 && entry.ContLevel <= 64 && d.hasPatternMatch(entry) {
			if match, result := d.matchEntry(data, entry, data); match {
				finalResult := d.enhanceDeepNestedResult(data, entries, i, result)
				
				if d.options.Debug {
					d.logger.Debug("✓ DEEP-NESTED MATCH",
						"entry", i,
						"strength", entry.Strength,
						"result", finalResult)
				}

				if len(strings.TrimSpace(finalResult)) > 0 && d.isValidDescription(finalResult) {
					return d.formatResult(finalResult), nil
				}
			}
		}

		// Standard pattern matching
		if match, result := d.matchEntry(data, entry, data); match {
			if d.options.Debug {
				d.logger.Debug("✓ STANDARD MATCH",
					"entry", i,
					"strength", entry.Strength,
					"result", result)
			}

			// Skip matches with empty or invalid results
			if len(strings.TrimSpace(result)) == 0 {
				if d.options.Debug {
					d.logger.Debug("  Skipping empty result, continuing search...")
				}
				continue
			}

			if !d.isValidDescription(result) {
				if d.options.Debug {
					d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
				}
				continue
			}

			return d.formatResult(result), nil
		}
	}

	if d.options.Debug {
		d.logger.Debug("No matches found after checking entries", "match_attempts", matchAttempts)
	}

	// Enhanced fallback detection
	return d.performFallbackDetection(data)
}

// hasPatternMatch checks if an entry has a meaningful pattern to match against
func (d *Detector) hasPatternMatch(entry *magic.MagicEntry) bool {
	if entry.Type == magic.FILE_STRING || entry.Type == magic.FILE_PSTRING {
		value := entry.GetValueAsString()
		return len(value) > 0
	}

	// Add other type checks as needed
	return entry.Type == magic.FILE_BYTE || entry.Type == magic.FILE_SHORT ||
		entry.Type == magic.FILE_LONG || entry.Type == magic.FILE_LELONG ||
		entry.Type == magic.FILE_BELONG
}

// hasKnownBinaryPattern checks if an entry contains a known binary signature
func (d *Detector) hasKnownBinaryPattern(entry *magic.MagicEntry) bool {
	if entry.Type != magic.FILE_STRING {
		return false
	}

	value := entry.GetValueAsString()
	if len(value) < 4 {
		return false
	}

	// Check for 7z signature: 37 7a bc af 27 1c
	if len(value) >= 6 {
		if value[0] == 0x37 && value[1] == 0x7a && value[2] == 0xbc &&
			value[3] == 0xaf && value[4] == 0x27 && value[5] == 0x1c {
			return true
		}
	}

	// Add other known binary patterns as needed
	// ZIP signature: 50 4b 03 04 or 50 4b 05 06 or 50 4b 07 08
	if len(value) >= 4 {
		if value[0] == 0x50 && value[1] == 0x4b &&
			(value[2] == 0x03 || value[2] == 0x05 || value[2] == 0x07) {
			return true
		}
	}

	// PDF signature: 25 50 44 46 (%PDF)
	if len(value) >= 4 {
		if value[0] == 0x25 && value[1] == 0x50 && value[2] == 0x44 && value[3] == 0x46 {
			return true
		}
	}

	return false
}

// enhanceDeepNestedResult tries to find a meaningful description for deeply nested entries
func (d *Detector) enhanceDeepNestedResult(data []byte, entries []*magic.MagicEntry, index int, baseResult string) string {
	entry := entries[index]

	if d.options.Debug {
		d.logger.Debug("ENHANCE: Processing deep nested result",
			"index", index,
			"base_result", baseResult,
			"cont_level", entry.ContLevel)
	}

	// If the base result is empty, look for description in nearby entries
	if len(strings.TrimSpace(baseResult)) == 0 {
		// Check subsequent entries at the same level for descriptions
		for i := index + 1; i < len(entries) && i < index+20; i++ {
			nextEntry := entries[i]

			// Stop if we hit a different continuation level
			if nextEntry.ContLevel != entry.ContLevel {
				continue
			}

			desc := nextEntry.GetDescription()
			if len(strings.TrimSpace(desc)) > 0 {
				// Try to match this entry to see if it provides additional context
				if match, result := d.matchEntry(data, nextEntry, data); match {
					if len(strings.TrimSpace(result)) > 0 {
						return result
					}
					return desc
				}
			}
		}

		// For 7z specifically, provide a default description based on the signature match
		if entry.Type == magic.FILE_STRING && entry.Offset == 0 {
			value := entry.GetValueAsString()
			if len(value) >= 6 {
				// Check for 7z signature: 37 7a bc af 27 1c
				if value[0] == 0x37 && value[1] == 0x7a && value[2] == 0xbc &&
					value[3] == 0xaf && value[4] == 0x27 && value[5] == 0x1c {
					// Try to determine version from the file
					if len(data) >= 7 {
						version := data[6]
						return fmt.Sprintf("7-zip archive data, version 0.%d", version)
					}
					return "7-zip archive data"
				}
			}
		}
	}

	return baseResult
}


// matchEntry attempts to match data against a single magic entry
func (d *Detector) matchEntry(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	// Check for indirect addressing first
	if entry.Flag&magic.INDIR != 0 {
		return d.matchIndirectWithFullData(data, entry, fullData)
	}

	// Check if offset is valid
	if entry.Offset < 0 || int(entry.Offset) >= len(data) {
		return false, ""
	}

	// Check if we have enough data to read at the specified offset
	startPos := int(entry.Offset)
	if startPos >= len(data) {
		return false, ""
	}

	// Calculate end position based on value length or data type
	var endPos int
	if entry.Vallen > 0 && entry.Type != magic.FILE_BESTRING16 && entry.Type != magic.FILE_STRING {
		endPos = startPos + int(entry.Vallen)
	} else {
		// Use default sizes based on type
		switch entry.Type {
		case magic.FILE_BYTE:
			endPos = startPos + 1
		case magic.FILE_SHORT, magic.FILE_BESHORT, magic.FILE_LESHORT:
			endPos = startPos + 2
		case magic.FILE_LONG, magic.FILE_BELONG, magic.FILE_LELONG:
			endPos = startPos + 4
		case magic.FILE_BEQUAD, magic.FILE_LEQUAD, magic.FILE_QUAD:
			endPos = startPos + 8
		case magic.FILE_GUID:
			endPos = startPos + 16
		case magic.FILE_DER:
			// DER is variable length, read enough for header analysis
			endPos = startPos + 32
		case magic.FILE_FLOAT, magic.FILE_BEFLOAT, magic.FILE_LEFLOAT:
			endPos = startPos + 4
		case magic.FILE_DOUBLE, magic.FILE_BEDOUBLE, magic.FILE_LEDOUBLE:
			endPos = startPos + 8
		case magic.FILE_BEDATE, magic.FILE_LEDATE:
			endPos = startPos + 4
		case magic.FILE_BELDATE:
			endPos = startPos + 4
		case magic.FILE_LEQDATE, magic.FILE_BEQDATE:
			endPos = startPos + 8
		case magic.FILE_DATE, magic.FILE_LDATE, magic.FILE_LELDATE:
			endPos = startPos + 4
		case magic.FILE_QDATE, magic.FILE_QLDATE, magic.FILE_LEQLDATE, magic.FILE_BEQLDATE:
			endPos = startPos + 8
		case magic.FILE_MSDOSDATE, magic.FILE_LEMSDOSDATE, magic.FILE_BEMSDOSDATE:
			endPos = startPos + 2
		case magic.FILE_MSDOSTIME, magic.FILE_LEMSDOSTIME, magic.FILE_BEMSDOSTIME:
			endPos = startPos + 2
		case magic.FILE_OCTAL:
			endPos = startPos + 4
		case magic.FILE_MEDATE, magic.FILE_MELDATE, magic.FILE_MELONG:
			endPos = startPos + 4
		case magic.FILE_QWDATE, magic.FILE_LEQWDATE, magic.FILE_BEQWDATE:
			endPos = startPos + 8
		case magic.FILE_BEID3, magic.FILE_LEID3:
			endPos = startPos + 4
		case magic.FILE_BEVARINT, magic.FILE_LEVARINT:
			// Variable length - read up to 8 bytes
			endPos = startPos + 8
			if endPos > len(data) {
				endPos = len(data)
			}
		case magic.FILE_BESTRING16:
			// For 16-bit strings, read until null terminator or end of data
			// Need to read more than just Vallen for string matching
			endPos = len(data)
		case magic.FILE_STRING:
			// For strings, read until null terminator or end of data
			endPos = len(data)
		case magic.FILE_PSTRING:
			// Pascal string: first byte is length, followed by string data
			if startPos < len(data) {
				strLen := int(data[startPos])
				endPos = startPos + 1 + strLen
			} else {
				endPos = startPos + 1
			}
		default:
			endPos = startPos + 4 // Default to 4 bytes
		}
	}

	if endPos > len(data) {
		endPos = len(data)
	}

	if startPos >= endPos {
		return false, ""
	}

	segment := data[startPos:endPos]

	// Perform the actual matching based on entry type
	return d.performMatch(segment, entry, fullData)
}

// performMatch performs the actual pattern matching
func (d *Detector) performMatch(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if d.options.Debug {
		d.logger.Debug("  Matching type at offset", "type", entry.Type, "offset", entry.Offset)
		d.logger.Debug("  Data at offset", "hex", hex.EncodeToString(data[:min(16, len(data))]))
	}

	switch entry.Type {
	case magic.FILE_BYTE:
		return d.matchByte(data, entry, fullData)
	case magic.FILE_SHORT:
		return d.matchShort(data, entry, fullData)
	case magic.FILE_LONG:
		return d.matchLong(data, entry, fullData)
	case magic.FILE_STRING:
		return d.matchString(data, entry)
	case magic.FILE_BELONG:
		return d.matchBELong(data, entry, fullData)
	case magic.FILE_LELONG:
		return d.matchLELong(data, entry, fullData)
	case magic.FILE_BESHORT:
		return d.matchBEShort(data, entry, fullData)
	case magic.FILE_LESHORT:
		return d.matchLEShort(data, entry, fullData)
	case magic.FILE_BEQUAD:
		return d.matchBEQuad(data, entry, fullData)
	case magic.FILE_LEQUAD:
		return d.matchLEQuad(data, entry, fullData)
	case magic.FILE_PSTRING:
		return d.matchPString(data, entry)
	case magic.FILE_GUID:
		return d.matchGUID(data, entry)
	case magic.FILE_DER:
		return d.matchDER(data, entry)
	case magic.FILE_FLOAT:
		return d.matchFloat(data, entry, fullData)
	case magic.FILE_DOUBLE:
		return d.matchDouble(data, entry, fullData)
	case magic.FILE_BEDATE:
		return d.matchBEDate(data, entry, fullData)
	case magic.FILE_LEDATE:
		return d.matchLEDate(data, entry, fullData)
	case magic.FILE_BELDATE:
		return d.matchBELDate(data, entry, fullData)
	case magic.FILE_LEQDATE:
		return d.matchLEQDate(data, entry, fullData)
	case magic.FILE_BEQDATE:
		return d.matchBEQDate(data, entry, fullData)
	case magic.FILE_QUAD:
		return d.matchQuad(data, entry, fullData)
	case magic.FILE_BEFLOAT:
		return d.matchBEFloat(data, entry, fullData)
	case magic.FILE_LEFLOAT:
		return d.matchLEFloat(data, entry, fullData)
	case magic.FILE_BEDOUBLE:
		return d.matchBEDouble(data, entry, fullData)
	case magic.FILE_LEDOUBLE:
		return d.matchLEDouble(data, entry, fullData)
	case magic.FILE_BESTRING16:
		return d.matchBEString16(data, entry)
	case magic.FILE_LESTRING16:
		return d.matchLEString16(data, entry)
	case magic.FILE_OFFSET:
		return d.matchOffset(data, entry, fullData)
	case magic.FILE_INDIRECT:
		return d.matchIndirect(data, entry)
	case magic.FILE_USE:
		return d.matchUse(data, entry)
	case magic.FILE_CLEAR:
		return d.matchClear(data, entry, fullData)
	case magic.FILE_DATE:
		return d.matchDate(data, entry, fullData)
	case magic.FILE_LDATE:
		return d.matchLDate(data, entry, fullData)
	case magic.FILE_LELDATE:
		return d.matchLELDate(data, entry, fullData)
	case magic.FILE_QDATE:
		return d.matchQDate(data, entry, fullData)
	case magic.FILE_QLDATE:
		return d.matchQLDate(data, entry, fullData)
	case magic.FILE_LEQLDATE:
		return d.matchLEQLDate(data, entry, fullData)
	case magic.FILE_BEQLDATE:
		return d.matchBEQLDate(data, entry, fullData)
	case magic.FILE_MSDOSDATE:
		return d.matchMSDOSDate(data, entry, fullData)
	case magic.FILE_LEMSDOSDATE:
		return d.matchLEMSDOSDate(data, entry, fullData)
	case magic.FILE_BEMSDOSDATE:
		return d.matchBEMSDOSDate(data, entry, fullData)
	case magic.FILE_MSDOSTIME:
		return d.matchMSDOSTime(data, entry, fullData)
	case magic.FILE_LEMSDOSTIME:
		return d.matchLEMSDOSTime(data, entry, fullData)
	case magic.FILE_BEMSDOSTIME:
		return d.matchBEMSDOSTime(data, entry, fullData)
	case magic.FILE_OCTAL:
		return d.matchOctal(data, entry, fullData)
	case magic.FILE_MEDATE:
		return d.matchMEDate(data, entry, fullData)
	case magic.FILE_MELDATE:
		return d.matchMELDate(data, entry, fullData)
	case magic.FILE_MELONG:
		return d.matchMELong(data, entry, fullData)
	case magic.FILE_QWDATE:
		return d.matchQWDate(data, entry, fullData)
	case magic.FILE_LEQWDATE:
		return d.matchLEQWDate(data, entry, fullData)
	case magic.FILE_BEQWDATE:
		return d.matchBEQWDate(data, entry, fullData)
	case magic.FILE_BEID3:
		return d.matchBEID3(data, entry, fullData)
	case magic.FILE_LEID3:
		return d.matchLEID3(data, entry, fullData)
	case magic.FILE_BEVARINT:
		return d.matchBEVarInt(data, entry, fullData)
	case magic.FILE_LEVARINT:
		return d.matchLEVarInt(data, entry, fullData)
	case magic.FILE_REGEX:
		return d.matchRegex(data, entry)
	case magic.FILE_SEARCH:
		return d.matchSearch(data, entry, fullData)
	case magic.FILE_NAME:
		return d.matchName(data, entry)
	case magic.FILE_DEFAULT:
		return d.matchDefault(data, entry)
	case 99, 114: // Custom types - need to analyze actual values
		return d.matchCustomType(data, entry, fullData)
	default:
		if d.options.Debug {
			d.logger.Debug("  Unimplemented type", "type", entry.Type)
		}
		return false, ""
	}
}

// performFallbackDetection provides intelligent fallback when no magic entries match
func (d *Detector) performFallbackDetection(data []byte) (string, error) {
	if len(data) == 0 {
		if d.options.MIME {
			return "inode/x-empty", nil
		}
		return "empty", nil
	}

	// Check if data appears to be text
	if d.isTextData(data) {
		encoding := d.detectTextEncoding(data)
		if d.options.MIME {
			return "text/plain", nil
		}
		return encoding + " text", nil
	}

	// Default for binary data
	if d.options.MIME {
		return "application/octet-stream", nil
	}
	return "data", nil
}

// isTextData determines if data appears to be text
func (d *Detector) isTextData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check first 1KB or all data if smaller
	sampleSize := len(data)
	if sampleSize > 1024 {
		sampleSize = 1024
	}
	sample := data[:sampleSize]

	textBytes := 0
	controlBytes := 0

	for _, b := range sample {
		switch {
		case b == 0:
			// Null bytes usually indicate binary
			return false
		case b == '\t' || b == '\n' || b == '\r':
			// Common text control characters
			textBytes++
		case b >= 32 && b <= 126:
			// Printable ASCII
			textBytes++
		case b >= 128:
			// Extended ASCII (could be ISO-8859 or UTF-8)
			textBytes++
		default:
			// Other control characters
			controlBytes++
		}
	}

	// Consider it text if >85% of bytes are text-like
	total := textBytes + controlBytes
	if total == 0 {
		return false
	}

	textRatio := float64(textBytes) / float64(total)
	return textRatio > 0.85
}

// detectTextEncoding determines text encoding type
func (d *Detector) detectTextEncoding(data []byte) string {
	if len(data) == 0 {
		return "ASCII"
	}

	hasExtended := false
	hasHighBit := false

	// Check for extended characters
	for _, b := range data {
		if b > 127 {
			hasExtended = true
			if b >= 128 && b <= 255 {
				hasHighBit = true
			}
		}
	}

	if !hasExtended {
		return "ASCII"
	}

	if hasHighBit {
		// Could be ISO-8859 or other 8-bit encoding
		return "ISO-8859"
	}

	// Default to ASCII for now
	return "ASCII"
}
