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

// DetectBytes detects the file type from a byte slice
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

	// Get all magic entries from database
	entries := d.database.GetEntries()

	if d.options.Debug {
		d.logger.Debug("=== Starting detection ===",
			"data_bytes", len(data),
			"first_32_bytes", hex.EncodeToString(data[:min(32, len(data))]),
			"total_entries", len(entries))
	}

	if len(entries) == 0 {
		return "data (no magic entries loaded)", nil
	}

	// Try to match against each magic entry with priority ordering
	matchAttempts := 0

	// First pass: Specific binary signatures at offset 0
	for i, entry := range entries {
		if entry.Offset != 0 {
			continue
		}
		
		// Process specific binary signatures (including binary strings)
		if d.isSpecificBinarySignature(entry) {
			if match, result := d.matchEntry(data, entry, data); match {
				if d.options.Debug {
					d.logger.Debug("✓ SPECIFIC-BINARY MATCH",
						"entry", i,
						"result", result)
				}
				
				// Skip matches with empty results to continue searching
				if len(strings.TrimSpace(result)) == 0 {
					if d.options.Debug {
						d.logger.Debug("  Skipping empty result, continuing search...")
					}
					continue
				}

				// Additional validation before accepting result
				if !d.isValidDescription(result) {
					if d.options.Debug {
						d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
					}
					continue
				}

				return d.formatResult(result), nil
			}
		}
	}

	// Second pass: High-priority binary signatures (other patterns)
	for i, entry := range entries {
		if !d.isHighPriorityType(entry.Type) {
			continue
		}

		// Skip entries with very high offsets for debugging
		if d.options.Debug && entry.Offset > int32(len(data)) {
			continue
		}

		if match, result := d.matchEntry(data, entry, data); match {
			if d.options.Debug {
				d.logger.Debug("✓ HIGH-PRIORITY MATCH", "entry", i, "result", result)
			}

			// Skip matches with empty results to continue searching
			if len(strings.TrimSpace(result)) == 0 {
				if d.options.Debug {
					d.logger.Debug("  Skipping empty result, continuing search...")
				}
				continue
			}

			// Additional validation before accepting result
			if !d.isValidDescription(result) {
				if d.options.Debug {
					d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
				}
				continue
			}

			return d.formatResult(result), nil
		}
		
		matchAttempts++

		// Log first few attempts in debug mode
		if d.options.Debug && matchAttempts <= 10 {
			d.logger.Debug("Entry (HP)", "index", i, "type", entry.Type, "offset", entry.Offset, "desc", entry.GetDescription())
		}
	}

	// Second pass: Medium-priority patterns
	for i, entry := range entries {
		if d.isHighPriorityType(entry.Type) || d.isLowPriorityType(entry.Type) {
			continue
		}

		// Skip entries with very high offsets for debugging
		if d.options.Debug && entry.Offset > int32(len(data)) {
			continue
		}

		if match, result := d.matchEntry(data, entry, data); match {
			if d.options.Debug {
				d.logger.Debug("✓ MEDIUM-PRIORITY MATCH", "entry", i, "result", result)
			}

			// Skip matches with empty results to continue searching
			if len(strings.TrimSpace(result)) == 0 {
				if d.options.Debug {
					d.logger.Debug("  Skipping empty result, continuing search...")
				}
				continue
			}

			// Additional validation before accepting result
			if !d.isValidDescription(result) {
				if d.options.Debug {
					d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
				}
				continue
			}

			return d.formatResult(result), nil
		}
		matchAttempts++
	}

	// Third pass: Medium-priority patterns (including string patterns not in first pass)
	for i, entry := range entries {
		// Skip patterns already processed in first pass
		if entry.Offset == 0 && d.isSpecificBinarySignature(entry) {
			continue
		}
		
		if d.isHighPriorityType(entry.Type) || d.isLowPriorityType(entry.Type) {
			continue
		}
		
		// Process STRING types and other medium-priority patterns
		if entry.Type == magic.FILE_STRING || entry.Type == magic.FILE_PSTRING ||
		   entry.Type == magic.FILE_BESTRING16 || entry.Type == magic.FILE_LESTRING16 ||
		   entry.Type == magic.FILE_REGEX || entry.Type == magic.FILE_SEARCH {
			
			// Skip entries with very high offsets for debugging
			if d.options.Debug && entry.Offset > int32(len(data)) {
				continue
			}

			if match, result := d.matchEntry(data, entry, data); match {
				if d.options.Debug {
					d.logger.Debug("✓ MEDIUM-PRIORITY MATCH", "entry", i, "result", result)
				}

				// Skip matches with empty results to continue searching
				if len(strings.TrimSpace(result)) == 0 {
					if d.options.Debug {
						d.logger.Debug("  Skipping empty result, continuing search...")
					}
					continue
				}

				// Additional validation before accepting result
				if !d.isValidDescription(result) {
					if d.options.Debug {
						d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
					}
					continue
				}

				return d.formatResult(result), nil
			}
		}
	}

	// Fourth pass: Low-priority generic patterns (USE, NAME, DEFAULT)
	for i, entry := range entries {
		if !d.isLowPriorityType(entry.Type) {
			continue
		}

		// Skip entries with very high offsets for debugging
		if d.options.Debug && entry.Offset > int32(len(data)) {
			continue
		}

		if match, result := d.matchEntry(data, entry, data); match {
			if d.options.Debug {
				d.logger.Debug("✓ LOW-PRIORITY MATCH", "entry", i, "result", result)
			}

			// Skip matches with empty results to continue searching
			if len(strings.TrimSpace(result)) == 0 {
				if d.options.Debug {
					d.logger.Debug("  Skipping empty result, continuing search...")
				}
				continue
			}

			// Additional validation before accepting result
			if !d.isValidDescription(result) {
				if d.options.Debug {
					d.logger.Debug("  Skipping invalid description", "hex", hex.EncodeToString([]byte(result)))
				}
				continue
			}

			return d.formatResult(result), nil
		}
		matchAttempts++
	}

	if d.options.Debug {
		d.logger.Debug("No matches found after checking entries", "match_attempts", matchAttempts)
	}

	// Enhanced fallback detection
	return d.performFallbackDetection(data)
}

// isSpecificBinarySignature returns true for entries that represent specific binary file signatures
func (d *Detector) isSpecificBinarySignature(entry *magic.MagicEntry) bool {
	// Must be at offset 0 to be a file signature
	if entry.Offset != 0 {
		return false
	}
	
	// Must have a meaningful description to be a specific signature
	desc := entry.GetDescription()
	if len(strings.TrimSpace(desc)) == 0 {
		return false
	}
	
	// Reject single-character descriptions that are likely generic or meaningless
	if len(desc) == 1 {
		return false
	}
	
	// Reject very short descriptions unless they're known good file types
	if len(desc) <= 3 {
		// Allow known file extensions/types
		lowerDesc := strings.ToLower(desc)
		knownShort := lowerDesc == "png" || lowerDesc == "pdf" || lowerDesc == "gif" || 
		             lowerDesc == "zip" || lowerDesc == "exe" || lowerDesc == "xml" ||
		             lowerDesc == "txt" || lowerDesc == "htm" || lowerDesc == "jpg"
		if !knownShort {
			return false
		}
	}
	
	// Binary types at offset 0 with meaningful descriptions are usually specific signatures
	switch entry.Type {
	case magic.FILE_BYTE, magic.FILE_SHORT, magic.FILE_LONG:
		// Only if the expected value is not zero (to avoid generic "anything != 0" matches)
		if entry.GetValueAsUint64() != 0 {
			return true
		}
		return false
	case magic.FILE_BESHORT, magic.FILE_BELONG, magic.FILE_LESHORT, magic.FILE_LELONG:
		// Only if the expected value is not zero (to avoid generic "anything != 0" matches)
		if entry.GetValueAsUint64() != 0 {
			return true
		}
		return false
	case magic.FILE_BEQUAD, magic.FILE_LEQUAD, magic.FILE_QUAD:
		// Only if the expected value is not zero (to avoid generic "anything != 0" matches)
		if entry.GetValueAsUint64() != 0 {
			return true
		}
		return false
	case magic.FILE_STRING:
		// String types at offset 0 with binary patterns (like 7z signature)
		if entry.Offset == 0 {
			// Check if this looks like a binary signature
			valueStr := entry.GetValueAsString()
			if len(valueStr) >= 3 {
				// Look for known binary patterns or non-printable characters
				hasBinary := false
				for i := 0; i < len(valueStr) && i < 8; i++ {
					b := valueStr[i]
					if b < 32 || b > 126 {
						hasBinary = true
						break
					}
				}
				if hasBinary {
					return true
				}
				
				// Check for known archive/binary signatures
				desc := entry.GetDescription()
				if len(desc) > 0 {
					lowerDesc := strings.ToLower(desc)
					if strings.Contains(lowerDesc, "archive") ||
					   strings.Contains(lowerDesc, "zip") ||
					   strings.Contains(lowerDesc, "7z") ||
					   strings.Contains(lowerDesc, "7-zip") ||
					   strings.Contains(lowerDesc, "compressed") ||
					   strings.Contains(lowerDesc, "executable") ||
					   strings.Contains(lowerDesc, "image") {
						return true
					}
				}
			}
		}
		return false
	default:
		return false
	}
}

// isHighPriorityType returns true for types that should be checked first (specific binary signatures)
func (d *Detector) isHighPriorityType(magicType uint8) bool {
	switch magicType {
	case magic.FILE_BYTE, magic.FILE_SHORT, magic.FILE_LONG:
		return true
	case magic.FILE_BESHORT, magic.FILE_BELONG, magic.FILE_LESHORT, magic.FILE_LELONG:
		return true
	case magic.FILE_BEQUAD, magic.FILE_LEQUAD, magic.FILE_QUAD:
		return true
	case magic.FILE_FLOAT, magic.FILE_DOUBLE:
		return true
	case magic.FILE_BEFLOAT, magic.FILE_LEFLOAT:
		return true
	case magic.FILE_BEDOUBLE, magic.FILE_LEDOUBLE:
		return true
	case magic.FILE_BEDATE, magic.FILE_LEDATE:
		return true
	case magic.FILE_BELDATE, magic.FILE_LEQDATE, magic.FILE_BEQDATE:
		return true
	case magic.FILE_DATE, magic.FILE_LDATE, magic.FILE_LELDATE:
		return true
	case magic.FILE_QDATE, magic.FILE_QLDATE, magic.FILE_LEQLDATE, magic.FILE_BEQLDATE:
		return true
	case magic.FILE_MSDOSDATE, magic.FILE_LEMSDOSDATE, magic.FILE_BEMSDOSDATE:
		return true
	case magic.FILE_MSDOSTIME, magic.FILE_LEMSDOSTIME, magic.FILE_BEMSDOSTIME:
		return true
	case magic.FILE_OCTAL:
		return true
	case magic.FILE_MEDATE, magic.FILE_MELDATE, magic.FILE_MELONG:
		return true
	case magic.FILE_QWDATE, magic.FILE_LEQWDATE, magic.FILE_BEQWDATE:
		return true
	case magic.FILE_BEID3, magic.FILE_LEID3:
		return true
	case magic.FILE_BEVARINT, magic.FILE_LEVARINT:
		return true
	case magic.FILE_BESTRING16:
		return true
	case magic.FILE_GUID:
		return true
	case magic.FILE_DER:
		return true
	default:
		return false
	}
}

// isLowPriorityType returns true for types that should be checked last (generic patterns)
func (d *Detector) isLowPriorityType(magicType uint8) bool {
	switch magicType {
	case magic.FILE_USE, magic.FILE_NAME, magic.FILE_DEFAULT:
		return true
	case magic.FILE_INDIRECT: // Complex addressing, often generic
		return true
	default:
		return false
	}
}

// matchEntry attempts to match data against a single magic entry
func (d *Detector) matchEntry(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
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
