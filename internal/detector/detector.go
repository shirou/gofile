package detector

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
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
	return &Detector{
		database: db,
		options:  opts,
	}
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
		log.Printf("DetectFile: Opened file %s, size: %d bytes", path, stat.Size())
	}

	return d.DetectReader(file)
}

// DetectReader detects the file type from an io.Reader
func (d *Detector) DetectReader(reader io.Reader) (string, error) {
	// Read initial bytes for analysis
	buffer := make([]byte, d.options.MaxReadSize)
	n, err := reader.Read(buffer)
	
	if d.options.Debug {
		log.Printf("DetectReader: Read attempt returned %d bytes, error: %v", n, err)
		log.Printf("DetectReader: MaxReadSize: %d, buffer len: %d", d.options.MaxReadSize, len(buffer))
		if n > 0 {
			log.Printf("DetectReader: First 16 bytes: %x", buffer[:min(16, n)])
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
			log.Printf("ERROR: DetectBytes received empty data")
		}
		return "empty", nil
	}
	
	if d.options.Debug {
		log.Printf("DetectBytes: Processing %d bytes of data", len(data))
	}

	// Get all magic entries from database
	entries := d.database.GetEntries()
	
	if d.options.Debug {
		log.Printf("=== Starting detection on %d bytes of data ===", len(data))
		log.Printf("First 32 bytes: %s", hex.EncodeToString(data[:min(32, len(data))]))
		log.Printf("Total magic entries: %d", len(entries))
	}
	
	if len(entries) == 0 {
		return "data (no magic entries loaded)", nil
	}
	
	// Try to match against each magic entry
	matchAttempts := 0
	for i, entry := range entries {
		// Skip entries with very high offsets for debugging
		if d.options.Debug && entry.Offset > int32(len(data)) {
			continue
		}
		
		if match, result := d.matchEntry(data, entry, data); match {
			if d.options.Debug {
				log.Printf("✓ MATCH at entry %d: %s", i, result)
			}
			
			// Skip matches with empty results to continue searching
			if len(strings.TrimSpace(result)) == 0 {
				if d.options.Debug {
					log.Printf("  Skipping empty result, continuing search...")
				}
				continue
			}
			
			// Additional validation before accepting result
			if !d.isValidDescription(result) {
				if d.options.Debug {
					log.Printf("  Skipping invalid description: %x", []byte(result))
				}
				continue
			}
			
			return d.formatResult(result), nil
		}
		matchAttempts++
		
		// Log first few attempts in debug mode
		if d.options.Debug && matchAttempts <= 10 {
			log.Printf("Entry %d: Type=%d, Offset=%d, Desc='%s'", 
				i, entry.Type, entry.Offset, entry.GetDescription())
		}
	}

	if d.options.Debug {
		log.Printf("No matches found after checking %d entries", matchAttempts)
	}

	// Enhanced fallback detection
	return d.performFallbackDetection(data)
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
	if entry.Vallen > 0 {
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
		case magic.FILE_BEQUAD, magic.FILE_LEQUAD:
			endPos = startPos + 8
		case magic.FILE_GUID:
			endPos = startPos + 16
		case magic.FILE_DER:
			// DER is variable length, read enough for header analysis
			endPos = startPos + 32
		case magic.FILE_FLOAT:
			endPos = startPos + 4
		case magic.FILE_DOUBLE:
			endPos = startPos + 8
		case magic.FILE_BEDATE, magic.FILE_LEDATE:
			endPos = startPos + 4
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
		log.Printf("  Matching type %d at offset %d", entry.Type, entry.Offset)
		log.Printf("  Data at offset: %s", hex.EncodeToString(data[:min(16, len(data))]))
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
	case magic.FILE_LESTRING16:
		return d.matchLEString16(data, entry)
	case magic.FILE_OFFSET:
		return d.matchOffset(data, entry, fullData)
	case magic.FILE_INDIRECT:
		return d.matchIndirect(data, entry)
	case magic.FILE_USE:
		return d.matchUse(data, entry)
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
			log.Printf("  Unimplemented type: %d", entry.Type)
		}
		return false, ""
	}
}

// matchByte matches single byte values
func (d *Detector) matchByte(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 1 {
		return false, ""
	}

	expected := entry.Value[0]
	actual := data[0]

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= byte(entry.NumMask)
		expected &= byte(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		// Skip entries with corrupted/binary descriptions
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		// If no description available, check if this is a meaningful match
		if len(desc) == 0 {
			// Check if Value field has meaningful data (not all zeros)
			hasValue := false
			for _, b := range entry.Value[:min(8, len(entry.Value))] {
				if b != 0 {
					hasValue = true
					break
				}
			}
			
			// Only use fallback if this entry seems to have a meaningful pattern
			if hasValue {
				desc = d.getDefaultDescription(fullData, entry)
			} else {
				// Skip entries with no description and no meaningful value
				return false, ""
			}
		}
		
		return true, desc
	}
	return false, ""
}

// matchShort matches 16-bit integer values
func (d *Detector) matchShort(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	var actual uint16
	if entry.Flag&magic.INDIR != 0 {
		// Handle indirect addressing later
		return false, ""
	}

	// Read 16-bit value with proper endianness
	if entry.Flag&magic.UNSIGNED != 0 {
		actual = d.readUint16(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
	} else {
		// Signed short - convert to unsigned for comparison
		signed := d.readInt16(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
		actual = uint16(signed)
	}

	// Get expected value from entry
	expected := uint16(entry.Value[0]) | uint16(entry.Value[1])<<8

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SHORT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchLong matches 32-bit integer values
func (d *Detector) matchLong(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	var actual uint32
	if entry.Flag&magic.INDIR != 0 {
		// Handle indirect addressing later
		return false, ""
	}

	// Read 32-bit value with proper endianness
	if entry.Flag&magic.UNSIGNED != 0 {
		actual = d.readUint32(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
	} else {
		// Signed long - convert to unsigned for comparison
		signed := d.readInt32(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
		actual = uint32(signed)
	}

	// Get expected value from entry (little endian)
	expected := uint32(entry.Value[0]) | 
		uint32(entry.Value[1])<<8 | 
		uint32(entry.Value[2])<<16 | 
		uint32(entry.Value[3])<<24

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SHORT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchString matches string patterns
func (d *Detector) matchString(data []byte, entry *magic.MagicEntry) (bool, string) {
	pattern := entry.GetValueAsString()
	
	if d.options.Debug {
		log.Printf("  String match: pattern='%s' (len=%d)", pattern, len(pattern))
		if len(data) >= len(pattern) {
			log.Printf("  Actual data: '%s'", string(data[:len(pattern)]))
		}
	}
	
	if len(pattern) == 0 {
		return false, ""
	}

	if len(data) < len(pattern) {
		if d.options.Debug {
			log.Printf("  Not enough data: need %d bytes, have %d", len(pattern), len(data))
		}
		return false, ""
	}

	// Simple string comparison
	actual := string(data[:len(pattern)])
	if actual == pattern {
		if d.options.Debug {
			log.Printf("  ✓ String match!")
		}
		
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping STRING entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		// If description is empty, skip this match unless it's a very specific pattern
		if len(desc) == 0 {
			// Only accept very specific patterns that might be meaningful
			if len(pattern) >= 3 && !strings.Contains(pattern, "\x00") {
				if d.options.Debug {
					log.Printf("  String match has no description, skipping")
				}
				return false, ""
			}
		}
		
		return true, desc
	}
	
	if d.options.Debug {
		log.Printf("  ✗ No match")
	}
	
	return false, ""
}






// matchLEString16 matches little-endian 16-bit character strings
func (d *Detector) matchLEString16(data []byte, entry *magic.MagicEntry) (bool, string) {
	// For now, treat as string match - proper implementation would handle 16-bit chars
	return d.matchString(data, entry)
}

// matchOffset handles offset-based matching
func (d *Detector) matchOffset(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	// Simple implementation - treat as long value for now
	return d.matchLong(data, entry, fullData)
}

// matchIndirect handles indirect references
func (d *Detector) matchIndirect(data []byte, entry *magic.MagicEntry) (bool, string) {
	// Complex feature - for now, skip indirect matches
	return false, ""
}

// matchUse handles FILE_USE type (Type 46)
func (d *Detector) matchUse(data []byte, entry *magic.MagicEntry) (bool, string) {
	// FILE_USE references another magic entry - for now treat as string match
	return d.matchString(data, entry)
}

// matchCustomType handles custom types 99, 114
func (d *Detector) matchCustomType(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	// Try to match as string first, then as byte value
	if result, desc := d.matchString(data, entry); result {
		return result, desc
	}
	return d.matchByte(data, entry, fullData)
}


// matchBELong matches 32-bit big-endian integer values  
func (d *Detector) matchBELong(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read big-endian 32-bit value from data
	actual := d.readUint32(data, false)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := uint32(entry.Value[0]) | 
		uint32(entry.Value[1])<<8 | 
		uint32(entry.Value[2])<<16 | 
		uint32(entry.Value[3])<<24

	if d.options.Debug {
		log.Printf("  BELONG: actual=0x%08x, expected=0x%08x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SHORT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchLELong matches 32-bit little-endian integer values
func (d *Detector) matchLELong(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read little-endian 32-bit value from data
	actual := d.readUint32(data, true)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := uint32(entry.Value[0]) | 
		uint32(entry.Value[1])<<8 | 
		uint32(entry.Value[2])<<16 | 
		uint32(entry.Value[3])<<24

	if d.options.Debug {
		log.Printf("  LELONG: actual=0x%08x, expected=0x%08x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		if len(desc) == 0 {
			// Provide fallback description for common file signatures
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchBEShort matches 16-bit big-endian integer values
func (d *Detector) matchBEShort(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read big-endian 16-bit value from data
	actual := d.readUint16(data, false)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := uint16(entry.Value[0]) | uint16(entry.Value[1])<<8

	if d.options.Debug {
		log.Printf("  BESHORT: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SHORT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchLEShort matches 16-bit little-endian integer values
func (d *Detector) matchLEShort(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read little-endian 16-bit value from data
	actual := d.readUint16(data, true)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := uint16(entry.Value[0]) | uint16(entry.Value[1])<<8

	if d.options.Debug {
		log.Printf("  LESHORT: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SHORT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchBEQuad matches 64-bit big-endian integer values
func (d *Detector) matchBEQuad(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read big-endian 64-bit value from data
	actual := d.readUint64(data, false)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  BEQUAD: actual=0x%016x, expected=0x%016x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := d.compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEQUAD entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchLEQuad matches 64-bit little-endian integer values
func (d *Detector) matchLEQuad(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read little-endian 64-bit value from data
	actual := d.readUint64(data, true)
	
	// Get expected value from entry (stored as little-endian in Value field)
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  LEQUAD: actual=0x%016x, expected=0x%016x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := d.compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEQUAD entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchPString matches Pascal-style length-prefixed strings
func (d *Detector) matchPString(data []byte, entry *magic.MagicEntry) (bool, string) {
	if len(data) < 1 {
		return false, ""
	}
	
	// Pascal string format: first byte is length, followed by string data
	strLen := int(data[0])
	if len(data) < 1+strLen {
		if d.options.Debug {
			log.Printf("  PSTRING: not enough data for string length %d", strLen)
		}
		return false, ""
	}
	
	// Extract the actual string data (skip length byte)
	actual := string(data[1 : 1+strLen])
	
	// Get expected pattern from magic entry
	pattern := entry.GetValueAsString()
	
	if d.options.Debug {
		log.Printf("  PSTRING match: pattern='%s' (len=%d), actual='%s' (len=%d)", 
			pattern, len(pattern), actual, len(actual))
	}
	
	if len(pattern) == 0 {
		return false, ""
	}

	// Compare strings
	if actual == pattern {
		if d.options.Debug {
			log.Printf("  ✓ PSTRING match!")
		}
		
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping PSTRING entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				log.Printf("  PSTRING match has no description, skipping")
			}
			return false, ""
		}
		
		return true, desc
	}
	
	if d.options.Debug {
		log.Printf("  ✗ PSTRING no match")
	}
	
	return false, ""
}

// matchGUID matches 16-byte Globally Unique Identifiers
func (d *Detector) matchGUID(data []byte, entry *magic.MagicEntry) (bool, string) {
	if len(data) < 16 {
		return false, ""
	}
	
	// Compare the 16-byte GUID directly with the expected value in entry
	for i := 0; i < 16; i++ {
		if i < len(entry.Value) && data[i] != entry.Value[i] {
			if d.options.Debug {
				log.Printf("  GUID mismatch at byte %d: got 0x%02x, expected 0x%02x", 
					i, data[i], entry.Value[i])
			}
			return false, ""
		}
	}
	
	if d.options.Debug {
		// Format GUID for debugging: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
		guid := fmt.Sprintf("{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
			data[0], data[1], data[2], data[3],
			data[4], data[5],
			data[6], data[7],
			data[8], data[9],
			data[10], data[11], data[12], data[13], data[14], data[15])
		log.Printf("  ✓ GUID match: %s", guid)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && !d.isValidDescription(desc) {
		if d.options.Debug {
			log.Printf("  Skipping GUID entry with corrupted description: %x", []byte(desc))
		}
		return false, ""
	}
	
	if len(desc) == 0 {
		if d.options.Debug {
			log.Printf("  GUID match has no description, skipping")
		}
		return false, ""
	}
	
	return true, desc
}

// matchDER matches ASN.1 DER (Distinguished Encoding Rules) encoded data
func (d *Detector) matchDER(data []byte, entry *magic.MagicEntry) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}
	
	// DER uses ASN.1 Basic Encoding Rules with additional constraints
	// Format: Tag | Length | Value
	// Tag byte format: [class(2bits)][constructed(1bit)][tag number(5bits)]
	
	tag := data[0]
	lengthByte := data[1]
	
	if d.options.Debug {
		log.Printf("  DER: tag=0x%02x, length_byte=0x%02x", tag, lengthByte)
	}
	
	// Get expected pattern from magic entry
	expectedPattern := entry.GetValueAsString()
	if len(expectedPattern) == 0 {
		// Try byte comparison if no string pattern
		if len(entry.Value) > 0 {
			if data[0] == entry.Value[0] {
				if len(entry.Value) > 1 && len(data) > 1 {
					if data[1] != entry.Value[1] {
						return false, ""
					}
				}
			} else {
				return false, ""
			}
		} else {
			// No pattern to match against
			return false, ""
		}
	} else {
		// String pattern matching for DER
		if len(data) < len(expectedPattern) {
			return false, ""
		}
		
		actual := string(data[:len(expectedPattern)])
		if actual != expectedPattern {
			if d.options.Debug {
				log.Printf("  DER pattern mismatch: expected '%s', got '%s'", expectedPattern, actual)
			}
			return false, ""
		}
	}
	
	// Basic DER structure validation
	var totalLength int
	if lengthByte & 0x80 == 0 {
		// Short form: length is in the lower 7 bits
		totalLength = int(lengthByte)
	} else {
		// Long form: lower 7 bits indicate number of octets for length
		lengthOctets := int(lengthByte & 0x7F)
		if lengthOctets == 0 || lengthOctets > 4 || len(data) < 2+lengthOctets {
			// Invalid or unsupported long form
			if d.options.Debug {
				log.Printf("  DER invalid long form length: %d octets", lengthOctets)
			}
			return false, ""
		}
		
		totalLength = 0
		for i := 0; i < lengthOctets; i++ {
			totalLength = (totalLength << 8) | int(data[2+i])
		}
	}
	
	if d.options.Debug {
		log.Printf("  ✓ DER match: tag=0x%02x, length=%d", tag, totalLength)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && !d.isValidDescription(desc) {
		if d.options.Debug {
			log.Printf("  Skipping DER entry with corrupted description: %x", []byte(desc))
		}
		return false, ""
	}
	
	if len(desc) == 0 {
		// Provide basic DER description based on tag
		desc = d.getDERDescription(tag, totalLength)
	}
	
	return true, desc
}

// getDERDescription provides basic descriptions for common DER tags
func (d *Detector) getDERDescription(tag byte, length int) string {
	// Common ASN.1 tags
	switch tag {
	case 0x30:
		return "ASN.1 DER, sequence"
	case 0x31:
		return "ASN.1 DER, set"
	case 0x02:
		return "ASN.1 DER, integer"
	case 0x04:
		return "ASN.1 DER, octet string"
	case 0x06:
		return "ASN.1 DER, object identifier"
	case 0x0C:
		return "ASN.1 DER, UTF8 string"
	case 0x13:
		return "ASN.1 DER, printable string"
	case 0x17:
		return "ASN.1 DER, UTC time"
	case 0x18:
		return "ASN.1 DER, generalized time"
	case 0xA0:
		return "ASN.1 DER, context-specific [0]"
	case 0xA1:
		return "ASN.1 DER, context-specific [1]"
	case 0xA3:
		return "ASN.1 DER, context-specific [3]"
	default:
		return fmt.Sprintf("ASN.1 DER, tag 0x%02x", tag)
	}
}

// matchFloat matches 32-bit floating-point values
func (d *Detector) matchFloat(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read 32-bit float value (assumes little-endian by default)
	actual := d.readFloat32(data, true)
	
	// Get expected value from entry (treat as float)
	expected := entry.GetValueAsFloat64()

	if d.options.Debug {
		log.Printf("  FLOAT: actual=%f, expected=%f", actual, expected)
	}

	match := d.compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping FLOAT entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchDouble matches 64-bit floating-point values
func (d *Detector) matchDouble(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit double value (assumes little-endian by default)
	actual := d.readFloat64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsFloat64()

	if d.options.Debug {
		log.Printf("  DOUBLE: actual=%f, expected=%f", actual, expected)
	}

	match := d.compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping DOUBLE entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchBEDate matches 32-bit big-endian Unix timestamp values
func (d *Detector) matchBEDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read big-endian 32-bit timestamp
	actual := d.readUint32(data, false)
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  BEDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEDATE entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

// matchLEDate matches 32-bit little-endian Unix timestamp values
func (d *Detector) matchLEDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read little-endian 32-bit timestamp
	actual := d.readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  LEDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := d.compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEDATE entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}


// matchRegex matches regular expression patterns  
func (d *Detector) matchRegex(data []byte, entry *magic.MagicEntry) (bool, string) {
	// For now, treat as string match - full regex support needs regexp library
	pattern := entry.GetValueAsString()
	if len(pattern) == 0 {
		return false, ""
	}
	
	// Simple substring search as fallback
	if len(data) >= len(pattern) {
		text := string(data)
		if strings.Contains(text, pattern) {
			return true, entry.GetDescription()
		}
	}
	return false, ""
}

// matchSearch searches for patterns within file content
func (d *Detector) matchSearch(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	pattern := entry.GetValueAsString()
	if len(pattern) == 0 {
		return false, ""
	}
	
	// Search entire file content
	text := string(fullData)
	if strings.Contains(text, pattern) {
		return true, entry.GetDescription()
	}
	return false, ""
}

// matchName matches based on filename patterns
func (d *Detector) matchName(data []byte, entry *magic.MagicEntry) (bool, string) {
	// This requires filename context which we don't have in this method
	// Skip for now - would need to be implemented at higher level
	return false, ""
}

// matchDefault provides default behavior for unspecified types
func (d *Detector) matchDefault(data []byte, entry *magic.MagicEntry) (bool, string) {
	// Default type often means "continue to next entry"
	return false, ""
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
