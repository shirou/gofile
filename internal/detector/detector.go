package detector

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

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

	// Default fallback
	if d.options.MIME {
		return "application/octet-stream", nil
	}
	return "data", nil
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
		case magic.FILE_SHORT:
			endPos = startPos + 2
		case magic.FILE_LONG:
			endPos = startPos + 4
		case magic.FILE_STRING:
			// For strings, read until null terminator or end of data
			endPos = len(data)
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
	case magic.FILE_LESTRING16:
		return d.matchLEString16(data, entry)
	case magic.FILE_OFFSET:
		return d.matchOffset(data, entry, fullData)
	case magic.FILE_INDIRECT:
		return d.matchIndirect(data, entry)
	case magic.FILE_USE:
		return d.matchUse(data, entry)
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
		if len(desc) == 0 {
			// Provide fallback description for common file signatures
			desc = d.getDefaultDescription(fullData, entry)
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
	
	// For FILE_STRING, extract the actual pattern from the description
	// PNG entries have the signature embedded in the description field
	if entry.Type == magic.FILE_STRING {
		desc := entry.GetDescription()
		
		// Look for binary signatures embedded in description
		if len(desc) > 4 {
			// PNG signature is at offset 1 in description field 
			// Convert binary data to bytes for comparison
			if len(entry.Desc) > 8 {
				// Extract binary pattern starting from offset 1 in description
				binaryPattern := entry.Desc[1:9] // PNG signature is 8 bytes
				
				// Check if this looks like PNG signature
				if binaryPattern[0] == 0x89 && binaryPattern[1] == 0x50 && 
				   binaryPattern[2] == 0x4E && binaryPattern[3] == 0x47 {
					pattern = string(binaryPattern[:8])
				} else if len(desc) >= 3 && desc[:3] == "PNG" {
					// For text-based PNG detection, use first 3 characters
					pattern = "PNG"
				}
			}
		}
	}
	
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

	// For binary patterns, compare as bytes
	if pattern[0] == '\x89' { // PNG binary signature
		if len(data) >= 8 && len(pattern) >= 8 {
			match := true
			for i := 0; i < 8; i++ {
				if data[i] != uint8(pattern[i]) {
					match = false
					break
				}
			}
			if match {
				if d.options.Debug {
					log.Printf("  ✓ Binary PNG signature match!")
				}
				return true, entry.GetDescription()
			}
		}
	} else {
		// Text-based string matching
		actual := string(data[:len(pattern)])
		if actual == pattern {
			if d.options.Debug {
				log.Printf("  ✓ String match!")
			}
			return true, entry.GetDescription()
		}
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
		if len(desc) == 0 {
			desc = d.getDefaultDescription(fullData, entry)
		}
		return true, desc
	}
	return false, ""
}

