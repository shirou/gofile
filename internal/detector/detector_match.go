package detector

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
		actual = readUint16(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
	} else {
		// Signed short - convert to unsigned for comparison
		signed := readInt16(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
		actual = uint16(signed)
	}

	// Get expected value from entry
	expected := uint16(entry.Value[0]) | uint16(entry.Value[1])<<8

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
		actual = readUint32(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
	} else {
		// Signed long - convert to unsigned for comparison
		signed := readInt32(data, entry.Flag&magic.LITTLE_ENDIAN != 0)
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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

// matchIndirect handles complex indirect addressing (Type 41)
func (d *Detector) matchIndirect(data []byte, entry *magic.MagicEntry) (bool, string) {
	if d.options.Debug {
		log.Printf("  INDIRECT: offset=%d, in_offset=%d, flags=0x%x", 
			entry.Offset, entry.InOffset, entry.Flag)
	}
	
	// Basic indirect addressing implementation
	// Full implementation requires complex flag interpretation
	
	// Check if we have enough data for the base offset
	if entry.Offset < 0 || int(entry.Offset) >= len(data) {
		if d.options.Debug {
			log.Printf("  INDIRECT: base offset %d out of range", entry.Offset)
		}
		return false, ""
	}
	
	baseOffset := int(entry.Offset)
	
	// Read indirect offset based on type (simplified)
	var indirectOffset int
	if baseOffset+4 <= len(data) {
		// Read 32-bit offset (assuming little-endian for now)
		indirectOffset = int(data[baseOffset]) | 
			int(data[baseOffset+1])<<8 | 
			int(data[baseOffset+2])<<16 | 
			int(data[baseOffset+3])<<24
		
		// Add the InOffset value
		indirectOffset += int(entry.InOffset)
		
		if d.options.Debug {
			log.Printf("  INDIRECT: computed offset=%d", indirectOffset)
		}
		
		// Check if the computed offset is valid
		if indirectOffset >= 0 && indirectOffset < len(data) {
			// For now, just check if we can read data at the computed offset
			// A full implementation would recursively evaluate the pattern
			desc := entry.GetDescription()
			
			if len(desc) > 0 && d.isValidDescription(desc) {
				if d.options.Debug {
					log.Printf("  ✓ INDIRECT: valid offset, using description: %s", desc)
				}
				return true, desc
			}
		}
	}
	
	if d.options.Debug {
		log.Printf("  INDIRECT: complex addressing not fully supported")
	}
	return false, ""
}

// matchUse handles FILE_USE type (Type 46) - references another named magic pattern
func (d *Detector) matchUse(data []byte, entry *magic.MagicEntry) (bool, string) {
	// FILE_USE references another magic entry by name
	// The pattern name is stored in the Value field as a string
	referenceName := entry.GetValueAsString()
	
	if d.options.Debug {
		log.Printf("  FILE_USE: looking for reference '%s'", referenceName)
	}
	
	if len(referenceName) == 0 {
		if d.options.Debug {
			log.Printf("  FILE_USE: no reference name specified")
		}
		return false, ""
	}
	
	// Look for the referenced magic entry in the database
	// For now, we'll implement a simplified version that handles common cases
	// A full implementation would require a name-to-entry mapping system
	
	// Check if this is a simple pattern that we can handle directly
	desc := entry.GetDescription()
	if len(desc) > 0 && d.isValidDescription(desc) {
		// If we have a valid description, use it directly
		// This handles cases where FILE_USE entries have standalone descriptions
		if d.options.Debug {
			log.Printf("  ✓ FILE_USE: using direct description: %s", desc)
		}
		return true, desc
	}
	
	// For complex FILE_USE patterns, we would need to:
	// 1. Build a name-to-entry mapping during database loading
	// 2. Recursively evaluate the referenced entry
	// 3. Handle circular references and depth limits
	
	if d.options.Debug {
		log.Printf("  FILE_USE: complex reference '%s' not yet supported", referenceName)
	}
	
	return false, ""
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
	actual := readUint32(data, false)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
	actual := readUint32(data, true)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
	actual := readUint16(data, false)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
	actual := readUint16(data, true)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
	actual := readUint64(data, false)
	
	// Get expected value from entry - read as big-endian since this is FILE_BEQUAD
	expected := readUint64(entry.Value[:8], false)

	if d.options.Debug {
		log.Printf("  BEQUAD: actual=0x%016x, expected=0x%016x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
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
	actual := readUint64(data, true)
	
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

	match := compareValues(actual, expected, entry.Reln)
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
	actual := readFloat32(data, true)
	
	// Get expected value from entry (treat as float)
	expected := entry.GetValueAsFloat64()

	if d.options.Debug {
		log.Printf("  FLOAT: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
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
	actual := readFloat64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsFloat64()

	if d.options.Debug {
		log.Printf("  DOUBLE: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
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
	actual := readUint32(data, false)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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
	actual := readUint32(data, true)
	
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

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
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

// matchQuad matches 64-bit integer values (native endianness)
func (d *Detector) matchQuad(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit value with native endianness (little-endian on most platforms)
	actual := readUint64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  QUAD: actual=0x%016x, expected=0x%016x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping QUAD entry with corrupted description: %x", []byte(desc))
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

// matchBEFloat matches 32-bit big-endian floating-point values
func (d *Detector) matchBEFloat(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read 32-bit float value (big-endian)
	actual := readFloat32(data, false)
	
	// Get expected value from entry - read as big-endian float32
	expected := float64(readFloat32(entry.Value[:4], false))

	if d.options.Debug {
		log.Printf("  BEFLOAT: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEFLOAT entry with corrupted description: %x", []byte(desc))
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

// matchLEFloat matches 32-bit little-endian floating-point values
func (d *Detector) matchLEFloat(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read 32-bit float value (little-endian)
	actual := readFloat32(data, true)
	
	// Get expected value from entry - read as little-endian float32
	expected := float64(readFloat32(entry.Value[:4], true))

	if d.options.Debug {
		log.Printf("  LEFLOAT: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEFLOAT entry with corrupted description: %x", []byte(desc))
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

// matchBEDouble matches 64-bit big-endian floating-point values
func (d *Detector) matchBEDouble(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit double value (big-endian)
	actual := readFloat64(data, false)
	
	// Get expected value from entry - read as big-endian double
	expected := readFloat64(entry.Value[:8], false)

	if d.options.Debug {
		log.Printf("  BEDOUBLE: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEDOUBLE entry with corrupted description: %x", []byte(desc))
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

// matchLEDouble matches 64-bit little-endian floating-point values
func (d *Detector) matchLEDouble(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit double value (little-endian)
	actual := readFloat64(data, true)
	
	// Get expected value from entry - read as little-endian double
	expected := readFloat64(entry.Value[:8], true)

	if d.options.Debug {
		log.Printf("  LEDOUBLE: actual=%f, expected=%f", actual, expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEDOUBLE entry with corrupted description: %x", []byte(desc))
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

// matchRegex matches regular expression patterns with full regex support
func (d *Detector) matchRegex(data []byte, entry *magic.MagicEntry) (bool, string) {
	pattern := entry.GetValueAsString()
	if len(pattern) == 0 {
		return false, ""
	}
	
	if d.options.Debug {
		log.Printf("  REGEX: pattern='%s', data_len=%d", pattern, len(data))
	}
	
	// Compile the regular expression
	regex, err := regexp.Compile(pattern)
	if err != nil {
		if d.options.Debug {
			log.Printf("  REGEX: invalid pattern '%s': %v", pattern, err)
		}
		// Fallback to simple string matching for invalid patterns
		text := string(data)
		if strings.Contains(text, pattern) {
			if d.options.Debug {
				log.Printf("  ✓ REGEX: fallback string match")
			}
			desc := entry.GetDescription()
			if len(desc) > 0 && d.isValidDescription(desc) {
				return true, desc
			}
		}
		return false, ""
	}
	
	// Convert data to string for regex matching
	text := string(data)
	
	// Apply the regex pattern
	if regex.MatchString(text) {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping REGEX entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				log.Printf("  REGEX match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			log.Printf("  ✓ REGEX: pattern '%s' matched", pattern)
		}
		return true, desc
	}
	
	if d.options.Debug {
		log.Printf("  ✗ REGEX: pattern '%s' no match", pattern)
	}
	
	return false, ""
}

// matchSearch searches for patterns within file content with range support
func (d *Detector) matchSearch(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	pattern := entry.GetValueAsString()
	if len(pattern) == 0 {
		return false, ""
	}
	
	if d.options.Debug {
		log.Printf("  SEARCH: pattern='%s', offset=%d", pattern, entry.Offset)
	}
	
	// Determine search range
	searchData := fullData
	startOffset := int(entry.Offset)
	
	// Use NumMask as search range if specified (common FILE_SEARCH usage)
	var searchRange int
	if entry.NumMask > 0 && entry.NumMask < uint64(len(fullData)) {
		searchRange = int(entry.NumMask)
		if d.options.Debug {
			log.Printf("  SEARCH: using range mask %d", searchRange)
		}
	} else {
		searchRange = len(fullData)
	}
	
	// Adjust search window
	if startOffset >= 0 && startOffset < len(fullData) {
		endOffset := startOffset + searchRange
		if endOffset > len(fullData) {
			endOffset = len(fullData)
		}
		searchData = fullData[startOffset:endOffset]
		if d.options.Debug {
			log.Printf("  SEARCH: window [%d:%d], size=%d", startOffset, endOffset, len(searchData))
		}
	}
	
	// Perform search
	found := false
	if len(pattern) <= len(searchData) {
		// Search for pattern in the data window
		text := string(searchData)
		if strings.Contains(text, pattern) {
			found = true
		} else {
			// Also try binary search for non-text patterns
			for i := 0; i <= len(searchData)-len(pattern); i++ {
				if string(searchData[i:i+len(pattern)]) == pattern {
					found = true
					break
				}
			}
		}
	}
	
	if found {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping SEARCH entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				log.Printf("  SEARCH match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			log.Printf("  ✓ SEARCH: found pattern '%s'", pattern)
		}
		return true, desc
	}
	
	return false, ""
}

// matchName matches based on filename patterns
func (d *Detector) matchName(data []byte, entry *magic.MagicEntry) (bool, string) {
	// FILE_NAME requires filename context which we don't have in this method
	// However, we can still use the description if it's meaningful
	
	pattern := entry.GetValueAsString()
	if d.options.Debug {
		log.Printf("  NAME: pattern='%s' (filename context not available)", pattern)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && d.isValidDescription(desc) {
		// For FILE_NAME entries with valid descriptions, we can still return them
		// This is useful for entries that provide format info regardless of filename
		if d.options.Debug {
			log.Printf("  ✓ NAME: using description (no filename match needed): %s", desc)
		}
		return true, desc
	}
	
	// Skip FILE_NAME entries without filename context or valid descriptions
	if d.options.Debug {
		log.Printf("  NAME: skipping (requires filename context)")
	}
	return false, ""
}

// matchDefault provides default behavior for unspecified types
func (d *Detector) matchDefault(data []byte, entry *magic.MagicEntry) (bool, string) {
	// Default type often means "continue to next entry"
	return false, ""
}

// matchBELDate matches 32-bit big-endian long date values  
func (d *Detector) matchBELDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read big-endian 32-bit timestamp
	actual := readUint32(data, false)
	
	// Get expected value from entry
	expected := uint32(readUint32(entry.Value[:4], false))

	if d.options.Debug {
		log.Printf("  BELDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BELDATE entry with corrupted description: %x", []byte(desc))
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

// matchLEQDate matches 64-bit little-endian date values
func (d *Detector) matchLEQDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read little-endian 64-bit timestamp
	actual := readUint64(data, true)
	
	// Get expected value from entry - read as little-endian
	expected := readUint64(entry.Value[:8], true)

	if d.options.Debug {
		log.Printf("  LEQDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEQDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEQDate matches 64-bit big-endian date values
func (d *Detector) matchBEQDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read big-endian 64-bit timestamp
	actual := readUint64(data, false)
	
	// Get expected value from entry - read as big-endian
	expected := readUint64(entry.Value[:8], false)

	if d.options.Debug {
		log.Printf("  BEQDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEQDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEString16 matches big-endian 16-bit Unicode strings
func (d *Detector) matchBEString16(data []byte, entry *magic.MagicEntry) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Get expected pattern from entry
	pattern := entry.GetValueAsString()
	if len(pattern) == 0 {
		return false, ""
	}
	
	if d.options.Debug {
		log.Printf("  BESTRING16: pattern='%s', data_len=%d", pattern, len(data))
	}

	// Convert UTF-16 big-endian data to string for comparison
	// For simplicity, handle basic ASCII characters in UTF-16BE format
	var text strings.Builder
	for i := 0; i < len(data)-1; i += 2 {
		// Read 16-bit character in big-endian format
		char := uint16(data[i])<<8 | uint16(data[i+1])
		
		// Stop at null terminator
		if char == 0 {
			break
		}
		
		// Handle basic ASCII range (0-127)
		if char <= 127 {
			text.WriteByte(byte(char))
		} else {
			// For non-ASCII, use placeholder or skip
			text.WriteByte('?')
		}
		
		// Limit string length for performance
		if text.Len() > 256 {
			break
		}
	}
	
	textStr := text.String()
	
	// Check if pattern matches the converted string
	if strings.Contains(textStr, pattern) {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BESTRING16 entry with corrupted description: %x", []byte(desc))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				log.Printf("  BESTRING16 match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			log.Printf("  ✓ BESTRING16: pattern '%s' matched in '%s'", pattern, textStr)
		}
		return true, desc
	}
	
	if d.options.Debug {
		log.Printf("  ✗ BESTRING16: pattern '%s' no match in '%s'", pattern, textStr)
	}
	
	return false, ""
}

// matchClear clears flags or state in magic processing
func (d *Detector) matchClear(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if d.options.Debug {
		log.Printf("  CLEAR: clearing state flags")
	}
	
	// FILE_CLEAR is used to clear flags or reset state in complex magic sequences
	// For basic implementation, we just continue processing by returning false
	// In a more advanced implementation, this might clear specific state variables
	// or flags that affect subsequent magic entry processing
	
	return false, ""
}

// matchDate matches 32-bit Unix timestamp values (native endianness)
func (d *Detector) matchDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read 32-bit timestamp with native endianness (little-endian on most platforms)
	actual := readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  DATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping DATE entry with corrupted description: %x", []byte(desc))
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

// matchLDate matches long date values (native endianness)
func (d *Detector) matchLDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read 32-bit long date with native endianness
	actual := readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  LDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LDATE entry with corrupted description: %x", []byte(desc))
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

// matchLELDate matches little-endian long date values
func (d *Detector) matchLELDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read little-endian 32-bit long date
	actual := readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(readUint32(entry.Value[:4], true))

	if d.options.Debug {
		log.Printf("  LELDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LELDATE entry with corrupted description: %x", []byte(desc))
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

// matchQDate matches 64-bit quad date values (native endianness)
func (d *Detector) matchQDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit quad date with native endianness
	actual := readUint64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  QDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping QDATE entry with corrupted description: %x", []byte(desc))
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

// matchQLDate matches 64-bit quad long date values (native endianness)
func (d *Detector) matchQLDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit quad long date with native endianness
	actual := readUint64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  QLDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping QLDATE entry with corrupted description: %x", []byte(desc))
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

// matchLEQLDate matches little-endian 64-bit quad long date values
func (d *Detector) matchLEQLDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read little-endian 64-bit quad long date
	actual := readUint64(data, true)
	
	// Get expected value from entry - read as little-endian
	expected := readUint64(entry.Value[:8], true)

	if d.options.Debug {
		log.Printf("  LEQLDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEQLDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEQLDate matches big-endian 64-bit quad long date values
func (d *Detector) matchBEQLDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read big-endian 64-bit quad long date
	actual := readUint64(data, false)
	
	// Get expected value from entry - read as big-endian
	expected := readUint64(entry.Value[:8], false)

	if d.options.Debug {
		log.Printf("  BEQLDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEQLDATE entry with corrupted description: %x", []byte(desc))
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

// matchMSDOSDate matches MS-DOS date format (16-bit)
func (d *Detector) matchMSDOSDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// MS-DOS date format: bits 15-9 = year-1980, bits 8-5 = month, bits 4-0 = day
	actual := readUint16(data, true) // Little-endian by default for MS-DOS
	
	// Get expected value from entry
	expected := uint16(entry.GetValueAsUint64())

	if d.options.Debug {
		// Decode MS-DOS date for debugging
		year := 1980 + ((actual >> 9) & 0x7F)
		month := (actual >> 5) & 0x0F
		day := actual & 0x1F
		log.Printf("  MSDOSDATE: actual=0x%04x (%04d-%02d-%02d), expected=0x%04x", actual, year, month, day, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping MSDOSDATE entry with corrupted description: %x", []byte(desc))
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

// matchLEMSDOSDate matches little-endian MS-DOS date format
func (d *Detector) matchLEMSDOSDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read little-endian MS-DOS date
	actual := readUint16(data, true)
	
	// Get expected value from entry
	expected := uint16(readUint16(entry.Value[:2], true))

	if d.options.Debug {
		log.Printf("  LEMSDOSDATE: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEMSDOSDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEMSDOSDate matches big-endian MS-DOS date format
func (d *Detector) matchBEMSDOSDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read big-endian MS-DOS date
	actual := readUint16(data, false)
	
	// Get expected value from entry
	expected := uint16(readUint16(entry.Value[:2], false))

	if d.options.Debug {
		log.Printf("  BEMSDOSDATE: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEMSDOSDATE entry with corrupted description: %x", []byte(desc))
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

// matchMSDOSTime matches MS-DOS time format (16-bit)
func (d *Detector) matchMSDOSTime(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// MS-DOS time format: bits 15-11 = hour, bits 10-5 = minute, bits 4-0 = second/2
	actual := readUint16(data, true) // Little-endian by default for MS-DOS
	
	// Get expected value from entry
	expected := uint16(entry.GetValueAsUint64())

	if d.options.Debug {
		// Decode MS-DOS time for debugging
		hour := (actual >> 11) & 0x1F
		minute := (actual >> 5) & 0x3F
		second := (actual & 0x1F) * 2
		log.Printf("  MSDOSTIME: actual=0x%04x (%02d:%02d:%02d), expected=0x%04x", actual, hour, minute, second, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping MSDOSTIME entry with corrupted description: %x", []byte(desc))
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

// matchLEMSDOSTime matches little-endian MS-DOS time format
func (d *Detector) matchLEMSDOSTime(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read little-endian MS-DOS time
	actual := readUint16(data, true)
	
	// Get expected value from entry
	expected := uint16(readUint16(entry.Value[:2], true))

	if d.options.Debug {
		log.Printf("  LEMSDOSTIME: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEMSDOSTIME entry with corrupted description: %x", []byte(desc))
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

// matchBEMSDOSTime matches big-endian MS-DOS time format
func (d *Detector) matchBEMSDOSTime(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Read big-endian MS-DOS time
	actual := readUint16(data, false)
	
	// Get expected value from entry
	expected := uint16(readUint16(entry.Value[:2], false))

	if d.options.Debug {
		log.Printf("  BEMSDOSTIME: actual=0x%04x, expected=0x%04x", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint16(entry.NumMask)
		expected &= uint16(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEMSDOSTIME entry with corrupted description: %x", []byte(desc))
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

// matchOctal matches octal values
func (d *Detector) matchOctal(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Read octal value as 32-bit integer
	actual := readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  OCTAL: actual=0%o, expected=0%o", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping OCTAL entry with corrupted description: %x", []byte(desc))
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

// matchMEDate matches middle-endian 32-bit date values
func (d *Detector) matchMEDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Middle-endian: byte order 2,3,0,1 (pdp-11 style)
	actual := uint32(data[2]) | uint32(data[3])<<8 | uint32(data[0])<<16 | uint32(data[1])<<24
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  MEDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping MEDATE entry with corrupted description: %x", []byte(desc))
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

// matchMELDate matches middle-endian long date values
func (d *Detector) matchMELDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Middle-endian long date
	actual := uint32(data[2]) | uint32(data[3])<<8 | uint32(data[0])<<16 | uint32(data[1])<<24
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  MELDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping MELDATE entry with corrupted description: %x", []byte(desc))
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

// matchMELong matches middle-endian 32-bit long values
func (d *Detector) matchMELong(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Middle-endian: byte order 2,3,0,1
	actual := uint32(data[2]) | uint32(data[3])<<8 | uint32(data[0])<<16 | uint32(data[1])<<24
	
	// Get expected value from entry
	expected := uint32(entry.GetValueAsUint64())

	if d.options.Debug {
		log.Printf("  MELONG: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping MELONG entry with corrupted description: %x", []byte(desc))
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

// matchQWDate matches 64-bit quad word date values (native endianness)
func (d *Detector) matchQWDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read 64-bit quad word date with native endianness
	actual := readUint64(data, true)
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  QWDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping QWDATE entry with corrupted description: %x", []byte(desc))
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

// matchLEQWDate matches little-endian 64-bit quad word date values
func (d *Detector) matchLEQWDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read little-endian 64-bit quad word date
	actual := readUint64(data, true)
	
	// Get expected value from entry - read as little-endian
	expected := readUint64(entry.Value[:8], true)

	if d.options.Debug {
		log.Printf("  LEQWDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEQWDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEQWDate matches big-endian 64-bit quad word date values
func (d *Detector) matchBEQWDate(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 8 {
		return false, ""
	}

	// Read big-endian 64-bit quad word date
	actual := readUint64(data, false)
	
	// Get expected value from entry - read as big-endian
	expected := readUint64(entry.Value[:8], false)

	if d.options.Debug {
		log.Printf("  BEQWDATE: actual=%d, expected=%d", actual, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEQWDATE entry with corrupted description: %x", []byte(desc))
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

// matchBEID3 matches big-endian ID3 tag values
func (d *Detector) matchBEID3(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// ID3 tags are typically 4-byte identifiers in big-endian format
	actual := readUint32(data, false)
	
	// Get expected value from entry
	expected := uint32(readUint32(entry.Value[:4], false))

	if d.options.Debug {
		// Convert to string for debugging
		idStr := string([]byte{byte(actual >> 24), byte(actual >> 16), byte(actual >> 8), byte(actual)})
		log.Printf("  BEID3: actual=0x%08x (%s), expected=0x%08x", actual, idStr, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEID3 entry with corrupted description: %x", []byte(desc))
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

// matchLEID3 matches little-endian ID3 tag values
func (d *Detector) matchLEID3(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// ID3 tags in little-endian format
	actual := readUint32(data, true)
	
	// Get expected value from entry
	expected := uint32(readUint32(entry.Value[:4], true))

	if d.options.Debug {
		// Convert to string for debugging (reverse byte order for little-endian)
		idStr := string([]byte{byte(actual), byte(actual >> 8), byte(actual >> 16), byte(actual >> 24)})
		log.Printf("  LEID3: actual=0x%08x (%s), expected=0x%08x", actual, idStr, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= uint32(entry.NumMask)
		expected &= uint32(entry.NumMask)
	}

	match := compareValues(uint64(actual), uint64(expected), entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEID3 entry with corrupted description: %x", []byte(desc))
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

// matchBEVarInt matches big-endian variable-length integer values
func (d *Detector) matchBEVarInt(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 1 {
		return false, ""
	}

	// Variable-length integer decoding (LEB128-style, big-endian)
	var actual uint64
	bytesRead := 0
	
	for i, b := range data {
		if i >= 8 { // Limit to 8 bytes max
			break
		}
		
		// In big-endian varint, MSB indicates continuation
		actual = (actual << 7) | uint64(b&0x7F)
		bytesRead++
		
		// If MSB is 0, this is the last byte
		if b&0x80 == 0 {
			break
		}
		
		// Prevent infinite loop with malformed data
		if bytesRead >= len(data) {
			break
		}
	}
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  BEVARINT: actual=%d (%d bytes), expected=%d", actual, bytesRead, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping BEVARINT entry with corrupted description: %x", []byte(desc))
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

// matchLEVarInt matches little-endian variable-length integer values
func (d *Detector) matchLEVarInt(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if len(data) < 1 {
		return false, ""
	}

	// Variable-length integer decoding (LEB128-style, little-endian)
	var actual uint64
	bytesRead := 0
	
	for i, b := range data {
		if i >= 8 { // Limit to 8 bytes max
			break
		}
		
		// In little-endian varint, LSBs come first
		actual |= uint64(b&0x7F) << (i * 7)
		bytesRead++
		
		// If MSB is 0, this is the last byte
		if b&0x80 == 0 {
			break
		}
		
		// Prevent infinite loop with malformed data
		if bytesRead >= len(data) {
			break
		}
	}
	
	// Get expected value from entry
	expected := entry.GetValueAsUint64()

	if d.options.Debug {
		log.Printf("  LEVARINT: actual=%d (%d bytes), expected=%d", actual, bytesRead, expected)
	}

	// Apply mask if specified
	if entry.NumMask != 0 {
		actual &= entry.NumMask
		expected &= entry.NumMask
	}

	match := compareValues(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				log.Printf("  Skipping LEVARINT entry with corrupted description: %x", []byte(desc))
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