package detector

import (
	"fmt"
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
				d.logger.Debug("Skipping entry with corrupted description", 
					"description_hex", fmt.Sprintf("%x", []byte(desc)),
					"match_type", "byte")
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
				d.logger.Debug("Skipping SHORT entry with corrupted description", 
					"description_hex", fmt.Sprintf("%x", []byte(desc)),
					"match_type", "short")
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "SHORT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("String match attempt", "pattern", pattern, "pattern_length", len(pattern))
		if len(data) >= len(pattern) {
			d.logger.Debug("Actual data examined", "data", string(data[:len(pattern)]))
		}
	}
	
	if len(pattern) == 0 {
		return false, ""
	}

	if len(data) < len(pattern) {
		if d.options.Debug {
			d.logger.Debug("Insufficient data for pattern match", "bytes_needed", len(pattern), "bytes_available", len(data))
		}
		return false, ""
	}

	// Simple string comparison
	actual := string(data[:len(pattern)])
	if actual == pattern {
		if d.options.Debug {
			d.logger.Debug("String match successful")
		}
		
		desc := entry.GetDescription()
		
		// For STRING entries, if description looks like binary data, use MimeType instead
		if len(desc) > 0 && !d.isValidDescription(desc) {
			// Try MimeType field as description
			mimeDesc := entry.GetMimeType()
			if len(mimeDesc) > 0 && d.isValidDescription(mimeDesc) {
				desc = mimeDesc
				if d.options.Debug {
					d.logger.Debug("Using MimeType as description", "description", desc)
				}
			} else {
				if d.options.Debug {
					d.logger.Debug("Skipping entry with corrupted description", "entry_type", "STRING", "description_hex", fmt.Sprintf("%x", []byte(desc)))
				}
				return false, ""
			}
		}
		
		// If description is empty, skip this match unless it's a very specific pattern
		if len(desc) == 0 {
			// Check if this is a known binary signature that should be accepted
			// even with empty description (like 7z signature)
			isKnownBinarySignature := false
			
			// Check for 7z signature: 37 7a bc af 27 1c
			if len(pattern) >= 6 {
				if pattern[0] == 0x37 && pattern[1] == 0x7a && pattern[2] == 0xbc && 
				   pattern[3] == 0xaf && pattern[4] == 0x27 && pattern[5] == 0x1c {
					isKnownBinarySignature = true
					// Return a meaningful description for 7z with version info
					if len(data) >= 8 {
						// 7z version is typically at byte 7 (0-indexed)
						version := data[7]
						return true, fmt.Sprintf("7-zip archive data, version 0.%d", version)
					}
					return true, "7-zip archive data"
				}
			}
			
			// Add other known binary signatures as needed
			// ZIP signature: 50 4b 03 04 or 50 4b 05 06 or 50 4b 07 08
			if len(pattern) >= 4 {
				if pattern[0] == 0x50 && pattern[1] == 0x4b && 
				   (pattern[2] == 0x03 || pattern[2] == 0x05 || pattern[2] == 0x07) {
					isKnownBinarySignature = true
					// Use the sophisticated ZIP parser for detailed information
					zipDesc := d.parseZIPDetails(data)
					return true, zipDesc
				}
			}
			
			// For other patterns with empty descriptions, skip
			if !isKnownBinarySignature && len(pattern) >= 3 && !strings.Contains(pattern, "\x00") {
				if d.options.Debug {
					d.logger.Debug("String match has no description, skipping")
				}
				return false, ""
			}
		}
		
		return true, desc
	}
	
	if d.options.Debug {
		d.logger.Debug("No match found")
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
	return d.matchIndirectWithDepth(data, entry, data, 0)
}

// matchIndirectWithFullData handles indirect addressing with full data context
func (d *Detector) matchIndirectWithFullData(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	return d.matchIndirectWithDepth(data, entry, fullData, 0)
}

// matchIndirectWithDepth handles FILE_INDIRECT with recursion depth tracking
func (d *Detector) matchIndirectWithDepth(data []byte, entry *magic.MagicEntry, fullData []byte, depth int) (bool, string) {
	// Prevent infinite recursion
	const maxIndirectDepth = 10
	if depth > maxIndirectDepth {
		if d.options.Debug {
			d.logger.Debug("INDIRECT: maximum recursion depth exceeded", "depth", depth)
		}
		return false, ""
	}

	if d.options.Debug {
		d.logger.Debug("INDIRECT operation", 
			"offset", entry.Offset, 
			"in_offset", entry.InOffset, 
			"in_type", entry.InType,
			"flags", fmt.Sprintf("0x%x", entry.Flag),
			"depth", depth)
	}
	
	// Calculate the base offset considering relative positioning
	baseOffset := d.calculateBaseOffset(entry, len(data))
	if baseOffset < 0 || baseOffset >= len(data) {
		if d.options.Debug {
			d.logger.Debug("INDIRECT: base offset out of range", "offset", baseOffset)
		}
		return false, ""
	}

	// Read the pointer value based on the indirect type
	pointerValue, bytesRead, err := d.readIndirectPointer(data[baseOffset:], entry)
	if err != nil {
		if d.options.Debug {
			d.logger.Debug("INDIRECT: failed to read pointer", "error", err)
		}
		return false, ""
	}

	// Calculate the final target offset
	targetOffset := d.calculateTargetOffset(pointerValue, entry, baseOffset, len(data))
	if targetOffset < 0 || targetOffset >= len(data) {
		if d.options.Debug {
			d.logger.Debug("INDIRECT: target offset out of range", 
				"target_offset", targetOffset,
				"pointer_value", pointerValue,
				"in_offset", entry.InOffset)
		}
		return false, ""
	}

	if d.options.Debug {
		d.logger.Debug("INDIRECT: computed addresses",
			"base_offset", baseOffset,
			"pointer_value", fmt.Sprintf("0x%x", pointerValue),
			"target_offset", targetOffset,
			"bytes_read", bytesRead)
	}

	// Now we need to evaluate the pattern at the target offset
	// Create a new entry representing the evaluation at the indirect location
	indirectEntry := d.createIndirectEvaluationEntry(entry, targetOffset)
	
	// Recursively evaluate the pattern at the target location
	return d.matchIndirectPattern(fullData, indirectEntry, targetOffset, depth+1)
}

// calculateBaseOffset calculates the base offset considering relative positioning flags
func (d *Detector) calculateBaseOffset(entry *magic.MagicEntry, dataLen int) int {
	baseOffset := int(entry.Offset)
	
	// Handle relative positioning flags
	if entry.Flag&magic.OFFNEGATIVE != 0 {
		// Relative to end of file
		baseOffset = dataLen + baseOffset
	} else if entry.Flag&magic.OFFPOSITIVE != 0 {
		// Relative to beginning of file (explicit)
		// baseOffset is already correct
	}
	
	return baseOffset
}

// readIndirectPointer reads the pointer value from data based on indirect type
func (d *Detector) readIndirectPointer(data []byte, entry *magic.MagicEntry) (int64, int, error) {
	var pointerValue int64
	var bytesRead int
	
	// Determine endianness - default to little endian unless specified otherwise
	isLittleEndian := true // Default to little endian
	if entry.Flag&magic.LITTLE_ENDIAN != 0 {
		isLittleEndian = true
	}
	
	// Read pointer based on InType (or fall back to assuming 32-bit)
	switch entry.InType {
	case magic.FILE_BYTE:
		if len(data) < 1 {
			return 0, 0, fmt.Errorf("insufficient data for byte pointer")
		}
		pointerValue = int64(data[0])
		bytesRead = 1
		
	case magic.FILE_SHORT, magic.FILE_BESHORT, magic.FILE_LESHORT:
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("insufficient data for short pointer")
		}
		if isLittleEndian || entry.InType == magic.FILE_LESHORT {
			pointerValue = int64(readUint16(data, true))
		} else {
			pointerValue = int64(readUint16(data, false))
		}
		bytesRead = 2
		
	case magic.FILE_LONG, magic.FILE_BELONG, magic.FILE_LELONG:
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("insufficient data for long pointer")
		}
		if isLittleEndian || entry.InType == magic.FILE_LELONG {
			pointerValue = int64(readUint32(data, true))
		} else {
			pointerValue = int64(readUint32(data, false))
		}
		bytesRead = 4
		
	case magic.FILE_QUAD, magic.FILE_BEQUAD, magic.FILE_LEQUAD:
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("insufficient data for quad pointer")
		}
		if isLittleEndian || entry.InType == magic.FILE_LEQUAD {
			pointerValue = int64(readUint64(data, true))
		} else {
			pointerValue = int64(readUint64(data, false))
		}
		bytesRead = 8
		
	default:
		// Default to 32-bit pointer for unknown types
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("insufficient data for default pointer")
		}
		if isLittleEndian {
			pointerValue = int64(readUint32(data, true))
		} else {
			pointerValue = int64(readUint32(data, false))
		}
		bytesRead = 4
	}
	
	return pointerValue, bytesRead, nil
}

// calculateTargetOffset calculates the final target offset from the pointer value
func (d *Detector) calculateTargetOffset(pointerValue int64, entry *magic.MagicEntry, baseOffset, dataLen int) int {
	targetOffset := int(pointerValue)
	
	// Apply InOffset (additional offset)
	if entry.Flag&magic.OFFADD != 0 {
		// Add InOffset to the pointer value
		targetOffset += int(entry.InOffset)
	} else if entry.Flag&magic.INDIROFFADD != 0 {
		// More complex offset addition - add both base and InOffset
		targetOffset = baseOffset + int(pointerValue) + int(entry.InOffset)
	} else {
		// Simple case: just add InOffset
		targetOffset += int(entry.InOffset)
	}
	
	// Handle relative positioning of target
	if entry.Flag&magic.OFFNEGATIVE != 0 {
		// Target relative to end of file
		targetOffset = dataLen + targetOffset
	}
	
	return targetOffset
}

// createIndirectEvaluationEntry creates a new entry for evaluating at the indirect location
func (d *Detector) createIndirectEvaluationEntry(original *magic.MagicEntry, targetOffset int) *magic.MagicEntry {
	// Create a copy of the original entry but with the new offset
	entry := &magic.MagicEntry{
		Flag:      original.Flag &^ magic.INDIR, // Remove INDIR flag
		ContLevel: original.ContLevel,
		Factor:    original.Factor,
		Reln:      original.Reln,
		Vallen:    original.Vallen,
		Type:      original.Type,
		InType:    original.InType,
		InOp:      original.InOp,
		MaskOp:    original.MaskOp,
		Cond:      original.Cond,
		FactorOp:  original.FactorOp,
		Offset:    int32(targetOffset),
		InOffset:  original.InOffset,
		Lineno:    original.Lineno,
		NumMask:   original.NumMask,
		Desc:      original.Desc,
		Value:     original.Value,
		Apple:     original.Apple,
		MimeType:  original.MimeType,
		Ext:       original.Ext,
	}
	
	return entry
}

// matchIndirectPattern evaluates the pattern at the indirect location
func (d *Detector) matchIndirectPattern(data []byte, entry *magic.MagicEntry, targetOffset int, depth int) (bool, string) {
	// Ensure we have enough data at the target offset
	if targetOffset >= len(data) {
		return false, ""
	}
	
	targetData := data[targetOffset:]
	
	// Based on the original entry type, evaluate the pattern
	switch entry.Type {
	case magic.FILE_BYTE:
		return d.matchByte(targetData, entry, data)
	case magic.FILE_SHORT:
		return d.matchShort(targetData, entry, data)
	case magic.FILE_LONG:
		return d.matchLong(targetData, entry, data)
	case magic.FILE_STRING:
		return d.matchString(targetData, entry)
	case magic.FILE_BESHORT:
		return d.matchBEShort(targetData, entry, data)
	case magic.FILE_BELONG:
		return d.matchBELong(targetData, entry, data)
	case magic.FILE_LESHORT:
		return d.matchLEShort(targetData, entry, data)
	case magic.FILE_LELONG:
		return d.matchLELong(targetData, entry, data)
	case magic.FILE_QUAD:
		return d.matchQuad(targetData, entry, data)
	case magic.FILE_BEQUAD:
		return d.matchBEQuad(targetData, entry, data)
	case magic.FILE_LEQUAD:
		return d.matchLEQuad(targetData, entry, data)
	case magic.FILE_INDIRECT:
		// Recursive indirect reference
		return d.matchIndirectWithDepth(targetData, entry, data, depth)
	default:
		// For unknown types, try string match as fallback
		if match, result := d.matchString(targetData, entry); match {
			return match, result
		}
		
		// If string match fails, check if we have a valid description
		desc := entry.GetDescription()
		if len(desc) > 0 && d.isValidDescription(desc) {
			return true, desc
		}
	}
	
	return false, ""
}

// matchUse handles FILE_USE type (Type 46) - references another named magic pattern
func (d *Detector) matchUse(data []byte, entry *magic.MagicEntry) (bool, string) {
	return d.matchUseWithDepth(data, entry, data, 0)
}

// matchUseWithDepth handles FILE_USE with recursion depth tracking
func (d *Detector) matchUseWithDepth(data []byte, entry *magic.MagicEntry, fullData []byte, depth int) (bool, string) {
	// Prevent infinite recursion
	const maxUseDepth = 10
	if depth > maxUseDepth {
		if d.options.Debug {
			d.logger.Debug("FILE_USE: maximum recursion depth exceeded", "depth", depth)
		}
		return false, ""
	}

	// FILE_USE references another magic entry by name
	// The pattern name is stored in the Value field as a string
	referenceName := entry.GetValueAsString()
	
	if d.options.Debug {
		d.logger.Debug("FILE_USE: looking for reference", 
			"reference_name", referenceName, 
			"depth", depth)
	}
	
	if len(referenceName) == 0 {
		if d.options.Debug {
			d.logger.Debug("FILE_USE: no reference name specified")
		}
		// Check if this entry has a standalone description
		desc := entry.GetDescription()
		if len(desc) > 0 && d.isValidDescription(desc) {
			return true, desc
		}
		return false, ""
	}
	
	// Look for the referenced magic entry in the database
	referencedEntry := d.database.FindNamedEntry(referenceName)
	if referencedEntry == nil {
		if d.options.Debug {
			d.logger.Debug("FILE_USE: referenced entry not found", "reference_name", referenceName)
		}
		
		// Fallback: check if the current entry has a description
		desc := entry.GetDescription()
		if len(desc) > 0 && d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("FILE_USE: using fallback description", "description", desc)
			}
			return true, desc
		}
		return false, ""
	}
	
	if d.options.Debug {
		d.logger.Debug("FILE_USE: found referenced entry", 
			"reference_name", referenceName,
			"referenced_type", referencedEntry.Type,
			"referenced_offset", referencedEntry.Offset)
	}
	
	// Recursively evaluate the referenced entry
	return d.evaluateReferencedEntry(data, referencedEntry, fullData, depth+1)
}

// evaluateReferencedEntry evaluates a referenced magic entry
func (d *Detector) evaluateReferencedEntry(data []byte, entry *magic.MagicEntry, fullData []byte, depth int) (bool, string) {
	// Check for circular references by checking if this is another FILE_USE
	if entry.Type == magic.FILE_USE {
		return d.matchUseWithDepth(data, entry, fullData, depth)
	}
	
	// Check for indirect addressing
	if entry.Flag&magic.INDIR != 0 {
		return d.matchIndirectWithDepth(data, entry, fullData, depth)
	}
	
	// For direct entries, we need to handle the offset correctly
	// The referenced entry might have a different offset than the current context
	var targetData []byte
	if entry.Offset >= 0 && int(entry.Offset) < len(fullData) {
		targetData = fullData[entry.Offset:]
	} else {
		// If offset is invalid, use the current data
		targetData = data
	}
	
	// Evaluate the referenced entry using the appropriate match function
	switch entry.Type {
	case magic.FILE_BYTE:
		return d.matchByte(targetData, entry, fullData)
	case magic.FILE_SHORT:
		return d.matchShort(targetData, entry, fullData)
	case magic.FILE_LONG:
		return d.matchLong(targetData, entry, fullData)
	case magic.FILE_STRING:
		return d.matchString(targetData, entry)
	case magic.FILE_BESHORT:
		return d.matchBEShort(targetData, entry, fullData)
	case magic.FILE_BELONG:
		return d.matchBELong(targetData, entry, fullData)
	case magic.FILE_LESHORT:
		return d.matchLEShort(targetData, entry, fullData)
	case magic.FILE_LELONG:
		return d.matchLELong(targetData, entry, fullData)
	case magic.FILE_QUAD:
		return d.matchQuad(targetData, entry, fullData)
	case magic.FILE_BEQUAD:
		return d.matchBEQuad(targetData, entry, fullData)
	case magic.FILE_LEQUAD:
		return d.matchLEQuad(targetData, entry, fullData)
	case magic.FILE_PSTRING:
		return d.matchPString(targetData, entry)
	case magic.FILE_REGEX:
		return d.matchRegex(targetData, entry)
	case magic.FILE_SEARCH:
		return d.matchSearch(targetData, entry, fullData)
	case magic.FILE_FLOAT:
		return d.matchFloat(targetData, entry, fullData)
	case magic.FILE_DOUBLE:
		return d.matchDouble(targetData, entry, fullData)
	case magic.FILE_GUID:
		return d.matchGUID(targetData, entry)
	case magic.FILE_DER:
		return d.matchDER(targetData, entry)
	default:
		// For unknown or complex types, try string match as fallback
		if match, result := d.matchString(targetData, entry); match {
			return match, result
		}
		
		// Last resort: use the description if available
		desc := entry.GetDescription()
		if len(desc) > 0 && d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("FILE_USE: using referenced entry description", "description", desc)
			}
			return true, desc
		}
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
		d.logger.Debug("BELONG comparison", "actual", fmt.Sprintf("0x%08x", actual), "expected", fmt.Sprintf("0x%08x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "SHORT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LELONG comparison", "actual", fmt.Sprintf("0x%08x", actual), "expected", fmt.Sprintf("0x%08x", expected))
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
		d.logger.Debug("BESHORT comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "SHORT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LESHORT comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "SHORT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEQUAD comparison", "actual", fmt.Sprintf("0x%016x", actual), "expected", fmt.Sprintf("0x%016x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEQUAD", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEQUAD comparison", "actual", fmt.Sprintf("0x%016x", actual), "expected", fmt.Sprintf("0x%016x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEQUAD", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
			d.logger.Debug("PSTRING: insufficient data for string length", "required_length", strLen)
		}
		return false, ""
	}
	
	// Extract the actual string data (skip length byte)
	actual := string(data[1 : 1+strLen])
	
	// Get expected pattern from magic entry
	pattern := entry.GetValueAsString()
	
	if d.options.Debug {
		d.logger.Debug("PSTRING match comparison", "pattern", pattern, "pattern_length", len(pattern), "actual", actual, "actual_length", len(actual))
	}
	
	if len(pattern) == 0 {
		return false, ""
	}

	// Compare strings
	if actual == pattern {
		if d.options.Debug {
			d.logger.Debug("PSTRING match successful")
		}
		
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "PSTRING", "description_hex", fmt.Sprintf("%x", []byte(desc)))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				d.logger.Debug("PSTRING match has no description, skipping")
			}
			return false, ""
		}
		
		return true, desc
	}
	
	if d.options.Debug {
		d.logger.Debug("PSTRING no match found")
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
				d.logger.Debug("GUID mismatch", "byte_position", i, "got", fmt.Sprintf("0x%02x", data[i]), "expected", fmt.Sprintf("0x%02x", entry.Value[i]))
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
		d.logger.Debug("GUID match successful", "guid", guid)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && !d.isValidDescription(desc) {
		if d.options.Debug {
			d.logger.Debug("Skipping entry with corrupted description", "entry_type", "GUID", "description_hex", fmt.Sprintf("%x", []byte(desc)))
		}
		return false, ""
	}
	
	if len(desc) == 0 {
		if d.options.Debug {
			d.logger.Debug("GUID match has no description, skipping")
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
		d.logger.Debug("DER parsing", "tag", fmt.Sprintf("0x%02x", tag), "length_byte", fmt.Sprintf("0x%02x", lengthByte))
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
				d.logger.Debug("DER pattern mismatch", "expected", expectedPattern, "got", actual)
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
				d.logger.Debug("DER invalid long form length", "octets", lengthOctets)
			}
			return false, ""
		}
		
		totalLength = 0
		for i := 0; i < lengthOctets; i++ {
			totalLength = (totalLength << 8) | int(data[2+i])
		}
	}
	
	if d.options.Debug {
		d.logger.Debug("DER match successful", "tag", fmt.Sprintf("0x%02x", tag), "length", totalLength)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && !d.isValidDescription(desc) {
		if d.options.Debug {
			d.logger.Debug("Skipping entry with corrupted description", "entry_type", "DER", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("FLOAT comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "FLOAT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("DOUBLE comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "DOUBLE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("QUAD comparison", "actual", fmt.Sprintf("0x%016x", actual), "expected", fmt.Sprintf("0x%016x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "QUAD", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEFLOAT comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEFLOAT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEFLOAT comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(float64(actual), expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEFLOAT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEDOUBLE comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEDOUBLE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEDOUBLE comparison", "actual", actual, "expected", expected)
	}

	match := compareFloats(actual, expected, entry.Reln)
	if match {
		desc := entry.GetDescription()
		
		// Check if description contains only printable characters
		if len(desc) > 0 && !d.isValidDescription(desc) {
			if d.options.Debug {
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEDOUBLE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("REGEX pattern check", "pattern", pattern, "data_length", len(data))
	}
	
	// Compile the regular expression
	regex, err := regexp.Compile(pattern)
	if err != nil {
		if d.options.Debug {
			d.logger.Debug("REGEX: invalid pattern", "pattern", pattern, "error", err)
		}
		// Fallback to simple string matching for invalid patterns
		text := string(data)
		if strings.Contains(text, pattern) {
			if d.options.Debug {
				d.logger.Debug("✓ REGEX: fallback string match")
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "REGEX", "description_hex", fmt.Sprintf("%x", []byte(desc)))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				d.logger.Debug("REGEX match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			d.logger.Debug("REGEX pattern matched", "pattern", pattern)
		}
		return true, desc
	}
	
	if d.options.Debug {
		d.logger.Debug("REGEX: pattern no match", "pattern", pattern)
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
		d.logger.Debug("SEARCH operation", "pattern", pattern, "offset", entry.Offset)
	}
	
	// Determine search range
	searchData := fullData
	startOffset := int(entry.Offset)
	
	// Use NumMask as search range if specified (common FILE_SEARCH usage)
	var searchRange int
	if entry.NumMask > 0 && entry.NumMask < uint64(len(fullData)) {
		searchRange = int(entry.NumMask)
		if d.options.Debug {
			d.logger.Debug("SEARCH: using range mask", "mask", searchRange)
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
			d.logger.Debug("SEARCH: window defined", "start", startOffset, "end", endOffset, "size", len(searchData))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "SEARCH", "description_hex", fmt.Sprintf("%x", []byte(desc)))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				d.logger.Debug("SEARCH match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			d.logger.Debug("SEARCH: pattern found", "pattern", pattern)
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
		d.logger.Debug("NAME: pattern check without filename context", "pattern", pattern)
	}
	
	desc := entry.GetDescription()
	
	// Check if description contains only printable characters
	if len(desc) > 0 && d.isValidDescription(desc) {
		// For FILE_NAME entries with valid descriptions, we can still return them
		// This is useful for entries that provide format info regardless of filename
		if d.options.Debug {
			d.logger.Debug("✓ NAME: using description (no filename match needed)", "value", desc)
		}
		return true, desc
	}
	
	// Skip FILE_NAME entries without filename context or valid descriptions
	if d.options.Debug {
		d.logger.Debug("NAME: skipping (requires filename context)")
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
		d.logger.Debug("BELDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BELDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEQDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEQDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEQDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEQDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BESTRING16 pattern check", "pattern", pattern, "data_length", len(data))
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
				d.logger.Debug("Skipping BESTRING16 entry with corrupted description", "description_hex", fmt.Sprintf("%x", []byte(desc)))
			}
			return false, ""
		}
		
		if len(desc) == 0 {
			if d.options.Debug {
				d.logger.Debug("BESTRING16 match has no description, skipping")
			}
			return false, ""
		}
		
		if d.options.Debug {
			d.logger.Debug("  ✓ BESTRING16 pattern check", "pattern", pattern, "text", textStr)
		}
		return true, desc
	}
	
	if d.options.Debug {
		d.logger.Debug("BESTRING16: pattern no match", "pattern", pattern, "text", textStr)
	}
	
	return false, ""
}

// matchClear clears flags or state in magic processing
func (d *Detector) matchClear(data []byte, entry *magic.MagicEntry, fullData []byte) (bool, string) {
	if d.options.Debug {
		d.logger.Debug("CLEAR: clearing state flags")
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
		d.logger.Debug("DATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "DATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LELDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LELDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("QDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "QDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("QLDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "QLDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEQLDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEQLDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEQLDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEQLDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("MSDOSDATE comparison", "actual", fmt.Sprintf("0x%04x", actual), "date", fmt.Sprintf("%04d-%02d-%02d", year, month, day), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "MSDOSDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEMSDOSDATE comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEMSDOSDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEMSDOSDATE comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEMSDOSDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("MSDOSTIME comparison", "actual", fmt.Sprintf("0x%04x", actual), "time", fmt.Sprintf("%02d:%02d:%02d", hour, minute, second), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "MSDOSTIME", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEMSDOSTIME comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEMSDOSTIME", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEMSDOSTIME comparison", "actual", fmt.Sprintf("0x%04x", actual), "expected", fmt.Sprintf("0x%04x", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEMSDOSTIME", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("OCTAL comparison", "actual", fmt.Sprintf("0%o", actual), "expected", fmt.Sprintf("0%o", expected))
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "OCTAL", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("MEDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "MEDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("MELDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "MELDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("MELONG comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "MELONG", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("QWDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "QWDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEQWDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEQWDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEQWDATE comparison", "actual", actual, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEQWDATE", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEID3 comparison", "actual", fmt.Sprintf("0x%08x", actual), "actual_string", idStr, "expected", fmt.Sprintf("0x%08x", expected))
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
				d.logger.Debug("Skipping BEID3 entry with corrupted description", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEID3 comparison", "actual", fmt.Sprintf("0x%08x", actual), "actual_string", idStr, "expected", fmt.Sprintf("0x%08x", expected))
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
				d.logger.Debug("Skipping LEID3 entry with corrupted description", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("BEVARINT comparison", "actual", actual, "bytes_read", bytesRead, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "BEVARINT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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
		d.logger.Debug("LEVARINT comparison", "actual", actual, "bytes_read", bytesRead, "expected", expected)
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
				d.logger.Debug("Skipping entry with corrupted description", "entry_type", "LEVARINT", "description_hex", fmt.Sprintf("%x", []byte(desc)))
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