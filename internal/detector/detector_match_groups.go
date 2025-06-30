package detector

import (
	"log"
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

// matchStringGroup optimizes string pattern matching by using a single pass
func (d *Detector) matchStringGroup(data []byte, entries []*magic.MagicEntry) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}

	text := string(data)
	
	// Build pattern map for efficient matching
	patterns := make(map[string]*magic.MagicEntry)
	for _, entry := range entries {
		pattern := entry.GetValueAsString()
		if len(pattern) > 0 {
			patterns[pattern] = entry
		}
	}

	// Single pass through the text to find any matching pattern
	for pattern, entry := range patterns {
		if strings.Contains(text, pattern) {
			desc := entry.GetDescription()
			if len(desc) > 0 && d.isValidDescription(desc) {
				if d.options.Debug {
					log.Printf("✓ STRING GROUP: pattern '%s' matched", pattern)
				}
				return true, desc
			}
		}
	}

	return false, ""
}

// matchByteGroup optimizes byte pattern matching
func (d *Detector) matchByteGroup(data []byte, entries []*magic.MagicEntry) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}

	firstByte := data[0]
	
	// Check all byte patterns against the first byte
	for _, entry := range entries {
		if entry.Offset == 0 {
			expected := entry.Value[0]
			
			// Apply mask if specified
			actual := firstByte
			if entry.NumMask != 0 {
				actual &= byte(entry.NumMask)
				expected &= byte(entry.NumMask)
			}
			
			if compareValues(uint64(actual), uint64(expected), entry.Reln) {
				desc := entry.GetDescription()
				if len(desc) > 0 && d.isValidDescription(desc) {
					if d.options.Debug {
						log.Printf("✓ BYTE GROUP: value 0x%02x matched", firstByte)
					}
					return true, desc
				}
			}
		}
	}

	return false, ""
}

// matchShortGroup optimizes 16-bit integer matching
func (d *Detector) matchShortGroup(data []byte, entries []*magic.MagicEntry) (bool, string) {
	if len(data) < 2 {
		return false, ""
	}

	// Pre-read values for different endiannesses
	leBe := readUint16(data, true)  // Little-endian
	beVal := readUint16(data, false) // Big-endian

	for _, entry := range entries {
		if entry.Offset == 0 {
			var actual uint16
			
			switch entry.Type {
			case magic.FILE_SHORT:
				actual = leBe // Default little-endian
			case magic.FILE_LESHORT:
				actual = leBe
			case magic.FILE_BESHORT:
				actual = beVal
			default:
				continue
			}

			expected := uint16(entry.Value[0]) | uint16(entry.Value[1])<<8

			// Apply mask if specified
			if entry.NumMask != 0 {
				actual &= uint16(entry.NumMask)
				expected &= uint16(entry.NumMask)
			}

			if compareValues(uint64(actual), uint64(expected), entry.Reln) {
				desc := entry.GetDescription()
				if len(desc) > 0 && d.isValidDescription(desc) {
					if d.options.Debug {
						log.Printf("✓ SHORT GROUP: value 0x%04x matched", actual)
					}
					return true, desc
				}
			}
		}
	}

	return false, ""
}

// matchLongGroup optimizes 32-bit integer matching
func (d *Detector) matchLongGroup(data []byte, entries []*magic.MagicEntry) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Pre-read values for different endiannesses
	leVal := readUint32(data, true)  // Little-endian
	beVal := readUint32(data, false) // Big-endian

	for _, entry := range entries {
		if entry.Offset == 0 {
			var actual uint32
			
			switch entry.Type {
			case magic.FILE_LONG:
				actual = leVal // Default little-endian
			case magic.FILE_LELONG:
				actual = leVal
			case magic.FILE_BELONG:
				actual = beVal
			default:
				continue
			}

			expected := uint32(entry.Value[0]) | 
				uint32(entry.Value[1])<<8 | 
				uint32(entry.Value[2])<<16 | 
				uint32(entry.Value[3])<<24

			// Apply mask if specified
			if entry.NumMask != 0 {
				actual &= uint32(entry.NumMask)
				expected &= uint32(entry.NumMask)
			}

			if compareValues(uint64(actual), uint64(expected), entry.Reln) {
				desc := entry.GetDescription()
				if len(desc) > 0 && d.isValidDescription(desc) {
					if d.options.Debug {
						log.Printf("✓ LONG GROUP: value 0x%08x matched", actual)
					}
					return true, desc
				}
			}
		}
	}

	return false, ""
}
