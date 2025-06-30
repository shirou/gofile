package detector

import (
	"github.com/shirou/gofile/internal/magic"
)

// AdvancedPatternMatcher provides enhanced pattern matching capabilities
type AdvancedPatternMatcher struct {
	detector *Detector
}

// NewAdvancedPatternMatcher creates a new advanced pattern matcher
func NewAdvancedPatternMatcher(detector *Detector) *AdvancedPatternMatcher {
	return &AdvancedPatternMatcher{detector: detector}
}

// MatchMultiPatterns matches against multiple patterns simultaneously for better performance
func (apm *AdvancedPatternMatcher) MatchMultiPatterns(data []byte, entries []*magic.MagicEntry) (bool, string) {
	if len(data) == 0 || len(entries) == 0 {
		return false, ""
	}

	// Group entries by type for batch processing
	typeGroups := make(map[uint8][]*magic.MagicEntry)
	for _, entry := range entries {
		typeGroups[entry.Type] = append(typeGroups[entry.Type], entry)
	}

	// Process each type group
	for magicType, groupEntries := range typeGroups {
		if match, result := apm.matchTypeGroup(data, magicType, groupEntries); match {
			return true, result
		}
	}

	return false, ""
}

// matchTypeGroup processes a group of entries of the same type
func (apm *AdvancedPatternMatcher) matchTypeGroup(data []byte, magicType uint8, entries []*magic.MagicEntry) (bool, string) {
	switch magicType {
	case magic.FILE_STRING:
		return apm.detector.matchStringGroup(data, entries)
	case magic.FILE_BYTE:
		return apm.detector.matchByteGroup(data, entries)
	case magic.FILE_SHORT, magic.FILE_BESHORT, magic.FILE_LESHORT:
		return apm.detector.matchShortGroup(data, entries)
	case magic.FILE_LONG, magic.FILE_BELONG, magic.FILE_LELONG:
		return apm.detector.matchLongGroup(data, entries)
	default:
		// Fall back to individual matching
		for _, entry := range entries {
			if match, result := apm.detector.matchEntry(data, entry, data); match {
				return true, result
			}
		}
	}
	return false, ""
}


// FastHeaderDetection performs quick detection based on common file headers
func (apm *AdvancedPatternMatcher) FastHeaderDetection(data []byte) (bool, string) {
	if len(data) < 4 {
		return false, ""
	}

	// Common file signatures for fast detection
	signatures := map[string]string{
		"\xFF\xD8\xFF":     "JPEG image data",
		"\x89PNG\r\n\x1A\n": "PNG image data",
		"GIF8":             "GIF image data", 
		"%PDF":             "PDF document",
		"PK\x03\x04":       "ZIP archive data",
		"Rar!":             "RAR archive data",
		"\x7FELF":          "ELF executable",
		"MZ":               "MS-DOS executable",
		"\xCA\xFE\xBA\xBE": "Java class file",
		"RIFF":             "RIFF data",
		"\x00\x00\x01\x00": "Windows icon",
		"\x00\x00\x02\x00": "Windows cursor",
		"ID3":              "MP3 audio file",
		"fLaC":             "FLAC audio file",
		"OggS":             "Ogg audio file",
		"\x1F\x8B":         "gzip compressed data",
		"BZh":              "bzip2 compressed data",
		"\xFD7zXZ\x00":     "XZ compressed data",
	}

	// Check against known signatures
	for sig, desc := range signatures {
		if len(data) >= len(sig) && string(data[:len(sig)]) == sig {
			if apm.detector.options.Debug {
				apm.detector.logger.Debug("✓ FAST HEADER: detected", "description", desc)
			}
			return true, desc
		}
	}

	return false, ""
}

// PerformanceOptimizedDetection combines multiple optimization techniques
func (apm *AdvancedPatternMatcher) PerformanceOptimizedDetection(data []byte, cache *DetectorCache) (string, error) {
	if len(data) == 0 {
		return "empty", nil
	}

	// Try fast header detection first
	if match, result := apm.FastHeaderDetection(data); match {
		return apm.detector.formatResult(result), nil
	}

	// Use enhanced detection with caching
	return apm.detector.EnhancedDetectBytes(data, cache)
}

// ValidateComplexPatterns performs advanced validation for complex file formats
func (apm *AdvancedPatternMatcher) ValidateComplexPatterns(data []byte, magicType uint8, result string) bool {
	switch magicType {
	case magic.FILE_DER:
		return apm.validateDERStructure(data)
	case magic.FILE_REGEX:
		return apm.validateRegexPattern(data, result)
	case magic.FILE_GUID:
		return apm.validateGUIDFormat(data)
	default:
		return true // No additional validation needed
	}
}

// validateDERStructure performs additional DER validation
func (apm *AdvancedPatternMatcher) validateDERStructure(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	tag := data[0]
	lengthByte := data[1]

	// Basic DER tag validation
	if tag == 0x00 || tag == 0xFF {
		return false // Invalid tags
	}

	// Basic length validation
	if lengthByte&0x80 != 0 {
		// Long form length
		lengthOctets := int(lengthByte & 0x7F)
		if lengthOctets == 0 || lengthOctets > 4 {
			return false // Invalid long form
		}
	}

	return true
}

// validateRegexPattern validates regex pattern results
func (apm *AdvancedPatternMatcher) validateRegexPattern(data []byte, result string) bool {
	// Basic validation - ensure result is meaningful
	return len(result) > 0 && len(result) < 200 // Reasonable description length
}

// validateGUIDFormat validates GUID structure
func (apm *AdvancedPatternMatcher) validateGUIDFormat(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// Basic GUID validation - check for all zeros or all ones
	allZeros := true
	allOnes := true
	
	for i := 0; i < 16; i++ {
		if data[i] != 0x00 {
			allZeros = false
		}
		if data[i] != 0xFF {
			allOnes = false
		}
	}

	// Invalid if all zeros or all ones
	return !allZeros && !allOnes
}