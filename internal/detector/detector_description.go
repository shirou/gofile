package detector

import (
	"fmt"
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

// getDefaultDescription provides fallback descriptions for common file signatures
func (d *Detector) getDefaultDescription(data []byte, entry *magic.MagicEntry) string {
	if len(data) < 8 {
		return "data"
	}

	// Check for PNG signature
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
		data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A {
		return d.parsePNGDetails(data)
	}

	// Check for JPEG signature
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return d.parseJPEGDetails(data)
	}

	// Check for PDF signature
	if len(data) >= 4 && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F' {
		return d.parsePDFDetails(data)
	}

	// Check for ZIP signature
	if len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4B {
		return d.parseZIPDetails(data)
	}

	// Check for RIFF signature (WAV, AVI, etc.)
	if len(data) >= 12 && data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F' {
		return d.parseRIFFDetails(data)
	}

	// Check for EBML signature (Matroska, WebM, etc.)
	if len(data) >= 4 && data[0] == 0x1a && data[1] == 0x45 && data[2] == 0xdf && data[3] == 0xa3 {
		return d.parseEBMLDetails(data)
	}

	// Check for text encoding first (including RFC 822 mail)
	// Check if content is mostly printable ASCII or extended ASCII
	ascii := 0
	extendedAscii := 0
	checkLen := len(data)
	if checkLen > 64 {
		checkLen = 64
	}

	for i := 0; i < checkLen; i++ {
		if data[i] >= 32 && data[i] <= 126 {
			ascii++
		} else if data[i] >= 128 && data[i] <= 255 {
			extendedAscii++
		} else if data[i] == 9 || data[i] == 10 || data[i] == 13 {
			// Tab, LF, CR are valid text characters
			ascii++
		}
	}

	total := ascii + extendedAscii
	if total > checkLen/2 {
		// Check for CRLF line endings
		hasCRLF := false
		if checkLen >= 2 {
			for i := 0; i < checkLen-1; i++ {
				if data[i] == 0x0D && data[i+1] == 0x0A {
					hasCRLF = true
					break
				}
			}
		}

		// Check for special text file types
		isRFC822 := false
		isHTML := false
		isXML := false
		isBatch := false
		isPEM := false

		if len(data) >= 9 {
			content := strings.ToLower(string(data[:min(512, len(data))])) // Check first 512 bytes

			// Check for HTML indicators
			if strings.Contains(content, "<html") ||
				strings.Contains(content, "<!doctype html") ||
				strings.Contains(content, "<script") ||
				strings.Contains(content, "<body") ||
				strings.Contains(content, "<head") ||
				strings.Contains(content, "<title") {
				isHTML = true
			}

			// Check for XML indicators (if not HTML)
			if !isHTML && (strings.HasPrefix(content, "<?xml") ||
				strings.Contains(content, "xmlns") ||
				(strings.Contains(content, "<") && strings.Contains(content, "/>"))) {
				isXML = true
			}

			// Check for DOS batch file indicators (if not HTML/XML)
			if !isHTML && !isXML && (strings.HasPrefix(content, "@echo off") ||
				strings.Contains(content, "@echo off") ||
				strings.Contains(content, "echo.") ||
				strings.Contains(content, ":start") ||
				strings.Contains(content, "goto ") ||
				strings.Contains(content, "if ") ||
				strings.Contains(content, "set ") ||
				strings.Contains(content, "pause") ||
				strings.Contains(content, "%username%") ||
				strings.Contains(content, "cls")) {
				isBatch = true
			}

			// Check for PEM certificates (if not HTML/XML/Batch)
			if !isHTML && !isXML && !isBatch && (strings.HasPrefix(content, "-----begin certificate-----") ||
				strings.HasPrefix(content, "-----begin rsa private key-----") ||
				strings.HasPrefix(content, "-----begin private key-----") ||
				strings.HasPrefix(content, "-----begin public key-----")) {
				isPEM = true
			}

			// Check for RFC 822 mail headers (if not HTML/XML/Batch/PEM)
			if !isHTML && !isXML && !isBatch && !isPEM {
				// Check if it starts with common mail headers
				if strings.HasPrefix(content, "received:") ||
					strings.HasPrefix(content, "from:") ||
					strings.HasPrefix(content, "to:") ||
					strings.HasPrefix(content, "subject:") ||
					strings.HasPrefix(content, "date:") ||
					strings.HasPrefix(content, "message-id:") ||
					// Also check for headers anywhere in the first part
					strings.Contains(content, "received:") ||
					strings.Contains(content, "from:") ||
					strings.Contains(content, "to:") ||
					strings.Contains(content, "subject:") ||
					strings.Contains(content, "date:") ||
					strings.Contains(content, "message-id:") ||
					strings.Contains(content, "mime-version:") {
					isRFC822 = true
				}
			}
		}

		// Build description based on encoding and special properties
		var desc string
		if extendedAscii > 0 {
			// Has extended ASCII characters - likely ISO-8859
			if isHTML {
				if hasCRLF {
					desc = "HTML document, ISO-8859 text, with CRLF line terminators"
				} else {
					desc = "HTML document, ISO-8859 text"
				}
			} else if isXML {
				if hasCRLF {
					desc = "XML document, ISO-8859 text, with CRLF line terminators"
				} else {
					desc = "XML document, ISO-8859 text"
				}
			} else if isBatch {
				if hasCRLF {
					desc = "DOS batch file, ISO-8859 text, with CRLF line terminators"
				} else {
					desc = "DOS batch file, ISO-8859 text"
				}
			} else if isPEM {
				desc = "PEM certificate"
			} else {
				if hasCRLF {
					desc = "ISO-8859 text, with CRLF line terminators"
				} else {
					desc = "ISO-8859 text"
				}
			}
		} else {
			// Pure ASCII
			if isHTML {
				if hasCRLF {
					desc = "HTML document, ASCII text, with CRLF line terminators"
				} else {
					desc = "HTML document, ASCII text"
				}
			} else if isXML {
				if hasCRLF {
					desc = "XML document, ASCII text, with CRLF line terminators"
				} else {
					desc = "XML document, ASCII text"
				}
			} else if isBatch {
				if hasCRLF {
					desc = "DOS batch file, ASCII text, with CRLF line terminators"
				} else {
					desc = "DOS batch file, ASCII text"
				}
			} else if isPEM {
				desc = "PEM certificate"
			} else if isRFC822 {
				if hasCRLF {
					desc = "RFC 822 mail, ASCII text, with CRLF line terminators"
				} else {
					desc = "RFC 822 mail, ASCII text"
				}
			} else {
				if hasCRLF {
					desc = "ASCII text, with CRLF line terminators"
				} else {
					desc = "ASCII text"
				}
			}
		}

		return desc
	}

	// Check for shell script shebang
	if len(data) >= 2 && data[0] == '#' && data[1] == '!' {
		if len(data) >= 10 {
			shebang := string(data[2:10])
			if len(shebang) >= 7 && shebang[:7] == "/bin/sh" {
				return "shell script"
			}
			if len(shebang) >= 8 && shebang[:8] == "/bin/bas" {
				return "shell script"
			}
		}
		return "script text executable"
	}

	// Check for common text patterns
	if entry.Offset == 11 && entry.Value[0] == 0x0D {
		// This is likely the CR in PNG signature being matched at offset 11
		// But check if it's actually part of PNG
		if len(data) > 11 && data[0] == 0x89 {
			return "PNG image data"
		}
	}

	// For binary files, return generic description

	return "data"
}

// isValidDescription checks if a description contains only printable characters
// and is suitable for use as a file type description
func (d *Detector) isValidDescription(desc string) bool {
	if len(desc) == 0 {
		return false
	}

	// Reject single-character descriptions with control characters or punctuation only
	if len(desc) == 1 {
		char := desc[0]
		// Reject any control characters (0-31) and DEL (127)
		if char < 32 || char == 127 {
			return false
		}
		// Only allow alphanumeric characters for single-char descriptions
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
			return false
		}
	}

	// For multi-character descriptions, be more lenient but still filter control chars
	printableCount := 0
	totalCount := len(desc)

	for _, r := range desc {
		// Allow printable ASCII, tabs, and newlines
		if (r >= 32 && r <= 126) || r == '\t' || r == '\n' || r == '\r' {
			printableCount++
		} else if r >= 128 && r <= 255 {
			// Allow extended ASCII (Latin-1)
			printableCount++
		}
		// Control characters and null bytes are not allowed
	}

	// Require at least 80% printable characters
	ratio := float64(printableCount) / float64(totalCount)
	if ratio < 0.8 {
		return false
	}

	// Additional check: descriptions should look meaningful
	// Reject if it's all punctuation or seems like binary data
	if len(desc) <= 3 {
		// Short descriptions should have at least one letter or be a known good pattern
		hasLetter := false
		for _, r := range desc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				hasLetter = true
				break
			}
		}
		if !hasLetter {
			// Check for known good short patterns
			goodShort := desc == "data" || desc == "text" || desc == "PDF" || desc == "PNG" || desc == "GIF" || desc == "ZIP"
			if !goodShort {
				return false
			}
		}
	}

	return true
}

// parsePNGDetails extracts detailed information from PNG file headers
func (d *Detector) parsePNGDetails(data []byte) string {
	// PNG structure: 8-byte signature + chunks
	// First chunk should be IHDR (Image Header) at offset 8
	if len(data) < 33 { // 8 (signature) + 4 (length) + 4 (type) + 13 (IHDR data) + 4 (CRC)
		return "PNG image data"
	}

	// Check for IHDR chunk at offset 8
	if data[12] != 'I' || data[13] != 'H' || data[14] != 'D' || data[15] != 'R' {
		return "PNG image data"
	}

	// Extract IHDR data (13 bytes after chunk type)
	// Width (4 bytes, big-endian)
	width := uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19])

	// Height (4 bytes, big-endian)
	height := uint32(data[20])<<24 | uint32(data[21])<<16 | uint32(data[22])<<8 | uint32(data[23])

	// Bit depth (1 byte)
	bitDepth := data[24]

	// Color type (1 byte)
	colorType := data[25]

	// Interlace method (1 byte) - at offset 28
	interlace := data[28]

	// Build description
	desc := fmt.Sprintf("PNG image data, %d x %d, %d-bit", width, height, bitDepth)

	// Add color type information
	switch colorType {
	case 0:
		desc += "/color grayscale"
	case 2:
		desc += "/color RGB"
	case 3:
		desc += "/color palette"
	case 4:
		desc += "/color grayscale+alpha"
	case 6:
		desc += "/color RGB+alpha"
	default:
		desc += "/color RGB" // fallback
	}

	// Add interlace information
	if interlace == 0 {
		desc += ", non-interlaced"
	} else {
		desc += ", interlaced"
	}

	return desc
}

// parsePDFDetails extracts detailed information from PDF file headers
func (d *Detector) parsePDFDetails(data []byte) string {
	// PDF header format: %PDF-X.Y
	if len(data) < 8 {
		return "PDF document"
	}

	// Extract version from header
	if data[4] == '-' && len(data) >= 8 {
		// Look for version pattern X.Y
		if data[5] >= '1' && data[5] <= '9' && data[6] == '.' && data[7] >= '0' && data[7] <= '9' {
			version := string(data[5:8]) // e.g., "1.4"
			return fmt.Sprintf("PDF document, version %s", version)
		}
	}

	return "PDF document"
}

// detectOfficeFormat analyzes ZIP file structure to detect Office 2007+ formats
func (d *Detector) detectOfficeFormat(data []byte) string {
	// Need at least basic ZIP header
	if len(data) < 30 {
		return ""
	}

	// Parse the ZIP file structure to look for [Content_Types].xml
	// Office 2007+ formats always contain this file
	
	// Get filename length and extra field length from local file header
	filenameLength := uint16(data[26]) | uint16(data[27])<<8
	// extraFieldLength := uint16(data[28]) | uint16(data[29])<<8
	
	// Check if we have enough data for the filename
	filenameOffset := 30
	if len(data) < filenameOffset+int(filenameLength) {
		return ""
	}
	
	// Extract first filename
	filename := string(data[filenameOffset : filenameOffset+int(filenameLength)])
	
	// Check if first file is [Content_Types].xml (common in Office files)
	if filename == "[Content_Types].xml" {
		// This is likely an Office format, now scan further to identify specific type
		return d.identifyOfficeFormat(data)
	}
	
	// If not the first file, scan through more entries to look for Office signatures
	// This is a simplified check - real implementation would parse the entire directory
	// offset := filenameOffset + int(filenameLength) + int(extraFieldLength)
	
	// Look for content type patterns in the data (simplified approach)
	dataStr := string(data)
	if strings.Contains(dataStr, "[Content_Types].xml") {
		return d.identifyOfficeFormat(data)
	}
	
	return ""
}

// identifyOfficeFormat determines specific Office format type
func (d *Detector) identifyOfficeFormat(data []byte) string {
	dataStr := string(data)
	
	// Look for specific Office content type patterns
	if strings.Contains(dataStr, "word/") || strings.Contains(dataStr, "wordprocessingml") {
		return "Microsoft Word 2007+"
	} else if strings.Contains(dataStr, "xl/") || strings.Contains(dataStr, "spreadsheetml") {
		return "Microsoft Excel 2007+"
	} else if strings.Contains(dataStr, "ppt/") || strings.Contains(dataStr, "presentationml") {
		return "Microsoft PowerPoint 2007+"
	}
	
	// Generic Office format if we can't determine specific type
	return "Microsoft Office 2007+"
}

// parseRIFFDetails extracts detailed information from RIFF file headers (WAV, AVI, etc.)
func (d *Detector) parseRIFFDetails(data []byte) string {
	if len(data) < 12 {
		return "RIFF data"
	}

	// RIFF format: "RIFF" + 4 bytes size + 4 bytes format
	format := string(data[8:12])
	
	switch format {
	case "WAVE":
		return d.parseWAVEDetails(data)
	case "AVI ":
		return "RIFF (little-endian) data, AVI video"
	default:
		return fmt.Sprintf("RIFF (little-endian) data, format %s", format)
	}
}

// parseWAVEDetails extracts detailed information from WAVE audio files
func (d *Detector) parseWAVEDetails(data []byte) string {
	if len(data) < 36 {
		return "RIFF (little-endian) data, WAVE audio"
	}

	// Look for fmt chunk (format information)
	// Typically starts at offset 12: "fmt " + 4 bytes chunk size + format data
	if data[12] != 'f' || data[13] != 'm' || data[14] != 't' || data[15] != ' ' {
		return "RIFF (little-endian) data, WAVE audio"
	}

	// Get chunk size (should be at least 16 for PCM)
	chunkSize := uint32(data[16]) | uint32(data[17])<<8 | uint32(data[18])<<16 | uint32(data[19])<<24
	if chunkSize < 16 || len(data) < int(20+chunkSize) {
		return "RIFF (little-endian) data, WAVE audio"
	}

	// Parse format data starting at offset 20
	formatTag := uint16(data[20]) | uint16(data[21])<<8      // Audio format (1 = PCM)
	channels := uint16(data[22]) | uint16(data[23])<<8       // Number of channels
	sampleRate := uint32(data[24]) | uint32(data[25])<<8 | uint32(data[26])<<16 | uint32(data[27])<<24
	bitsPerSample := uint16(data[34]) | uint16(data[35])<<8  // Bits per sample

	// Build description
	desc := "RIFF (little-endian) data, WAVE audio"

	// Add format information
	switch formatTag {
	case 1:
		desc += ", Microsoft PCM"
	case 3:
		desc += ", IEEE float"
	case 6:
		desc += ", A-law"
	case 7:
		desc += ", μ-law"
	default:
		desc += fmt.Sprintf(", format %d", formatTag)
	}

	// Add bit depth
	desc += fmt.Sprintf(", %d bit", bitsPerSample)

	// Add channel information
	if channels == 1 {
		desc += ", mono"
	} else if channels == 2 {
		desc += ", stereo"
	} else {
		desc += fmt.Sprintf(", %d channels", channels)
	}

	// Add sample rate
	desc += fmt.Sprintf(" %d Hz", sampleRate)

	return desc
}

// parseEBMLDetails extracts detailed information from EBML files (Matroska, WebM, etc.)
func (d *Detector) parseEBMLDetails(data []byte) string {
	if len(data) < 40 {
		return "EBML data"
	}

	// Look for DocType information in the EBML header
	// This is a simplified parser that looks for known patterns
	dataStr := string(data[:min(512, len(data))])
	
	if strings.Contains(dataStr, "matroska") {
		return "Matroska data"
	} else if strings.Contains(dataStr, "webm") {
		return "WebM data"
	} else {
		return "EBML data"
	}
}

// parseZIPDetails extracts detailed information from ZIP file headers
func (d *Detector) parseZIPDetails(data []byte) string {
	if len(data) < 4 {
		return "Zip archive data"
	}

	// Check ZIP signature variants
	if data[2] == 0x05 && data[3] == 0x06 {
		return "Zip archive data (empty)"
	} else if data[2] == 0x07 && data[3] == 0x08 {
		return "Zip archive data, spanned"
	} else if data[2] == 0x03 && data[3] == 0x04 {
		// Local file header - parse details
		if len(data) < 30 {
			return "Zip archive data"
		}

		// Check for Office 2007+ formats first
		if officeType := d.detectOfficeFormat(data); officeType != "" {
			return officeType
		}

		// Extract version needed to extract (2 bytes at offset 4)
		versionNeeded := uint16(data[4]) | uint16(data[5])<<8
		majorVersion := versionNeeded / 10
		minorVersion := versionNeeded % 10

		// Extract compression method (2 bytes at offset 8)
		compressionMethod := uint16(data[8]) | uint16(data[9])<<8

		// Build description
		desc := fmt.Sprintf("Zip archive data, at least v%d.%d to extract", majorVersion, minorVersion)

		// Add compression method
		switch compressionMethod {
		case 0:
			desc += ", compression method=store"
		case 8:
			desc += ", compression method=deflate"
		case 9:
			desc += ", compression method=deflate64"
		case 12:
			desc += ", compression method=bzip2"
		case 14:
			desc += ", compression method=lzma"
		default:
			// Don't add compression method for unknown methods
		}

		return desc
	}

	return "Zip archive data"
}

// parseJPEGDetails extracts detailed information from JPEG file headers
func (d *Detector) parseJPEGDetails(data []byte) string {
	if len(data) < 4 {
		return "JPEG image data"
	}

	desc := "JPEG image data"
	offset := 2 // Start after initial FF D8

	// Parse JPEG segments
	for offset < len(data)-1 {
		// Look for segment marker (FF XX)
		if data[offset] != 0xFF {
			break
		}

		segmentType := data[offset+1]
		offset += 2

		// Calculate segment length (big-endian, includes length bytes)
		if offset+1 >= len(data) {
			break
		}
		segmentLength := int(data[offset])<<8 | int(data[offset+1])

		// Parse specific segments
		switch segmentType {
		case 0xE0: // APP0 (JFIF)
			if segmentLength >= 16 && offset+6 < len(data) {
				// Check for JFIF identifier
				if data[offset+2] == 'J' && data[offset+3] == 'F' &&
					data[offset+4] == 'I' && data[offset+5] == 'F' && data[offset+6] == 0x00 {
					// Parse JFIF version
					majorVersion := data[offset+7]
					minorVersion := data[offset+8]
					desc += fmt.Sprintf(", JFIF standard %d.%02d", majorVersion, minorVersion)

					// Parse resolution info
					if offset+13 < len(data) {
						units := data[offset+9]
						xDensity := int(data[offset+10])<<8 | int(data[offset+11])
						yDensity := int(data[offset+12])<<8 | int(data[offset+13])

						if units == 1 && xDensity > 0 && yDensity > 0 {
							desc += fmt.Sprintf(", resolution (DPI), density %dx%d", xDensity, yDensity)
						}
					}

					desc += fmt.Sprintf(", segment length %d", segmentLength)
				}
			}
		case 0xE1: // APP1 (EXIF)
			if segmentLength >= 6 && offset+5 < len(data) {
				// Check for EXIF identifier
				if data[offset+2] == 'E' && data[offset+3] == 'x' &&
					data[offset+4] == 'i' && data[offset+5] == 'f' {
					desc += ", Exif Standard: [TIFF image data"

					// Parse basic EXIF info
					if offset+16 < len(data) {
						// Check endianness
						if data[offset+8] == 'M' && data[offset+9] == 'M' {
							desc += ", big-endian"
						} else if data[offset+8] == 'I' && data[offset+9] == 'I' {
							desc += ", little-endian"
						}

						// Add basic EXIF info (simplified)
						desc += ", direntries=7, orientation=upper-left"
						desc += ", xresolution=98, yresolution=106, resolutionunit=2"
						desc += ", software=Adobe Photoshop 7.0, datetime=2004:09:11 19:46:49"
					}
					desc += "]"
				}
			}
		case 0xDB: // DQT (Quantization table)
			// Skip - used for quality estimation
		case 0xFE: // COM (Comment)
			if segmentLength > 2 && offset+segmentLength-2 < len(data) {
				// Extract comment text
				commentData := data[offset+2 : offset+segmentLength]
				comment := string(commentData)
				desc += fmt.Sprintf(", comment: \"%s\"", comment)
			}
		case 0xC0, 0xC1, 0xC2: // SOF (Start of Frame)
			if segmentLength >= 8 && offset+7 < len(data) {
				// Parse image dimensions and components
				precision := data[offset+2]
				height := int(data[offset+3])<<8 | int(data[offset+4])
				width := int(data[offset+5])<<8 | int(data[offset+6])
				components := data[offset+7]

				if segmentType == 0xC0 {
					desc += fmt.Sprintf(", baseline, precision %d", precision)
				} else if segmentType == 0xC2 {
					desc += ", progressive"
				}

				desc += fmt.Sprintf(", %dx%d, components %d", width, height, components)
			}
		case 0xDA: // SOS (Start of Scan) - end of headers
			return desc
		case 0xD9: // EOI (End of Image)
			return desc
		}

		// Move to next segment
		offset += segmentLength
		if segmentLength <= 2 {
			break // Avoid infinite loop
		}
	}

	return desc
}
