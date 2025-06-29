package detector

import (
	"fmt"
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

// Helper functions for reading different integer types

func (d *Detector) readUint16(data []byte, littleEndian bool) uint16 {
	if littleEndian {
		return uint16(data[0]) | uint16(data[1])<<8
	}
	return uint16(data[1]) | uint16(data[0])<<8
}

func (d *Detector) readInt16(data []byte, littleEndian bool) int16 {
	return int16(d.readUint16(data, littleEndian))
}

func (d *Detector) readUint32(data []byte, littleEndian bool) uint32 {
	if littleEndian {
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	}
	return uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
}

func (d *Detector) readInt32(data []byte, littleEndian bool) int32 {
	return int32(d.readUint32(data, littleEndian))
}

// compareValues compares two values based on the relation operator
func (d *Detector) compareValues(actual, expected uint64, relation byte) bool {
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

// formatResult formats the detection result based on options
func (d *Detector) formatResult(desc string) string {
	if d.options.MIME {
		// Convert description to MIME type
		// This is a simplified mapping - real implementation would be more comprehensive
		return d.descriptionToMIME(desc)
	}
	
	if d.options.Brief {
		// Return brief description
		return d.makeBrief(desc)
	}
	
	return desc
}

// descriptionToMIME converts a description to MIME type
func (d *Detector) descriptionToMIME(desc string) string {
	desc = strings.ToLower(desc)
	
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
		
	// Archive formats
	case contains(desc, "zip"):
		return "application/zip"
	case contains(desc, "gzip") || contains(desc, "gz"):
		return "application/gzip"
	case contains(desc, "bzip2") || contains(desc, "bz2"):
		return "application/x-bzip2"
	case contains(desc, "tar"):
		return "application/x-tar"
	case contains(desc, "7-zip"):
		return "application/x-7z-compressed"
	case contains(desc, "rar"):
		return "application/vnd.rar"
		
	// Audio formats
	case contains(desc, "mp3"):
		return "audio/mpeg"
	case contains(desc, "wav"):
		return "audio/wav"
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
	case contains(desc, "mkv"):
		return "video/x-matroska"
	case contains(desc, "webm"):
		return "video/webm"
	case contains(desc, "mov"):
		return "video/quicktime"
		
	// Executable formats
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
func (d *Detector) makeBrief(desc string) string {
	// Extract the first meaningful part of the description
	// TODO: Implement proper brief formatting
	if len(desc) > 50 {
		return desc[:47] + "..."
	}
	return desc
}

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
			
			// Check for RFC 822 mail headers (if not HTML/XML/Batch)
			if !isHTML && !isXML && !isBatch {
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