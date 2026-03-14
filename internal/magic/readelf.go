package magic

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// elfReader provides pread-style access to ELF file data.
type elfReader struct {
	r    io.ReaderAt
	size int64
}

// readAt reads data from the underlying reader at the given offset.
// Returns the data read, or nil if the read fails or goes out of bounds.
func (er *elfReader) readAt(offset, length int64) []byte {
	if offset < 0 || length <= 0 {
		return nil
	}
	if er.size > 0 && offset+length > er.size {
		length = er.size - offset
		if length <= 0 {
			return nil
		}
	}
	buf := make([]byte, length)
	n, err := er.r.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return nil
	}
	return buf[:n]
}

// ELF constants
const (
	// ELF identification indices
	eiMAG0    = 0
	eiMAG1    = 1
	eiMAG2    = 2
	eiMAG3    = 3
	eiCLASS   = 4
	eiDATA    = 5
	eiNIDENT  = 16

	// ELF magic bytes
	elfMAG0 = 0x7f
	elfMAG1 = 'E'
	elfMAG2 = 'L'
	elfMAG3 = 'F'

	// ELF class
	elfCLASS32 = 1
	elfCLASS64 = 2

	// ELF data encoding
	elfDATA2LSB = 1
	elfDATA2MSB = 2

	// ELF file types
	etEXEC = 2
	etDYN  = 3

	// Program header types
	ptDYNAMIC = 2
	ptINTERP  = 3
	ptNOTE    = 4

	// Section header types
	shtSYMTAB = 2
	shtNOTE   = 7

	// Dynamic entry tags
	dtNULL    = 0
	dtNEEDED  = 1
	dtFLAGS1  = 0x6ffffffb

	// DF_1 flags
	df1PIE = 0x08000000

	// Note types
	ntGNUVersion = 1
	ntGNUBuildID = 3
	ntGoBuildID  = 4

	// GNU OS types
	gnuOSLinux    = 0
	gnuOSHurd     = 1
	gnuOSSolaris  = 2
	gnuOSKFreeBSD = 3
	gnuOSKNetBSD  = 4

	// Other note types
	ntFreeBSDVersion   = 1
	ntNetBSDVersion    = 1
	ntOpenBSDVersion   = 1
	ntDragonFlyVersion = 1
	ntAndroidVersion   = 1
)

// ELF header sizes
const (
	elf32EhdrSize = 52
	elf64EhdrSize = 64
	elf32PhdrSize = 32
	elf64PhdrSize = 56
	elf32ShdrSize = 40
	elf64ShdrSize = 64
	elfNhdrSize   = 12 // same for 32-bit and 64-bit
	elf32DynSize  = 8
	elf64DynSize  = 16
)

// elfInfo holds the extracted ELF information.
type elfInfo struct {
	linkType    string   // "dynamically linked", "statically linked", "static-pie linked"
	interp      string
	notes       []string // collected in order (OS note, BuildID, Go BuildID, etc.)
	hasOSNote   bool
	hasBuildID  bool
	hasGoBuildID bool
	stripped    bool
	hasDebug    bool
	isPIE       bool // for varexpand ${x?...}
}

// tryELF checks if buf is an ELF file and extracts detailed information.
// buf is the initial file buffer (for magic identification check).
// If r is non-nil, it's used for reading data at arbitrary offsets (for large files).
func tryELF(buf []byte, r io.ReaderAt, fileSize int64) *elfInfo {
	if len(buf) < eiNIDENT {
		return nil
	}
	if buf[eiMAG0] != elfMAG0 || buf[eiMAG1] != elfMAG1 ||
		buf[eiMAG2] != elfMAG2 || buf[eiMAG3] != elfMAG3 {
		return nil
	}

	class := buf[eiCLASS]
	if class != elfCLASS32 && class != elfCLASS64 {
		return nil
	}

	dataEnc := buf[eiDATA]
	var bo binary.ByteOrder
	switch dataEnc {
	case elfDATA2LSB:
		bo = binary.LittleEndian
	case elfDATA2MSB:
		bo = binary.BigEndian
	default:
		return nil
	}

	is64 := class == elfCLASS64

	// Parse ELF header
	ehdrSize := elf32EhdrSize
	if is64 {
		ehdrSize = elf64EhdrSize
	}
	if len(buf) < ehdrSize {
		return nil
	}

	// Set up elfReader for arbitrary offset reads
	er := &elfReader{size: fileSize}
	if r != nil {
		er.r = r
	} else {
		er.r = newBytesReaderAt(buf)
		er.size = int64(len(buf))
	}

	var eType, phEntSize, phNum, shEntSize, shNum, shStrNdx uint16
	var phOff, shOff uint64

	eType = bo.Uint16(buf[16:])
	if is64 {
		phOff = bo.Uint64(buf[32:])
		shOff = bo.Uint64(buf[40:])
		phEntSize = bo.Uint16(buf[54:])
		phNum = bo.Uint16(buf[56:])
		shEntSize = bo.Uint16(buf[58:])
		shNum = bo.Uint16(buf[60:])
		shStrNdx = bo.Uint16(buf[62:])
	} else {
		phOff = uint64(bo.Uint32(buf[28:]))
		shOff = uint64(bo.Uint32(buf[32:]))
		phEntSize = bo.Uint16(buf[42:])
		phNum = bo.Uint16(buf[44:])
		shEntSize = bo.Uint16(buf[46:])
		shNum = bo.Uint16(buf[48:])
		shStrNdx = bo.Uint16(buf[50:])
	}

	info := &elfInfo{stripped: true}

	switch eType {
	case etEXEC, etDYN:
		processPhdr(er, bo, is64, phOff, phEntSize, phNum, shNum > 0, info)
		processSections(er, bo, is64, shOff, shEntSize, shNum, shStrNdx, info)
	default:
		return nil // Only handle executables and shared objects
	}

	return info
}

// bytesReaderAt wraps a byte slice to implement io.ReaderAt.
type bytesReaderAt struct {
	data []byte
}

func newBytesReaderAt(data []byte) *bytesReaderAt {
	return &bytesReaderAt{data: data}
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n = copy(p, b.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}

// processPhdr processes program headers (PT_DYNAMIC, PT_INTERP, PT_NOTE).
func processPhdr(er *elfReader, bo binary.ByteOrder, is64 bool, phOff uint64, phEntSize, phNum uint16, hasSections bool, info *elfInfo) {
	dynamic := false
	pie := false
	var needCount int

	expectedSize := elf32PhdrSize
	if is64 {
		expectedSize = elf64PhdrSize
	}
	if int(phEntSize) < expectedSize {
		return
	}

	for i := 0; i < int(phNum); i++ {
		off := int64(phOff) + int64(i)*int64(phEntSize)
		phdrData := er.readAt(off, int64(expectedSize))
		if len(phdrData) < expectedSize {
			break
		}

		var pType uint32
		var pOffset, pFilesz uint64

		if is64 {
			pType = bo.Uint32(phdrData[0:])
			pOffset = bo.Uint64(phdrData[8:])
			pFilesz = bo.Uint64(phdrData[32:])
		} else {
			pType = bo.Uint32(phdrData[0:])
			pOffset = uint64(bo.Uint32(phdrData[4:]))
			pFilesz = uint64(bo.Uint32(phdrData[16:]))
		}

		switch pType {
		case ptDYNAMIC:
			dynamic = true
			dynData := er.readAt(int64(pOffset), int64(pFilesz))
			if dynData != nil {
				processDynamic(dynData, bo, is64, &pie, &needCount)
			}

		case ptINTERP:
			if pFilesz > 0 && pFilesz < 4096 {
				interpData := er.readAt(int64(pOffset), int64(pFilesz))
				if interpData != nil {
					if idx := indexOf(interpData, 0); idx >= 0 {
						interpData = interpData[:idx]
					}
					info.interp = string(interpData)
				}
			}

		case ptNOTE:
			if hasSections {
				continue // prefer section headers for notes
			}
			noteData := er.readAt(int64(pOffset), int64(pFilesz))
			if noteData != nil {
				processNotes(noteData, bo, info)
			}
		}
	}

	if dynamic {
		if pie && needCount == 0 {
			info.linkType = "static-pie linked"
		} else {
			info.linkType = "dynamically linked"
		}
	} else {
		info.linkType = "statically linked"
	}

	info.isPIE = pie
}

// processDynamic processes dynamic section entries from a data buffer.
func processDynamic(data []byte, bo binary.ByteOrder, is64 bool, pie *bool, needCount *int) {
	entSize := elf32DynSize
	if is64 {
		entSize = elf64DynSize
	}

	for off := 0; off+entSize <= len(data); off += entSize {
		var tag, val uint64
		if is64 {
			tag = bo.Uint64(data[off:])
			val = bo.Uint64(data[off+8:])
		} else {
			tag = uint64(bo.Uint32(data[off:]))
			val = uint64(bo.Uint32(data[off+4:]))
		}

		if tag == dtNULL {
			break
		}

		switch tag {
		case dtFLAGS1:
			if val&df1PIE != 0 {
				*pie = true
			}
		case dtNEEDED:
			*needCount++
		}
	}
}

// processSections processes section headers for notes, symtab, and debug info.
func processSections(er *elfReader, bo binary.ByteOrder, is64 bool, shOff uint64, shEntSize, shNum, shStrNdx uint16, info *elfInfo) {
	entSize := elf32ShdrSize
	if is64 {
		entSize = elf64ShdrSize
	}
	if int(shEntSize) < entSize {
		return
	}
	if shNum == 0 {
		return
	}

	// Read the string table section header to get name_off
	var nameOff uint64
	if int(shStrNdx) < int(shNum) {
		strTabOff := int64(shOff) + int64(shStrNdx)*int64(shEntSize)
		strTabData := er.readAt(strTabOff, int64(entSize))
		if len(strTabData) >= entSize {
			if is64 {
				nameOff = bo.Uint64(strTabData[24:]) // sh_offset
			} else {
				nameOff = uint64(bo.Uint32(strTabData[16:])) // sh_offset
			}
		}
	}

	for i := 0; i < int(shNum); i++ {
		off := int64(shOff) + int64(i)*int64(shEntSize)
		shdrData := er.readAt(off, int64(entSize))
		if len(shdrData) < entSize {
			break
		}

		var shType uint32
		var shOffset, shSize uint64
		var shName uint32

		if is64 {
			shName = bo.Uint32(shdrData[0:])
			shType = bo.Uint32(shdrData[4:])
			shOffset = bo.Uint64(shdrData[24:])
			shSize = bo.Uint64(shdrData[32:])
		} else {
			shName = bo.Uint32(shdrData[0:])
			shType = bo.Uint32(shdrData[4:])
			shOffset = uint64(bo.Uint32(shdrData[16:]))
			shSize = uint64(bo.Uint32(shdrData[20:]))
		}

		// Check section name for .debug_info
		if nameOff > 0 {
			nameData := er.readAt(int64(nameOff)+int64(shName), 50)
			if nameData != nil {
				name := readCStringBytes(nameData)
				if name == ".debug_info" {
					info.hasDebug = true
					info.stripped = false
				}
			}
		}

		switch shType {
		case shtSYMTAB:
			info.stripped = false

		case shtNOTE:
			if shSize > 0 && shSize < 1024*1024 {
				noteData := er.readAt(int64(shOffset), int64(shSize))
				if noteData != nil {
					processNotes(noteData, bo, info)
				}
			}
		}
	}
}

// processNotes parses NOTE segments/sections.
func processNotes(data []byte, bo binary.ByteOrder, info *elfInfo) {
	offset := 0
	for offset+elfNhdrSize <= len(data) {
		namesz := bo.Uint32(data[offset:])
		descsz := bo.Uint32(data[offset+4:])
		ntype := bo.Uint32(data[offset+8:])
		offset += elfNhdrSize

		if namesz == 0 && descsz == 0 {
			break
		}
		if namesz > 0x8000 || descsz > 0x8000 {
			break
		}

		noff := offset
		doff := alignUp(offset+int(namesz), 4)
		nextOff := alignUp(doff+int(descsz), 4)

		if doff+int(descsz) > len(data) {
			break
		}

		name := ""
		if int(namesz) > 0 && noff+int(namesz) <= len(data) {
			n := data[noff : noff+int(namesz)]
			// Strip all trailing nulls (e.g., "Go\0\0" → "Go")
			for len(n) > 0 && n[len(n)-1] == 0 {
				n = n[:len(n)-1]
			}
			name = string(n)
		}

		// OS note
		if !info.hasOSNote {
			if s := parseOSNote(name, ntype, data, doff, int(descsz), bo); s != "" {
				info.notes = append(info.notes, s)
				info.hasOSNote = true
			}
		}

		// Build ID note
		if !info.hasBuildID {
			if s := parseBuildIDNote(name, ntype, data, doff, int(descsz)); s != "" {
				info.notes = append(info.notes, s)
				info.hasBuildID = true
			}
		}

		// Go Build ID note
		if !info.hasGoBuildID {
			if s := parseGoBuildIDNote(name, ntype, data, doff, int(descsz)); s != "" {
				info.notes = append(info.notes, s)
				info.hasGoBuildID = true
			}
		}

		offset = nextOff
	}
}

// parseOSNote parses a GNU version note.
func parseOSNote(name string, ntype uint32, data []byte, doff, descsz int, bo binary.ByteOrder) string {
	if name == "GNU" && ntype == ntGNUVersion && descsz == 16 {
		osType := bo.Uint32(data[doff:])
		major := bo.Uint32(data[doff+4:])
		minor := bo.Uint32(data[doff+8:])
		patch := bo.Uint32(data[doff+12:])

		var osName string
		switch osType {
		case gnuOSLinux:
			osName = "Linux"
		case gnuOSHurd:
			osName = "Hurd"
		case gnuOSSolaris:
			osName = "Solaris"
		case gnuOSKFreeBSD:
			osName = "kFreeBSD"
		case gnuOSKNetBSD:
			osName = "kNetBSD"
		default:
			osName = "<unknown>"
		}
		return fmt.Sprintf("for GNU/%s %d.%d.%d", osName, major, minor, patch)
	}

	if name == "FreeBSD" && ntype == ntFreeBSDVersion && descsz == 4 {
		return "for FreeBSD"
	}
	if name == "NetBSD" && ntype == ntNetBSDVersion && descsz == 4 {
		return "for NetBSD"
	}
	if name == "OpenBSD" && ntype == ntOpenBSDVersion && descsz == 4 {
		return "for OpenBSD"
	}
	if name == "DragonFly" && ntype == ntDragonFlyVersion && descsz == 4 {
		desc := bo.Uint32(data[doff:])
		return fmt.Sprintf("for DragonFly %d.%d.%d", desc/100000, desc/10000%10, desc%10000)
	}
	if name == "Android" && ntype == ntAndroidVersion && descsz >= 4 {
		apiLevel := bo.Uint32(data[doff:])
		return fmt.Sprintf("for Android %d", apiLevel)
	}

	return ""
}

// parseBuildIDNote parses a GNU Build ID note.
func parseBuildIDNote(name string, ntype uint32, data []byte, doff, descsz int) string {
	if name != "GNU" || ntype != ntGNUBuildID || descsz < 4 || descsz > 20 {
		return ""
	}

	var btype string
	switch descsz {
	case 8:
		btype = "xxHash"
	case 16:
		btype = "md5/uuid"
	case 20:
		btype = "sha1"
	default:
		btype = "unknown"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "BuildID[%s]=", btype)
	for i := 0; i < descsz; i++ {
		fmt.Fprintf(&sb, "%02x", data[doff+i])
	}
	return sb.String()
}

// parseGoBuildIDNote parses a Go Build ID note.
func parseGoBuildIDNote(name string, ntype uint32, data []byte, doff, descsz int) string {
	// Go notes have namesz=4 (including padding) and name "Go\0\0"
	if name != "Go" || ntype != ntGoBuildID || descsz >= 128 || descsz == 0 {
		return ""
	}

	desc := data[doff : doff+descsz]
	// Trim trailing null
	if idx := indexOf(desc, 0); idx >= 0 {
		desc = desc[:idx]
	}
	return "Go BuildID=" + string(desc)
}

// formatELFInfo formats the elfInfo into an appendable string.
func formatELFInfo(info *elfInfo) string {
	var parts []string

	if info.linkType != "" {
		parts = append(parts, info.linkType)
	}
	if info.interp != "" {
		parts = append(parts, "interpreter "+info.interp)
	}
	// Notes are already in the order they were found in the ELF file
	parts = append(parts, info.notes...)

	if info.hasDebug {
		if info.stripped {
			parts = append(parts, "with debug_info", "stripped")
		} else {
			parts = append(parts, "with debug_info", "not stripped")
		}
	} else if info.stripped {
		parts = append(parts, "stripped")
	} else {
		parts = append(parts, "not stripped")
	}

	return strings.Join(parts, ", ")
}

// Helper functions

func indexOf(b []byte, v byte) int {
	for i, c := range b {
		if c == v {
			return i
		}
	}
	return -1
}

func alignUp(n, align int) int {
	return (n + align - 1) &^ (align - 1)
}

func readCStringBytes(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
