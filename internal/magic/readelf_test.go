package magic

import (
	"encoding/binary"
	"testing"
)

func TestTryELF_NotELF(t *testing.T) {
	buf := []byte("not an ELF file at all")
	if info := tryELF(buf, nil, 0); info != nil {
		t.Errorf("expected nil for non-ELF, got %+v", info)
	}
}

func TestTryELF_TooShort(t *testing.T) {
	buf := []byte{0x7f, 'E', 'L'}
	if info := tryELF(buf, nil, 0); info != nil {
		t.Errorf("expected nil for short buffer, got %+v", info)
	}
}

// buildELF64 builds a minimal ELF 64-bit LSB executable/shared-object buffer.
func buildELF64(eType uint16, opts ...elfBuildOpt) []byte {
	bo := binary.LittleEndian

	// Compute sizes
	phEntries := 0
	shEntries := 0
	for _, o := range opts {
		switch o.kind {
		case optPhdr:
			phEntries++
		case optShdr:
			shEntries++
		}
	}

	ehdrSize := 64
	phdrStart := ehdrSize
	phdrSize := phEntries * elf64PhdrSize
	shdrStart := phdrStart + phdrSize
	// Add 1 for strtab section header
	totalShEntries := shEntries + 1 // +1 for null section
	if shEntries > 0 {
		totalShEntries++ // +1 for strtab
	}
	shdrSize := totalShEntries * elf64ShdrSize
	dataStart := shdrStart + shdrSize

	// Build string table and extra data
	var strTab []byte
	strTab = append(strTab, 0) // null entry
	sectionNames := make(map[int]uint32)

	// Pre-scan for section names
	for i, o := range opts {
		if o.kind == optShdr && o.name != "" {
			sectionNames[i] = uint32(len(strTab))
			strTab = append(strTab, []byte(o.name)...)
			strTab = append(strTab, 0)
		}
	}

	// We'll build the buffer incrementally
	buf := make([]byte, dataStart+4096) // generous space

	// ELF header
	buf[0] = 0x7f
	buf[1] = 'E'
	buf[2] = 'L'
	buf[3] = 'F'
	buf[4] = elfCLASS64
	buf[5] = elfDATA2LSB
	buf[6] = 1 // EV_CURRENT
	bo.PutUint16(buf[16:], eType)
	bo.PutUint16(buf[18:], 0x3E)  // EM_X86_64
	bo.PutUint32(buf[20:], 1)     // EV_CURRENT
	bo.PutUint64(buf[32:], uint64(phdrStart))
	bo.PutUint64(buf[40:], uint64(shdrStart))
	bo.PutUint16(buf[52:], 64) // e_ehsize
	bo.PutUint16(buf[54:], uint16(elf64PhdrSize))
	bo.PutUint16(buf[56:], uint16(phEntries))
	bo.PutUint16(buf[58:], uint16(elf64ShdrSize))
	bo.PutUint16(buf[60:], uint16(totalShEntries))
	// shstrndx = last section
	if shEntries > 0 {
		bo.PutUint16(buf[62:], uint16(totalShEntries-1))
	}

	// Place string table data after section headers
	strTabOff := dataStart
	copy(buf[strTabOff:], strTab)
	extraOff := strTabOff + len(strTab)

	// Program headers
	phIdx := 0
	for _, o := range opts {
		if o.kind != optPhdr {
			continue
		}
		off := phdrStart + phIdx*elf64PhdrSize

		// Write data to extraOff
		dataOff := extraOff
		copy(buf[dataOff:], o.data)
		extraOff += len(o.data)

		bo.PutUint32(buf[off:], o.phType)   // p_type
		bo.PutUint32(buf[off+4:], 0)        // p_flags
		bo.PutUint64(buf[off+8:], uint64(dataOff))  // p_offset
		bo.PutUint64(buf[off+16:], 0)       // p_vaddr
		bo.PutUint64(buf[off+24:], 0)       // p_paddr
		bo.PutUint64(buf[off+32:], uint64(len(o.data))) // p_filesz
		bo.PutUint64(buf[off+40:], uint64(len(o.data))) // p_memsz
		bo.PutUint64(buf[off+48:], 4)       // p_align
		phIdx++
	}

	// Section headers
	// First: null section header (all zeros, already zeroed)
	shIdx := 1
	for i, o := range opts {
		if o.kind != optShdr {
			continue
		}
		off := shdrStart + shIdx*elf64ShdrSize

		dataOff := extraOff
		copy(buf[dataOff:], o.data)
		extraOff += len(o.data)

		if nameOff, ok := sectionNames[i]; ok {
			bo.PutUint32(buf[off:], nameOff) // sh_name
		}
		bo.PutUint32(buf[off+4:], o.shType)          // sh_type
		bo.PutUint64(buf[off+24:], uint64(dataOff))   // sh_offset
		bo.PutUint64(buf[off+32:], uint64(len(o.data))) // sh_size
		shIdx++
	}

	// String table section header (last)
	if shEntries > 0 {
		off := shdrStart + shIdx*elf64ShdrSize
		bo.PutUint32(buf[off+4:], 3) // SHT_STRTAB
		bo.PutUint64(buf[off+24:], uint64(strTabOff))
		bo.PutUint64(buf[off+32:], uint64(len(strTab)))
	}

	return buf[:extraOff]
}

const (
	optPhdr = iota
	optShdr
)

type elfBuildOpt struct {
	kind   int
	phType uint32
	shType uint32
	name   string
	data   []byte
}

func withInterp(path string) elfBuildOpt {
	data := append([]byte(path), 0)
	return elfBuildOpt{kind: optPhdr, phType: ptINTERP, data: data}
}

func withDynamic(entries [][2]uint64) elfBuildOpt {
	bo := binary.LittleEndian
	data := make([]byte, len(entries)*elf64DynSize)
	for i, e := range entries {
		off := i * elf64DynSize
		bo.PutUint64(data[off:], e[0])
		bo.PutUint64(data[off+8:], e[1])
	}
	return elfBuildOpt{kind: optPhdr, phType: ptDYNAMIC, data: data}
}

func withNote(name string, ntype uint32, desc []byte) elfBuildOpt {
	return elfBuildOpt{kind: optPhdr, phType: ptNOTE, data: buildNote(name, ntype, desc)}
}

func withNoteSection(name string, ntype uint32, desc []byte) elfBuildOpt {
	return elfBuildOpt{kind: optShdr, shType: shtNOTE, data: buildNote(name, ntype, desc)}
}

func withSymtab() elfBuildOpt {
	return elfBuildOpt{kind: optShdr, shType: shtSYMTAB, data: make([]byte, 24)}
}

func withDebugInfo() elfBuildOpt {
	return elfBuildOpt{kind: optShdr, shType: 1, name: ".debug_info", data: make([]byte, 8)} // SHT_PROGBITS
}

func buildNote(name string, ntype uint32, desc []byte) []byte {
	bo := binary.LittleEndian
	nameBytes := append([]byte(name), 0)
	namesz := uint32(len(nameBytes))
	descsz := uint32(len(desc))

	var buf []byte
	// Note header
	hdr := make([]byte, 12)
	bo.PutUint32(hdr[0:], namesz)
	bo.PutUint32(hdr[4:], descsz)
	bo.PutUint32(hdr[8:], ntype)
	buf = append(buf, hdr...)
	buf = append(buf, nameBytes...)
	// Align to 4
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	buf = append(buf, desc...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func TestTryELF_DynamicallyLinked(t *testing.T) {
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{
			{dtNEEDED, 1},
			{dtFLAGS1, df1PIE},
			{dtNULL, 0},
		}),
		withInterp("/lib64/ld-linux-x86-64.so.2"),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if info.linkType != "dynamically linked" {
		t.Errorf("linkType = %q, want %q", info.linkType, "dynamically linked")
	}
	if info.interp != "/lib64/ld-linux-x86-64.so.2" {
		t.Errorf("interp = %q, want %q", info.interp, "/lib64/ld-linux-x86-64.so.2")
	}
	if !info.isPIE {
		t.Error("expected isPIE=true")
	}
}

func TestTryELF_StaticallyLinked(t *testing.T) {
	// No PT_DYNAMIC → statically linked
	buf := buildELF64(etEXEC)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if info.linkType != "statically linked" {
		t.Errorf("linkType = %q, want %q", info.linkType, "statically linked")
	}
}

func TestTryELF_StaticPIE(t *testing.T) {
	// PT_DYNAMIC with DF_1_PIE but no DT_NEEDED → static-pie
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{
			{dtFLAGS1, df1PIE},
			{dtNULL, 0},
		}),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if info.linkType != "static-pie linked" {
		t.Errorf("linkType = %q, want %q", info.linkType, "static-pie linked")
	}
}

func TestTryELF_GNUVersion(t *testing.T) {
	bo := binary.LittleEndian
	desc := make([]byte, 16)
	bo.PutUint32(desc[0:], gnuOSLinux)
	bo.PutUint32(desc[4:], 3)
	bo.PutUint32(desc[8:], 2)
	bo.PutUint32(desc[12:], 0)

	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{
			{dtNEEDED, 1},
			{dtNULL, 0},
		}),
		withNoteSection("GNU", ntGNUVersion, desc),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if !info.hasOSNote || len(info.notes) == 0 || info.notes[0] != "for GNU/Linux 3.2.0" {
		t.Errorf("notes = %v, want [for GNU/Linux 3.2.0]", info.notes)
	}
}

func TestTryELF_BuildID(t *testing.T) {
	desc := make([]byte, 20)
	for i := range desc {
		desc[i] = byte(i * 17)
	}
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{{dtNEEDED, 1}, {dtNULL, 0}}),
		withNoteSection("GNU", ntGNUBuildID, desc),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if !info.hasBuildID || len(info.notes) == 0 {
		t.Fatal("expected buildID note, got none")
	}
	found := false
	for _, n := range info.notes {
		if startsWith(n, "BuildID[sha1]=") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v, want BuildID[sha1]= prefix", info.notes)
	}
}

func TestTryELF_Stripped(t *testing.T) {
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{{dtNEEDED, 1}, {dtNULL, 0}}),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if !info.stripped {
		t.Error("expected stripped=true (no SHT_SYMTAB)")
	}
}

func TestTryELF_NotStripped(t *testing.T) {
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{{dtNEEDED, 1}, {dtNULL, 0}}),
		withSymtab(),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if info.stripped {
		t.Error("expected stripped=false (has SHT_SYMTAB)")
	}
}

func TestTryELF_DebugInfo(t *testing.T) {
	buf := buildELF64(etDYN,
		withDynamic([][2]uint64{{dtNEEDED, 1}, {dtNULL, 0}}),
		withDebugInfo(),
	)
	info := tryELF(buf, nil, 0)
	if info == nil {
		t.Fatal("expected ELF info, got nil")
	}
	if !info.hasDebug {
		t.Error("expected hasDebug=true")
	}
	if info.stripped {
		t.Error("expected stripped=false (has .debug_info)")
	}
}

func TestFormatELFInfo(t *testing.T) {
	info := &elfInfo{
		linkType: "dynamically linked",
		interp:   "/lib64/ld-linux-x86-64.so.2",
		notes: []string{
			"BuildID[sha1]=abcdef1234567890abcdef1234567890abcdef12",
			"for GNU/Linux 3.2.0",
		},
		stripped: true,
	}
	result := formatELFInfo(info)
	expected := "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=abcdef1234567890abcdef1234567890abcdef12, for GNU/Linux 3.2.0, stripped"
	if result != expected {
		t.Errorf("\ngot:  %q\nwant: %q", result, expected)
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
