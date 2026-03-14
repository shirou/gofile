package magic

import (
	"os"
	"testing"
)

func TestParseMgcHeader(t *testing.T) {
	// Build a minimal .mgc with 1 binary entry, 0 text entries.
	// Entry size = 376 bytes (version 18 format).
	const entrySize = 376

	// Header entry (first 376 bytes)
	header := make([]byte, entrySize)
	// h[0..3] = magic number (little-endian uint32 at byte 0)
	putLE32(header, 0, mgcMagicLE)
	// h[4..7] = version
	putLE32(header, 4, 18)
	// h[2] = binary test count (byte 8)
	putLE32(header, 8, 1)
	// h[3] = text test count (byte 12)
	putLE32(header, 12, 0)

	// One binary entry: string match at offset 0 for "%PDF-"
	entry := make([]byte, entrySize)
	// cont_level (uint16 LE) = 0
	entry[0] = 0
	entry[1] = 0
	// flag (uint8) = 0x20 (BINTEST)
	entry[2] = 0x20
	// factor (uint8) = 0
	entry[3] = 0
	// reln (uint8) = '='
	entry[4] = '='
	// vallen (uint8) = 5
	entry[5] = 5
	// type (uint8) = 5 (TypeString)
	entry[6] = 5
	// offset (int32 LE) = 0
	putLE32(entry, 12, 0)
	// lineno (uint32 LE) = 1
	putLE32(entry, 20, 1)
	// value: "%PDF-"
	copy(entry[32:], []byte("%PDF-"))
	// desc: "PDF document"
	copy(entry[160:], []byte("PDF document"))
	// mimetype: "application/pdf"
	copy(entry[224:], []byte("application/pdf"))

	data := append(header, entry...)

	hdr, err := parseMgcHeader(data)
	if err != nil {
		t.Fatalf("parseMgcHeader: %v", err)
	}
	if hdr.version != 18 {
		t.Errorf("version = %d, want 18", hdr.version)
	}
	if hdr.numBinary != 1 {
		t.Errorf("numBinary = %d, want 1", hdr.numBinary)
	}
	if hdr.numText != 0 {
		t.Errorf("numText = %d, want 0", hdr.numText)
	}
	if hdr.entrySize != entrySize {
		t.Errorf("entrySize = %d, want %d", hdr.entrySize, entrySize)
	}
}

func TestParseMgcEntries(t *testing.T) {
	const entrySize = 376

	header := make([]byte, entrySize)
	putLE32(header, 0, mgcMagicLE)
	putLE32(header, 4, 18)
	putLE32(header, 8, 1)
	putLE32(header, 12, 0)

	entry := make([]byte, entrySize)
	entry[0] = 0 // cont_level low
	entry[1] = 0 // cont_level high
	entry[2] = 0x20
	entry[4] = '='
	entry[5] = 5
	entry[6] = 5 // TypeString
	putLE32(entry, 12, 0)
	putLE32(entry, 20, 1)
	copy(entry[32:], []byte("%PDF-"))
	copy(entry[160:], []byte("PDF document"))
	copy(entry[224:], []byte("application/pdf"))

	data := append(header, entry...)

	set, err := ParseMgcBytes(data)
	if err != nil {
		t.Fatalf("ParseMgcBytes: %v", err)
	}
	if len(set.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(set.Entries))
	}

	e := set.Entries[0]
	if e.ContLevel != 0 {
		t.Errorf("ContLevel = %d, want 0", e.ContLevel)
	}
	if e.Type != TypeString {
		t.Errorf("Type = %d, want %d (TypeString)", e.Type, TypeString)
	}
	if e.Relation != '=' {
		t.Errorf("Relation = %d, want %d ('=')", e.Relation, '=')
	}
	if string(e.Value.Str) != "%PDF-" {
		t.Errorf("Value.Str = %q, want %%PDF-", e.Value.Str)
	}
	if e.Desc != "PDF document" {
		t.Errorf("Desc = %q, want %q", e.Desc, "PDF document")
	}
	if e.MimeType != "application/pdf" {
		t.Errorf("MimeType = %q, want %q", e.MimeType, "application/pdf")
	}
}

func TestParseMgcNumericEntry(t *testing.T) {
	const entrySize = 376

	header := make([]byte, entrySize)
	putLE32(header, 0, mgcMagicLE)
	putLE32(header, 4, 18)
	putLE32(header, 8, 1)
	putLE32(header, 12, 0)

	entry := make([]byte, entrySize)
	entry[4] = '='
	entry[6] = byte(TypeBELong)    // belong
	putLE32(entry, 12, 0)          // offset 0
	putLE32(entry, 20, 10)         // lineno
	putLE32(entry, 32, 0x89504E47) // value: PNG magic (LE stored)
	copy(entry[160:], []byte("PNG image data,"))
	copy(entry[224:], []byte("image/png"))

	data := append(header, entry...)
	set, err := ParseMgcBytes(data)
	if err != nil {
		t.Fatalf("ParseMgcBytes: %v", err)
	}
	if len(set.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(set.Entries))
	}

	e := set.Entries[0]
	if e.Type != TypeBELong {
		t.Errorf("Type = %d, want %d (TypeBELong)", e.Type, TypeBELong)
	}
	if e.Value.Numeric != 0x89504E47 {
		t.Errorf("Value.Numeric = 0x%x, want 0x89504E47", e.Value.Numeric)
	}
}

func TestParseMgcWithContinuations(t *testing.T) {
	const entrySize = 376

	header := make([]byte, entrySize)
	putLE32(header, 0, mgcMagicLE)
	putLE32(header, 4, 18)
	putLE32(header, 8, 3) // 3 binary entries
	putLE32(header, 12, 0)

	// Entry 0: top-level (cont_level=0)
	e0 := make([]byte, entrySize)
	e0[4] = '='
	e0[5] = 5
	e0[6] = byte(TypeString)
	copy(e0[32:], []byte("%PDF-"))
	copy(e0[160:], []byte("PDF document"))

	// Entry 1: continuation (cont_level=1)
	e1 := make([]byte, entrySize)
	e1[0] = 1 // cont_level = 1
	e1[4] = 'x'
	e1[6] = byte(TypeByte)
	putLE32(e1, 12, 5) // offset 5
	copy(e1[160:], []byte(`\b, version %c`))

	// Entry 2: continuation (cont_level=1)
	e2 := make([]byte, entrySize)
	e2[0] = 1
	e2[4] = 'x'
	e2[6] = byte(TypeByte)
	putLE32(e2, 12, 7) // offset 7
	copy(e2[160:], []byte(`\b.%c`))

	data := append(header, e0...)
	data = append(data, e1...)
	data = append(data, e2...)

	set, err := ParseMgcBytes(data)
	if err != nil {
		t.Fatalf("ParseMgcBytes: %v", err)
	}
	if len(set.Entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(set.Entries))
	}
	if set.Entries[0].ContLevel != 0 {
		t.Errorf("entry[0].ContLevel = %d, want 0", set.Entries[0].ContLevel)
	}
	if set.Entries[1].ContLevel != 1 {
		t.Errorf("entry[1].ContLevel = %d, want 1", set.Entries[1].ContLevel)
	}
	if set.Entries[2].ContLevel != 1 {
		t.Errorf("entry[2].ContLevel = %d, want 1", set.Entries[2].ContLevel)
	}
}

func TestParseMgcSystemFile(t *testing.T) {
	// Test with real system .mgc file if available
	paths := []string{
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc",
		"/usr/share/file/magic.mgc",
	}
	var mgcPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			mgcPath = p
			break
		}
	}
	if mgcPath == "" {
		t.Skip("no system magic.mgc found")
	}

	set, err := ParseMgcFile(mgcPath)
	if err != nil {
		t.Fatalf("ParseMgcFile(%s): %v", mgcPath, err)
	}
	if len(set.Entries) == 0 {
		t.Fatal("no entries parsed from system mgc")
	}
	t.Logf("parsed %d entries from %s", len(set.Entries), mgcPath)

	// Verify groups were built
	if len(set.Groups) == 0 {
		t.Error("no groups built")
	}
	t.Logf("built %d groups", len(set.Groups))
}

func TestNewFromMgcFile(t *testing.T) {
	paths := []string{
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc",
	}
	var mgcPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			mgcPath = p
			break
		}
	}
	if mgcPath == "" {
		t.Skip("no system magic.mgc found")
	}

	fi, err := NewFromMgcFile(mgcPath, Options{})
	if err != nil {
		t.Fatalf("NewFromMgcFile: %v", err)
	}

	// Test identifying a known format
	pdfHeader := []byte("%PDF-1.4 test")
	result := fi.IdentifyBuffer(pdfHeader)
	if result == "" || result == "data" {
		t.Errorf("failed to identify PDF: got %q", result)
	}
	t.Logf("PDF identification: %s", result)
}

func putLE32(buf []byte, offset int, val uint32) {
	buf[offset] = byte(val)
	buf[offset+1] = byte(val >> 8)
	buf[offset+2] = byte(val >> 16)
	buf[offset+3] = byte(val >> 24)
}
