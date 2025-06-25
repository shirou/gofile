package magic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLine_SimpleString(t *testing.T) {
	entry, err := parseLine("0\tstring\t%PDF-\tPDF document", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ContLevel != 0 {
		t.Errorf("ContLevel = %d, want 0", entry.ContLevel)
	}
	if entry.Offset != 0 {
		t.Errorf("Offset = %d, want 0", entry.Offset)
	}
	if entry.Type != TypeString {
		t.Errorf("Type = %d, want TypeString(%d)", entry.Type, TypeString)
	}
	if entry.Relation != '=' {
		t.Errorf("Relation = %c, want =", entry.Relation)
	}
	if string(entry.Value.Str) != "%PDF-" {
		t.Errorf("Value.Str = %q, want %%PDF-", entry.Value.Str)
	}
	if entry.Desc != "PDF document" {
		t.Errorf("Desc = %q, want %q", entry.Desc, "PDF document")
	}
}

func TestParseLine_Continuation(t *testing.T) {
	// >5 byte x \b, version %c
	entry, err := parseLine(">5\tbyte\tx\t\\b, version %c", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ContLevel != 1 {
		t.Errorf("ContLevel = %d, want 1", entry.ContLevel)
	}
	if entry.Offset != 5 {
		t.Errorf("Offset = %d, want 5", entry.Offset)
	}
	if entry.Type != TypeByte {
		t.Errorf("Type = %d, want TypeByte(%d)", entry.Type, TypeByte)
	}
	if entry.Relation != 'x' {
		t.Errorf("Relation = %c, want x", entry.Relation)
	}
	if entry.Desc != "\\b, version %c" {
		t.Errorf("Desc = %q, want %q", entry.Desc, "\\b, version %c")
	}
}

func TestParseLine_NumericHex(t *testing.T) {
	// 0 belong 0x89504e47 PNG image data,
	entry, err := parseLine("0\tbelong\t0x89504e47\tPNG image data,", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Type != TypeBELong {
		t.Errorf("Type = %d, want TypeBELong(%d)", entry.Type, TypeBELong)
	}
	if entry.Relation != '=' {
		t.Errorf("Relation = %c, want =", entry.Relation)
	}
	if entry.Value.Numeric != 0x89504e47 {
		t.Errorf("Value.Numeric = 0x%x, want 0x89504e47", entry.Value.Numeric)
	}
}

func TestParseLine_UnsignedType(t *testing.T) {
	// >0 ubeshort >0x1F00
	entry, err := parseLine(">0\tubeshort\t>0x1F00", 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !entry.Unsigned {
		t.Error("Unsigned = false, want true")
	}
	if entry.Type != TypeBEShort {
		t.Errorf("Type = %d, want TypeBEShort(%d)", entry.Type, TypeBEShort)
	}
	if entry.Relation != '>' {
		t.Errorf("Relation = %c, want >", entry.Relation)
	}
	if entry.Value.Numeric != 0x1F00 {
		t.Errorf("Value.Numeric = 0x%x, want 0x1F00", entry.Value.Numeric)
	}
}

func TestParseLine_DeepContinuation(t *testing.T) {
	// >>>10 leshort 0x014c Intel 80386
	entry, err := parseLine(">>>10\tleshort\t0x014c\tIntel 80386", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ContLevel != 3 {
		t.Errorf("ContLevel = %d, want 3", entry.ContLevel)
	}
	if entry.Offset != 10 {
		t.Errorf("Offset = %d, want 10", entry.Offset)
	}
}

func TestParseLine_StringEscapes(t *testing.T) {
	// 0 string \x89PNG\x0d\x0a\x1a\x0a PNG
	entry, err := parseLine("0\tstring\t\\x89PNG\\x0d\\x0a\\x1a\\x0a\tPNG", 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if string(entry.Value.Str) != string(expected) {
		t.Errorf("Value.Str = %x, want %x", entry.Value.Str, expected)
	}
}

func TestParseLine_StringOctalEscape(t *testing.T) {
	entry, err := parseLine("0\tstring\tPK\\003\\004\tZip archive data", 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{'P', 'K', 0x03, 0x04}
	if string(entry.Value.Str) != string(expected) {
		t.Errorf("Value.Str = %x, want %x", entry.Value.Str, expected)
	}
}

func TestParseFile_PDFMagic(t *testing.T) {
	input := `# PDF
0	string	%PDF-	PDF document
!:mime	application/pdf
!:ext	pdf
>5	byte	x	\b, version %c
>6	byte	=.	\b.%c
`
	entries, err := ParseMagicBytes("pdf", []byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	// Top-level entry should have mime and ext from metadata
	if entries[0].MimeType != "application/pdf" {
		t.Errorf("MimeType = %q, want %q", entries[0].MimeType, "application/pdf")
	}
	if entries[0].Ext != "pdf" {
		t.Errorf("Ext = %q, want %q", entries[0].Ext, "pdf")
	}
	// Continuations
	if entries[1].ContLevel != 1 {
		t.Errorf("entries[1].ContLevel = %d, want 1", entries[1].ContLevel)
	}
	if entries[2].ContLevel != 1 {
		t.Errorf("entries[2].ContLevel = %d, want 1", entries[2].ContLevel)
	}
}

func TestParseMagicDir(t *testing.T) {
	magicDir := filepath.Join("magicdata", "Magdir")
	if _, err := os.Stat(magicDir); os.IsNotExist(err) {
		t.Skip("magicdata/Magdir not found")
	}
	set, err := ParseMagicDir(magicDir)
	if err != nil {
		t.Fatalf("ParseMagicDir failed: %v", err)
	}
	if len(set.Entries) == 0 {
		t.Fatal("no entries parsed from magic dir")
	}
	t.Logf("Parsed %d entries from magic dir", len(set.Entries))
}

func TestParseMagicDir_HasNamedRules(t *testing.T) {
	magicDir := filepath.Join("magicdata", "Magdir")
	if _, err := os.Stat(magicDir); os.IsNotExist(err) {
		t.Skip("magicdata/Magdir not found")
	}
	set, err := ParseMagicDir(magicDir)
	if err != nil {
		t.Fatalf("ParseMagicDir failed: %v", err)
	}
	if len(set.NamedRules) == 0 {
		t.Fatal("no named rules found")
	}
	t.Logf("Found %d named rules", len(set.NamedRules))
}
