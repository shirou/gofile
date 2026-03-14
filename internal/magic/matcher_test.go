package magic

import (
	"os"
	"testing"
)

func TestMatch_SimplePDF(t *testing.T) {
	entries, _ := ParseMagicBytes("test", []byte(`
0	string	%PDF-	PDF document
!:mime	application/pdf
>5	byte	x	\b, version %c
`))
	set := &MagicSet{
		Entries:    entries,
		NamedRules: make(map[string]int),
	}
	buf := []byte("%PDF-1.4 some content here")
	m := NewMatcher(set)
	result := m.Match(buf)
	if result == "" {
		t.Fatal("expected match, got empty string")
	}
	expected := "PDF document, version 1"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestMatch_PNG(t *testing.T) {
	entries, _ := ParseMagicBytes("test", []byte(`
0	string	\x89PNG\x0d\x0a\x1a\x0a	PNG image data,
!:mime	image/png
`))
	set := &MagicSet{
		Entries:    entries,
		NamedRules: make(map[string]int),
	}
	buf := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0}
	m := NewMatcher(set)
	result := m.Match(buf)
	if result != "PNG image data," {
		t.Errorf("got %q, want %q", result, "PNG image data,")
	}
}

func TestMatch_NoMatch(t *testing.T) {
	entries, _ := ParseMagicBytes("test", []byte(`
0	string	%PDF-	PDF document
`))
	set := &MagicSet{
		Entries:    entries,
		NamedRules: make(map[string]int),
	}
	buf := []byte("This is not a PDF")
	m := NewMatcher(set)
	result := m.Match(buf)
	// Falls back to encoding detection since no magic match
	if result != "ASCII text, with no line terminators" {
		t.Errorf("got %q, want %q", result, "ASCII text, with no line terminators")
	}
}

func TestMatch_NumericBELong(t *testing.T) {
	entries, _ := ParseMagicBytes("test", []byte(`
0	belong	0xcafebabe	Java class file
`))
	set := &MagicSet{
		Entries:    entries,
		NamedRules: make(map[string]int),
	}
	buf := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00}
	m := NewMatcher(set)
	result := m.Match(buf)
	if result != "Java class file" {
		t.Errorf("got %q, want %q", result, "Java class file")
	}
}

func TestMatch_LELongHex(t *testing.T) {
	// Simulating zstd v0.2: 0 lelong 0xFD2FB522
	entries, _ := ParseMagicBytes("test", []byte(`
0	lelong	0xFD2FB522	Zstandard compressed data (v0.2)
`))
	set := &MagicSet{Entries: entries, NamedRules: make(map[string]int)}
	buf := []byte{0x22, 0xB5, 0x2F, 0xFD, 0xFF, 0x01}
	m := NewMatcher(set)
	result := m.Match(buf)
	if result != "Zstandard compressed data (v0.2)" {
		t.Errorf("got %q, want %q", result, "Zstandard compressed data (v0.2)")
	}
}

func TestMatch_ContinuationWithFormat(t *testing.T) {
	entries, _ := ParseMagicBytes("test", []byte(`
0	string	PK\003\004	Zip archive data
>4	leshort	x	\b, at least v%d to extract
`))
	set := &MagicSet{
		Entries:    entries,
		NamedRules: make(map[string]int),
	}
	// PK\x03\x04 followed by version 20 (0x14) in little-endian
	buf := []byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00}
	m := NewMatcher(set)
	result := m.Match(buf)
	expected := "Zip archive data, at least v20 to extract"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestVarexpand(t *testing.T) {
	tests := []struct {
		desc       string
		mode       os.FileMode
		wantResult string
	}{
		{
			desc:       "${x?pie executable:shared object},",
			mode:       0755, // executable
			wantResult: "pie executable,",
		},
		{
			desc:       "${x?pie executable:shared object},",
			mode:       0644, // not executable
			wantResult: "shared object,",
		},
		{
			desc:       "no variables here",
			mode:       0755,
			wantResult: "no variables here",
		},
		{
			desc:       "prefix ${x?exec:lib} suffix",
			mode:       0100, // executable
			wantResult: "prefix exec suffix",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := varexpand(tt.desc, tt.mode)
			if got != tt.wantResult {
				t.Errorf("varexpand(%q, 0%o) = %q, want %q", tt.desc, tt.mode, got, tt.wantResult)
			}
		})
	}
}
