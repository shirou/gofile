package magic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParser_ParseFile(t *testing.T) {
	// Find test magic file
	magicFile := findTestMagicFile(t)
	
	parser := NewParser()
	db, err := parser.ParseFile(magicFile)
	if err != nil {
		t.Fatalf("Failed to parse magic file: %v", err)
	}
	
	// Basic validation
	if db == nil {
		t.Fatal("Database is nil")
	}
	
	if db.Version < MIN_VERSION || db.Version > VERSIONNO {
		t.Errorf("Expected version in range %d-%d, got %d", MIN_VERSION, VERSIONNO, db.Version)
	}
	
	// Check that we have entries
	totalEntries := uint32(0)
	for i := 0; i < MAGIC_SETS; i++ {
		totalEntries += db.NMagic[i]
		if len(db.Magic[i]) != int(db.NMagic[i]) {
			t.Errorf("Set %d: expected %d entries, got %d", 
				i, db.NMagic[i], len(db.Magic[i]))
		}
	}
	
	if totalEntries == 0 {
		t.Error("No magic entries found")
	}
	
	t.Logf("Successfully parsed magic database with %d total entries", totalEntries)
}

func TestParser_ParseHeader(t *testing.T) {
	magicFile := findTestMagicFile(t)
	
	file, err := os.Open(magicFile)
	if err != nil {
		t.Fatalf("Failed to open magic file: %v", err)
	}
	defer file.Close()
	
	// Read first 16 bytes (header size)
	headerData := make([]byte, 16)
	_, err = file.Read(headerData)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}
	
	parser := NewParser()
	header, err := parser.parseHeader(headerData)
	if err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}
	
	if header.Magic != MAGICNO {
		t.Errorf("Expected magic number 0x%08x, got 0x%08x", MAGICNO, header.Magic)
	}
	
	if header.Version < MIN_VERSION || header.Version > VERSIONNO {
		t.Errorf("Expected version in range %d-%d, got %d", MIN_VERSION, VERSIONNO, header.Version)
	}
	
	t.Logf("Header: Magic=0x%08x, Version=%d, NMagic=%v", 
		header.Magic, header.Version, header.NMagic)
}

func TestMagicEntry_Methods(t *testing.T) {
	// Create a test entry
	entry := &MagicEntry{
		Type:   FILE_STRING,
		Offset: 0,
	}
	
	// Set description
	desc := "Test description"
	copy(entry.Desc[:], desc)
	
	// Set MIME type
	mime := "text/plain"
	copy(entry.MimeType[:], mime)
	
	// Set value
	value := "test"
	copy(entry.Value[:], value)
	
	// Test methods
	if entry.GetDescription() != desc {
		t.Errorf("Expected description %s, got %s", desc, entry.GetDescription())
	}
	
	if entry.GetMimeType() != mime {
		t.Errorf("Expected MIME type %s, got %s", mime, entry.GetMimeType())
	}
	
	if !entry.IsString() {
		t.Error("Expected entry to be string type")
	}
	
	if entry.GetValueAsString() != value {
		t.Errorf("Expected value %s, got %s", value, entry.GetValueAsString())
	}
}

func TestMagicEntry_NumericTypes(t *testing.T) {
	entry := &MagicEntry{
		Type: FILE_LONG,
	}
	
	// Set a numeric value
	testValue := uint64(0x12345678)
	for i := 0; i < 8; i++ {
		entry.Value[i] = byte(testValue >> (i * 8))
	}
	
	if entry.IsString() {
		t.Error("Expected entry to be numeric type")
	}
	
	if entry.GetValueAsUint64() != testValue {
		t.Errorf("Expected value %d, got %d", testValue, entry.GetValueAsUint64())
	}
}

func TestDatabase_Load(t *testing.T) {
	magicFile := findTestMagicFile(t)
	
	db := NewDatabase()
	err := db.Load(magicFile)
	if err != nil {
		t.Fatalf("Failed to load database: %v", err)
	}
	
	if !db.IsLoaded() {
		t.Error("Database should be loaded")
	}
	
	stats := db.Stats()
	if stats.TotalEntries == 0 {
		t.Error("No entries loaded")
	}
	
	t.Logf("Database stats: %s", stats.String())
}

func TestDatabase_GetEntries(t *testing.T) {
	magicFile := findTestMagicFile(t)
	
	db := NewDatabase()
	err := db.Load(magicFile)
	if err != nil {
		t.Fatalf("Failed to load database: %v", err)
	}
	
	// Test getting entries by set
	for set := 0; set < MAGIC_SETS; set++ {
		entries := db.GetEntriesForSet(set)
		if len(entries) != int(db.GetDatabase().NMagic[set]) {
			t.Errorf("Set %d: expected %d entries, got %d", 
				set, db.GetDatabase().NMagic[set], len(entries))
		}
	}
	
	// Test getting all entries
	allEntries := db.GetEntries()
	expectedTotal := uint32(0)
	for i := 0; i < MAGIC_SETS; i++ {
		expectedTotal += db.GetDatabase().NMagic[i]
	}
	
	if len(allEntries) != int(expectedTotal) {
		t.Errorf("Expected %d total entries, got %d", expectedTotal, len(allEntries))
	}
}

func TestDatabase_GetEntriesByType(t *testing.T) {
	magicFile := findTestMagicFile(t)
	
	db := NewDatabase()
	err := db.Load(magicFile)
	if err != nil {
		t.Fatalf("Failed to load database: %v", err)
	}
	
	// Test getting entries by type
	stringEntries := db.GetEntriesByType(FILE_STRING)
	t.Logf("Found %d FILE_STRING entries", len(stringEntries))
	
	// Verify all returned entries are of the correct type
	for _, entry := range stringEntries {
		if entry.Type != FILE_STRING {
			t.Errorf("Expected type %d, got %d", FILE_STRING, entry.Type)
		}
	}
}

// findTestMagicFile finds the test magic file
func findTestMagicFile(t *testing.T) string {
	// Try to find project root
	wd, _ := os.Getwd()
	
	// Look for magic file in test data
	candidates := []string{
		filepath.Join(wd, "..", "..", "test", "testdata", "magic", "magic.mgc"),
		filepath.Join(wd, "..", "..", "..", "test", "testdata", "magic", "magic.mgc"),
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc",
	}
	
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	
	t.Fatalf("Test magic file not found. Run 'make setup-test' first.")
	return ""
}

// Benchmark tests
func BenchmarkParser_ParseFile(b *testing.B) {
	magicFile := findTestMagicFile(&testing.T{})
	parser := NewParser()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseFile(magicFile)
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

func BenchmarkDatabase_Load(b *testing.B) {
	magicFile := findTestMagicFile(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db := NewDatabase()
		err := db.Load(magicFile)
		if err != nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}
