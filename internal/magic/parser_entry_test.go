package magic

import (
	"testing"
	"unsafe"
)

func TestMagicEntrySize(t *testing.T) {
	// Calculate actual size of MagicEntry struct
	actualSize := unsafe.Sizeof(MagicEntry{})
	
	t.Logf("Actual MagicEntry size: %d bytes", actualSize)
	
	// Calculate expected size based on fields
	var expectedSize uintptr
	
	// Core fields
	expectedSize += unsafe.Sizeof(uint16(0))  // Flag
	expectedSize += unsafe.Sizeof(uint8(0))   // ContLevel
	expectedSize += unsafe.Sizeof(uint8(0))   // Factor
	expectedSize += unsafe.Sizeof(uint8(0))   // Reln
	expectedSize += unsafe.Sizeof(uint8(0))   // Vallen
	expectedSize += unsafe.Sizeof(uint8(0))   // Type
	expectedSize += unsafe.Sizeof(uint8(0))   // InType
	expectedSize += unsafe.Sizeof(uint8(0))   // InOp
	expectedSize += unsafe.Sizeof(uint8(0))   // MaskOp
	expectedSize += unsafe.Sizeof(uint8(0))   // Cond
	expectedSize += unsafe.Sizeof(uint8(0))   // FactorOp
	expectedSize += unsafe.Sizeof(int32(0))   // Offset
	expectedSize += unsafe.Sizeof(int32(0))   // InOffset
	expectedSize += unsafe.Sizeof(uint32(0))  // Lineno
	expectedSize += unsafe.Sizeof(uint64(0))  // NumMask
	
	t.Logf("Core fields size: %d bytes", expectedSize)
	
	// Text fields
	expectedSize += 64  // Desc
	expectedSize += 64  // Value
	expectedSize += 8   // Apple
	expectedSize += 80  // MimeType
	expectedSize += 64  // Ext
	expectedSize += 64  // Padding
	
	t.Logf("Expected total size: %d bytes", expectedSize)
	
	// Check field offsets
	entry := &MagicEntry{}
	
	flagOffset := unsafe.Offsetof(entry.Flag)
	descOffset := unsafe.Offsetof(entry.Desc)
	valueOffset := unsafe.Offsetof(entry.Value)
	appleOffset := unsafe.Offsetof(entry.Apple)
	mimeOffset := unsafe.Offsetof(entry.MimeType)
	extOffset := unsafe.Offsetof(entry.Ext)
	
	t.Logf("Field offsets:")
	t.Logf("  Flag:     %d", flagOffset)
	t.Logf("  Desc:     %d (expected 32)", descOffset)
	t.Logf("  Value:    %d (expected 96)", valueOffset)
	t.Logf("  Apple:    %d (expected 160)", appleOffset)
	t.Logf("  MimeType: %d (expected 168)", mimeOffset)
	t.Logf("  Ext:      %d (expected 248)", extOffset)
	
	// The actual struct size should be 376 bytes for version 18
	if actualSize != 376 {
		t.Errorf("MagicEntry size is %d, expected 376", actualSize)
	}
	
	// Verify critical offsets
	if descOffset != 32 {
		t.Errorf("Desc offset is %d, expected 32", descOffset)
	}
}

// Test parsing a known PNG magic entry
func TestParsePNGEntry(t *testing.T) {
	// Create a mock PNG magic entry
	// PNG signature: 89 50 4E 47 0D 0A 1A 0A
	entry := &MagicEntry{
		Type:   FILE_STRING,
		Offset: 0,
		Value:  [96]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		Desc:   [64]byte{'P', 'N', 'G', ' ', 'i', 'm', 'a', 'g', 'e', ' ', 'd', 'a', 't', 'a'},
	}
	
	desc := entry.GetDescription()
	t.Logf("PNG description: %q", desc)
	
	if desc != "PNG image data" {
		t.Errorf("Expected 'PNG image data', got %q", desc)
	}
}