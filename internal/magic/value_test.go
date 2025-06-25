package magic

import (
	"testing"
)

func TestExtractValue_Byte(t *testing.T) {
	buf := []byte{0x00, 0x42, 0xFF}
	entry := &MagicEntry{Type: TypeByte, Offset: 1}
	val, err := extractValue(buf, int(entry.Offset), entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Numeric != 0x42 {
		t.Errorf("Numeric = 0x%x, want 0x42", val.Numeric)
	}
}

func TestExtractValue_BELong(t *testing.T) {
	buf := []byte{0x89, 0x50, 0x4e, 0x47} // PNG magic
	entry := &MagicEntry{Type: TypeBELong, Offset: 0}
	val, err := extractValue(buf, 0, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Numeric != 0x89504e47 {
		t.Errorf("Numeric = 0x%x, want 0x89504e47", val.Numeric)
	}
}

func TestExtractValue_LELong(t *testing.T) {
	buf := []byte{0x47, 0x4e, 0x50, 0x89} // little-endian
	entry := &MagicEntry{Type: TypeLELong, Offset: 0}
	val, err := extractValue(buf, 0, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Numeric != 0x89504e47 {
		t.Errorf("Numeric = 0x%x, want 0x89504e47", val.Numeric)
	}
}

func TestExtractValue_BEShort(t *testing.T) {
	buf := []byte{0x00, 0xFF, 0xD8}
	entry := &MagicEntry{Type: TypeBEShort, Offset: 1}
	val, err := extractValue(buf, 1, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Numeric != 0xFFD8 {
		t.Errorf("Numeric = 0x%x, want 0xFFD8", val.Numeric)
	}
}

func TestExtractValue_LEShort(t *testing.T) {
	buf := []byte{0xD8, 0xFF}
	entry := &MagicEntry{Type: TypeLEShort, Offset: 0}
	val, err := extractValue(buf, 0, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.Numeric != 0xFFD8 {
		t.Errorf("Numeric = 0x%x, want 0xFFD8", val.Numeric)
	}
}

func TestExtractValue_String(t *testing.T) {
	buf := []byte("hello world")
	entry := &MagicEntry{
		Type:  TypeString,
		Value: Value{Str: []byte("hello"), IsString: true},
	}
	val, err := extractValue(buf, 0, entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val.Str) != "hello" {
		t.Errorf("Str = %q, want %q", val.Str, "hello")
	}
}

func TestExtractValue_OutOfBounds(t *testing.T) {
	buf := []byte{0x00, 0x01}
	entry := &MagicEntry{Type: TypeBELong, Offset: 0}
	_, err := extractValue(buf, 0, entry)
	if err == nil {
		t.Fatal("expected error for out of bounds, got nil")
	}
}

func TestCompare_Equal(t *testing.T) {
	entry := &MagicEntry{Relation: '=', Value: Value{Numeric: 0x89504e47}}
	val := Value{Numeric: 0x89504e47}
	if !compare(val, entry) {
		t.Error("compare returned false, want true")
	}
	val.Numeric = 0x12345678
	if compare(val, entry) {
		t.Error("compare returned true, want false")
	}
}

func TestCompare_GreaterThan(t *testing.T) {
	entry := &MagicEntry{Relation: '>', Value: Value{Numeric: 100}}
	if !compare(Value{Numeric: 200}, entry) {
		t.Error("200 > 100 should match")
	}
	if compare(Value{Numeric: 50}, entry) {
		t.Error("50 > 100 should not match")
	}
}

func TestCompare_AnyValue(t *testing.T) {
	entry := &MagicEntry{Relation: 'x'}
	if !compare(Value{Numeric: 42}, entry) {
		t.Error("x should always match")
	}
}

func TestCompare_StringEqual(t *testing.T) {
	entry := &MagicEntry{
		Relation: '=',
		Value:    Value{Str: []byte("%PDF-"), IsString: true},
	}
	if !compare(Value{Str: []byte("%PDF-"), IsString: true}, entry) {
		t.Error("string equal should match")
	}
	if compare(Value{Str: []byte("%PDX-"), IsString: true}, entry) {
		t.Error("string not equal should not match")
	}
}

func TestCompare_BitsSet(t *testing.T) {
	// & relation: all bits in test value must be set in extracted value
	entry := &MagicEntry{Relation: '&', Value: Value{Numeric: 0x0F}}
	if !compare(Value{Numeric: 0xFF}, entry) {
		t.Error("0xFF & 0x0F should match")
	}
	if compare(Value{Numeric: 0xF0}, entry) {
		t.Error("0xF0 & 0x0F should not match")
	}
}

func TestCompare_BitsClear(t *testing.T) {
	// ^ relation: some bits in test value must be clear in extracted value
	entry := &MagicEntry{Relation: '^', Value: Value{Numeric: 0x80}}
	if !compare(Value{Numeric: 0x7F}, entry) {
		t.Error("0x7F ^ 0x80: bit 0x80 is clear, should match")
	}
	if compare(Value{Numeric: 0xFF}, entry) {
		t.Error("0xFF ^ 0x80: bit 0x80 is set, should not match")
	}
}
