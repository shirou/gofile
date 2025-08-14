package magic

import (
	"math"
	"testing"
)

func TestGetValue(t *testing.T) {
	tests := map[string]struct {
		magicType MagicType
		typeStr   string
		reln      uint8
		testValue string
		wantQ     uint64
		wantF     float32
		wantD     float64
		wantS     string
		wantGuid  [2]uint64
		wantErr   bool
	}{
		// Numeric types - decimal
		"byte decimal positive": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "127",
			wantQ:     127,
		},
		"byte decimal negative": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "-128",
			wantQ:     0xffffffffffffff80, // -128 as uint64
		},
		"short decimal": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "32767",
			wantQ:     32767,
		},
		"long decimal": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "2147483647",
			wantQ:     2147483647,
		},
		"quad decimal": {
			magicType: TypeQuad,
			typeStr:   "quad",
			testValue: "9223372036854775807",
			wantQ:     9223372036854775807,
		},

		// Numeric types - hexadecimal
		"byte hex": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "0x7F",
			wantQ:     0x7F,
		},
		"short hex": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "0x7FFF",
			wantQ:     0x7FFF,
		},
		"long hex": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "0xDEADBEEF",
			wantQ:     0xffffffffDEADBEEF, // sign extended because high bit is set
		},
		"quad hex": {
			magicType: TypeQuad,
			typeStr:   "quad",
			testValue: "0x123456789ABCDEF0",
			wantQ:     0x123456789ABCDEF0,
		},

		// Numeric types - octal
		"byte octal": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "0177",
			wantQ:     0177,
		},
		"short octal": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "077777",
			wantQ:     077777,
		},

		// Endian-specific types
		"beshort": {
			magicType: TypeBeshort,
			typeStr:   "beshort",
			testValue: "0x1234",
			wantQ:     0x1234,
		},
		"leshort": {
			magicType: TypeLeshort,
			typeStr:   "leshort",
			testValue: "0x1234",
			wantQ:     0x1234,
		},
		"belong": {
			magicType: TypeBelong,
			typeStr:   "belong",
			testValue: "0x12345678",
			wantQ:     0x12345678,
		},
		"lelong": {
			magicType: TypeLelong,
			typeStr:   "lelong",
			testValue: "0x12345678",
			wantQ:     0x12345678,
		},

		// Float types
		"float": {
			magicType: TypeFloat,
			typeStr:   "float",
			testValue: "3.14159",
			wantF:     3.14159,
		},
		"befloat": {
			magicType: TypeBefloat,
			typeStr:   "befloat",
			testValue: "-2.71828",
			wantF:     -2.71828,
		},
		"lefloat": {
			magicType: TypeLefloat,
			typeStr:   "lefloat",
			testValue: "1.23456e10",
			wantF:     1.23456e10,
		},

		// Double types
		"double": {
			magicType: TypeDouble,
			typeStr:   "double",
			testValue: "3.141592653589793",
			wantD:     3.141592653589793,
		},
		"bedouble": {
			magicType: TypeBedouble,
			typeStr:   "bedouble",
			testValue: "-2.718281828459045",
			wantD:     -2.718281828459045,
		},
		"ledouble": {
			magicType: TypeLedouble,
			typeStr:   "ledouble",
			testValue: "1.23456789e100",
			wantD:     1.23456789e100,
		},

		// String types
		"string simple": {
			magicType: TypeString,
			typeStr:   "string",
			testValue: "Hello",
			wantS:     "Hello",
		},
		"string with spaces": {
			magicType: TypeString,
			typeStr:   "string",
			testValue: "Hello\\ World",
			wantS:     "Hello World",
		},
		"string with escapes": {
			magicType: TypeString,
			typeStr:   "string",
			testValue: "\\x48\\x65\\x6c\\x6c\\x6f",
			wantS:     "Hello",
		},
		"string with newline": {
			magicType: TypeString,
			typeStr:   "string",
			testValue: "Line1\\nLine2",
			wantS:     "Line1\nLine2",
		},
		"pstring": {
			magicType: TypePstring,
			typeStr:   "pstring",
			testValue: "Test\\x00String",
			wantS:     "Test\x00String",
		},
		"bestring16": {
			magicType: TypeBestring16,
			typeStr:   "bestring16",
			testValue: "UTF-16\\x00Test",
			wantS:     "UTF-16\x00Test",
		},

		// GUID type
		"guid with dashes": {
			magicType: TypeGuid,
			typeStr:   "guid",
			testValue: "12345678-9ABC-DEF0-1234-56789ABCDEF0",
			wantGuid:  [2]uint64{0x123456789ABCDEF0, 0x123456789ABCDEF0},
		},
		"guid without dashes": {
			magicType: TypeGuid,
			typeStr:   "guid",
			testValue: "123456789ABCDEF0123456789ABCDEF0",
			wantGuid:  [2]uint64{0x123456789ABCDEF0, 0x123456789ABCDEF0},
		},

		// Special cases
		"x relation": {
			magicType: TypeLong,
			typeStr:   "long",
			reln:      'x',
			testValue: "",
			wantQ:     0,
		},

		// Error cases
		"invalid number": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "not_a_number",
			wantErr:   true,
		},
		"overflow byte": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "256",
			wantErr:   true,
		},
		"overflow short": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "65536",
			wantErr:   true,
		},
		"invalid float": {
			magicType: TypeFloat,
			typeStr:   "float",
			testValue: "not_a_float",
			wantErr:   true,
		},
		"invalid guid": {
			magicType: TypeGuid,
			typeStr:   "guid",
			testValue: "invalid-guid",
			wantErr:   true,
		},
		"empty numeric value": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "",
			wantErr:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Magic{
				Type:    tt.magicType,
				TypeStr: tt.typeStr,
				Reln:    tt.reln,
			}

			err := getValue(m, tt.testValue)

			if tt.wantErr {
				if err == nil {
					t.Errorf("getValue() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("getValue() unexpected error: %v", err)
				return
			}

			// Check the appropriate field based on type
			switch tt.magicType {
			case TypeFloat, TypeBefloat, TypeLefloat:
				if !floatEquals(m.Value.F, tt.wantF) {
					t.Errorf("getValue() Value.F = %v, want %v", m.Value.F, tt.wantF)
				}
			case TypeDouble, TypeBedouble, TypeLedouble:
				if !float64Equals(m.Value.D, tt.wantD) {
					t.Errorf("getValue() Value.D = %v, want %v", m.Value.D, tt.wantD)
				}
			case TypeString, TypePstring, TypeBestring16, TypeLestring16,
				TypeRegex, TypeSearch, TypeName, TypeUse, TypeDer, TypeOctal:
				gotStr := string(m.Value.S[:m.Vallen])
				if gotStr != tt.wantS {
					t.Errorf("getValue() Value.S = %q, want %q", gotStr, tt.wantS)
				}
			case TypeGuid:
				if m.Value.Guid != tt.wantGuid {
					t.Errorf("getValue() Value.Guid = %v, want %v", m.Value.Guid, tt.wantGuid)
				}
			default:
				if m.Value.Q != tt.wantQ {
					t.Errorf("getValue() Value.Q = 0x%x, want 0x%x", m.Value.Q, tt.wantQ)
				}
			}
		})
	}
}

func TestSignExtension(t *testing.T) {
	tests := map[string]struct {
		magicType MagicType
		typeStr   string
		testValue string
		wantQ     uint64
	}{
		"byte negative sign extension": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "-1",
			wantQ:     math.MaxUint64, // -1 as uint64
		},
		"short negative sign extension": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "-1",
			wantQ:     math.MaxUint64, // -1 as uint64
		},
		"long negative sign extension": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "-1",
			wantQ:     math.MaxUint64, // -1 as uint64
		},
		"byte 0x80 sign extension": {
			magicType: TypeByte,
			typeStr:   "byte",
			testValue: "0x80",
			wantQ:     0xffffffffffffff80, // -128 sign extended
		},
		"short 0x8000 sign extension": {
			magicType: TypeShort,
			typeStr:   "short",
			testValue: "0x8000",
			wantQ:     0xffffffffffff8000, // -32768 sign extended
		},
		"long 0x80000000 sign extension": {
			magicType: TypeLong,
			typeStr:   "long",
			testValue: "0x80000000",
			wantQ:     0xffffffff80000000, // -2147483648 sign extended
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Magic{
				Type:    tt.magicType,
				TypeStr: tt.typeStr,
			}

			err := getValue(m, tt.testValue)
			if err != nil {
				t.Fatalf("getValue() unexpected error: %v", err)
			}

			if m.Value.Q != tt.wantQ {
				t.Errorf("getValue() sign extension: Value.Q = 0x%x, want 0x%x", m.Value.Q, tt.wantQ)
			}
		})
	}
}

func TestParseGUID(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    [2]uint64
		wantErr bool
	}{
		"valid guid with dashes": {
			input: "12345678-9ABC-DEF0-1234-56789ABCDEF0",
			want:  [2]uint64{0x123456789ABCDEF0, 0x123456789ABCDEF0},
		},
		"valid guid without dashes": {
			input: "123456789ABCDEF0123456789ABCDEF0",
			want:  [2]uint64{0x123456789ABCDEF0, 0x123456789ABCDEF0},
		},
		"all zeros": {
			input: "00000000-0000-0000-0000-000000000000",
			want:  [2]uint64{0, 0},
		},
		"all ones": {
			input: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
			want:  [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
		},
		"lowercase": {
			input: "abcdef01-2345-6789-abcd-ef0123456789",
			want:  [2]uint64{0xabcdef0123456789, 0xabcdef0123456789},
		},
		"too short": {
			input:   "12345678-9ABC-DEF0",
			wantErr: true,
		},
		"too long": {
			input:   "12345678-9ABC-DEF0-1234-56789ABCDEF01",
			wantErr: true,
		},
		"invalid hex": {
			input:   "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
			wantErr: true,
		},
		"empty": {
			input:   "",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseGUID(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseGUID() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("parseGUID() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("parseGUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckOverflow(t *testing.T) {
	tests := map[string]struct {
		val      uint64
		typeSize int
		wantErr  bool
	}{
		// 1-byte types
		"byte no overflow":          {0xFF, 1, false},
		"byte overflow positive":    {0x100, 1, true},
		"byte negative no overflow": {0xFFFFFFFFFFFFFF80, 1, false}, // -128

		// 2-byte types
		"short no overflow":          {0xFFFF, 2, false},
		"short overflow positive":    {0x10000, 2, true},
		"short negative no overflow": {0xFFFFFFFFFFFF8000, 2, false}, // -32768

		// 4-byte types
		"long no overflow":          {0xFFFFFFFF, 4, false},
		"long overflow positive":    {0x100000000, 4, true},
		"long negative no overflow": {0xFFFFFFFF80000000, 4, false}, // -2147483648

		// 8-byte types
		"quad no overflow":          {0xFFFFFFFFFFFFFFFF, 8, false},
		"quad negative no overflow": {0x8000000000000000, 8, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkOverflow(tt.val, tt.typeSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOverflow(0x%x, %d) error = %v, wantErr = %v",
					tt.val, tt.typeSize, err, tt.wantErr)
			}
		})
	}
}

// Helper functions for float comparison
func floatEquals(a, b float32) bool {
	const epsilon = 1e-6
	return math.Abs(float64(a-b)) < epsilon
}

func float64Equals(a, b float64) bool {
	const epsilon = 1e-9
	return math.Abs(a-b) < epsilon
}
