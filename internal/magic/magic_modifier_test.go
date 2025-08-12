package magic

import (
	"testing"
)

func TestParseOpModifierFunc(t *testing.T) {
	tests := map[string]struct {
		typeStr  string
		input    string
		op       uint8
		wantMask uint64
		wantRest string
		wantOp   uint8
	}{
		"AND with hex value": {
			typeStr:  string(TypeLong),
			input:    "&0xff",
			op:       FILE_OPAND,
			wantMask: 0xff,
			wantRest: "",
			wantOp:   FILE_OPAND,
		},
		"OR with decimal value": {
			typeStr:  string(TypeShort),
			input:    "|256",
			op:       FILE_OPOR,
			wantMask: 256,
			wantRest: "",
			wantOp:   FILE_OPOR,
		},
		"XOR with octal value": {
			typeStr:  string(TypeByte),
			input:    "^0377",
			op:       FILE_OPXOR,
			wantMask: 0xffffffffffffffff, // 0377 (255) sign-extended from byte to -1
			wantRest: "",
			wantOp:   FILE_OPXOR,
		},
		"ADD with decimal and size modifier": {
			typeStr:  string(TypeLong),
			input:    "+10L",
			op:       FILE_OPADD,
			wantMask: 10,
			wantRest: "",
			wantOp:   FILE_OPADD,
		},
		"MINUS with negative value": {
			typeStr:  string(TypeLong),
			input:    "--5",
			op:       FILE_OPMINUS,
			wantMask: 0xfffffffffffffffb, // -5 as uint64
			wantRest: "",
			wantOp:   FILE_OPMINUS,
		},
		"value with trailing text": {
			typeStr:  string(TypeLong),
			input:    "&0xff test",
			op:       FILE_OPAND,
			wantMask: 0xff,
			wantRest: " test",
			wantOp:   FILE_OPAND,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Magic{
				TypeStr: tt.typeStr,
				Flag:    0,
			}
			
			input := tt.input
			ParseOpModifier(m, &input, tt.op)
			
			if m.MaskOp != tt.wantOp {
				t.Errorf("MaskOp = %d, want %d", m.MaskOp, tt.wantOp)
			}
			
			if m.Mask != tt.wantMask {
				t.Errorf("Mask = %d, want %d", m.Mask, tt.wantMask)
			}
			
			if input != tt.wantRest {
				t.Errorf("remaining input = %q, want %q", input, tt.wantRest)
			}
		})
	}
}

func TestSignExtend(t *testing.T) {
	tests := map[string]struct {
		typeStr  string
		value    uint64
		unsigned bool
		want     uint64
	}{
		"byte sign extend": {
			typeStr:  string(TypeByte),
			value:    0xff,
			unsigned: false,
			want:     0xffffffffffffffff, // -1 as uint64
		},
		"byte unsigned": {
			typeStr:  string(TypeByte),
			value:    0xff,
			unsigned: true,
			want:     0xff,
		},
		"short sign extend": {
			typeStr:  string(TypeShort),
			value:    0xffff,
			unsigned: false,
			want:     0xffffffffffffffff, // -1 as uint64
		},
		"long sign extend": {
			typeStr:  string(TypeLong),
			value:    0xffffffff,
			unsigned: false,
			want:     0xffffffffffffffff, // -1 as uint64
		},
		"quad no sign extend": {
			typeStr:  string(TypeQuad),
			value:    0xffffffffffffffff,
			unsigned: false,
			want:     0xffffffffffffffff,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Magic{
				TypeStr: tt.typeStr,
			}
			if tt.unsigned {
				m.Flag |= UNSIGNED
			}
			
			got := signExtend(m, tt.value)
			if got != tt.want {
				t.Errorf("signExtend() = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestEatSize(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"unsigned long": {
			input: "uL remaining",
			want:  " remaining",
		},
		"short": {
			input: "s text",
			want:  " text",
		},
		"byte": {
			input: "b123",
			want:  "123",
		},
		"char": {
			input: "c",
			want:  "",
		},
		"uppercase unsigned short": {
			input: "US",
			want:  "",
		},
		"no size modifier": {
			input: "123",
			want:  "123",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			input := tt.input
			eatSize(&input)
			if input != tt.want {
				t.Errorf("eatSize(%q) = %q, want %q", tt.input, input, tt.want)
			}
		})
	}
}

func TestParseStringModifier(t *testing.T) {
	tests := map[string]struct {
		input         string
		typeStr       string
		expectedFlags uint32
		expectedCount uint32
		expectError   bool
	}{
		"compact whitespace flag": {
			input:         "/W",
			typeStr:       "string",
			expectedFlags: STRING_COMPACT_WHITESPACE,
			expectedCount: 0,
			expectError:   false,
		},
		"ignore case flags": {
			input:         "/cC",
			typeStr:       "string",
			expectedFlags: STRING_IGNORE_LOWERCASE | STRING_IGNORE_UPPERCASE,
			expectedCount: 0,
			expectError:   false,
		},
		"numeric range": {
			input:         "/256",
			typeStr:       "search",
			expectedFlags: 0,
			expectedCount: 256,
			expectError:   false,
		},
		"range with flags": {
			input:         "/100Wc",
			typeStr:       "string",
			expectedFlags: STRING_COMPACT_WHITESPACE | STRING_IGNORE_LOWERCASE,
			expectedCount: 100,
			expectError:   false,
		},
		"binary test flag": {
			input:         "/b",
			typeStr:       "string",
			expectedFlags: STRING_BINTEST,
			expectedCount: 0,
			expectError:   false,
		},
		"text test flag": {
			input:         "/t",
			typeStr:       "string",
			expectedFlags: STRING_TEXTTEST,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring 1-byte length": {
			input:         "/B",
			typeStr:       "pstring",
			expectedFlags: PSTRING_1_LE,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring 2-byte BE": {
			input:         "/H",
			typeStr:       "pstring",
			expectedFlags: PSTRING_2_BE,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring 2-byte LE": {
			input:         "/h",
			typeStr:       "pstring",
			expectedFlags: PSTRING_2_LE,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring 4-byte BE": {
			input:         "/L",
			typeStr:       "pstring",
			expectedFlags: PSTRING_4_BE,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring 4-byte LE": {
			input:         "/l",
			typeStr:       "pstring",
			expectedFlags: PSTRING_4_LE,
			expectedCount: 0,
			expectError:   false,
		},
		"regex line count": {
			input:         "/l",
			typeStr:       "regex",
			expectedFlags: REGEX_LINE_COUNT,
			expectedCount: 0,
			expectError:   false,
		},
		"pstring length includes itself": {
			input:         "/J",
			typeStr:       "pstring",
			expectedFlags: PSTRING_LENGTH_INCLUDES_ITSELF,
			expectedCount: 0,
			expectError:   false,
		},
		"invalid pstring modifier on string": {
			input:         "/H",
			typeStr:       "string",
			expectedFlags: 0,
			expectedCount: 0,
			expectError:   true,
		},
		"B flag on non-pstring": {
			input:         "/B",
			typeStr:       "string",
			expectedFlags: STRING_BINTEST,
			expectedCount: 0,
			expectError:   false,
		},
		"multiple modifiers": {
			input:         "/100WctT",
			typeStr:       "string",
			expectedFlags: STRING_COMPACT_WHITESPACE | STRING_IGNORE_LOWERCASE | STRING_TEXTTEST | STRING_TRIM,
			expectedCount: 100,
			expectError:   false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := &Magic{
				TypeStr: tt.typeStr,
				Flags:   0,
				Count:   0,
			}

			input := tt.input
			err := ParseStringModifier(m, &input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if m.Flags != tt.expectedFlags {
				t.Errorf("Flags: expected 0x%x, got 0x%x", tt.expectedFlags, m.Flags)
			}

			if m.Count != tt.expectedCount {
				t.Errorf("Count: expected %d, got %d", tt.expectedCount, m.Count)
			}
		})
	}
}