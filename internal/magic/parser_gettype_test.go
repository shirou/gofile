package magic

import (
	"strings"
	"testing"
)

func TestGetType(t *testing.T) {
	tests := map[string]struct {
		input       string
		wantType    MagicType
		wantRest    string
		wantErr     bool
		errContains string
	}{
		"valid byte type": {
			input:    "byte/10 test",
			wantType: TypeByte,
			wantRest: "/10 test",
			wantErr:  false,
		},
		"valid string type": {
			input:    "string/c test",
			wantType: TypeString,
			wantRest: "/c test",
			wantErr:  false,
		},
		"valid long type": {
			input:    "long&0xff",
			wantType: TypeLong,
			wantRest: "&0xff",
			wantErr:  false,
		},
		"invalid type": {
			input:       "invalidtype test",
			wantType:    TypeInvalid,
			wantRest:    "invalidtype test",
			wantErr:     true,
			errContains: "unknown type",
		},
		"empty input": {
			input:       "",
			wantType:    TypeInvalid,
			wantRest:    "",
			wantErr:     true,
			errContains: "unknown type",
		},
		"partial match": {
			input:       "shortcut",
			wantType:    TypeShort,
			wantRest:    "cut",
			wantErr:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotType, gotRest, err := getType(tt.input)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error message should contain '%s', got: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
			
			if gotType != tt.wantType {
				t.Errorf("Type mismatch: want=%s, got=%s", tt.wantType.ToString(), gotType.ToString())
			}
			
			if gotRest != tt.wantRest {
				t.Errorf("Rest mismatch: want=%s, got=%s", tt.wantRest, gotRest)
			}
		})
	}
}