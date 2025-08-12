package magic

import (
	"testing"
)

func TestGetStandardIntegerType(t *testing.T) {
	tests := map[string]struct {
		input    string
		wantType MagicType
		wantRest string
	}{
		"d - decimal long": {
			input:    "d",
			wantType: TypeLong,
			wantRest: "",
		},
		"u - unsigned long": {
			input:    "u",
			wantType: TypeUlong,
			wantRest: "",
		},
		"dC - decimal byte": {
			input:    "dC",
			wantType: TypeByte,
			wantRest: "",
		},
		"uC - unsigned byte": {
			input:    "uC",
			wantType: TypeUbyte,
			wantRest: "",
		},
		"dS - decimal short": {
			input:    "dS",
			wantType: TypeShort,
			wantRest: "",
		},
		"uS - unsigned short": {
			input:    "uS",
			wantType: TypeUshort,
			wantRest: "",
		},
		"dL - decimal long": {
			input:    "dL",
			wantType: TypeLong,
			wantRest: "",
		},
		"uL - unsigned long": {
			input:    "uL",
			wantType: TypeUlong,
			wantRest: "",
		},
		"dQ - decimal quad": {
			input:    "dQ",
			wantType: TypeQuad,
			wantRest: "",
		},
		"uQ - unsigned quad": {
			input:    "uQ",
			wantType: TypeUquad,
			wantRest: "",
		},
		"d1 - decimal byte (numeric)": {
			input:    "d1",
			wantType: TypeByte,
			wantRest: "",
		},
		"u2 - unsigned short (numeric)": {
			input:    "u2",
			wantType: TypeUshort,
			wantRest: "",
		},
		"d4 - decimal long (numeric)": {
			input:    "d4",
			wantType: TypeLong,
			wantRest: "",
		},
		"u8 - unsigned quad (numeric)": {
			input:    "u8",
			wantType: TypeUquad,
			wantRest: "",
		},
		"dL test - with trailing text": {
			input:    "dL test",
			wantType: TypeLong,
			wantRest: " test",
		},
		"invalid - not a SUS type": {
			input:    "invalid",
			wantType: "",
			wantRest: "invalid",
		},
		"empty string": {
			input:    "",
			wantType: "",
			wantRest: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotType, gotRest := getStandardIntegerType(tt.input)
			
			if gotType != tt.wantType {
				t.Errorf("Type mismatch: want=%s, got=%s", tt.wantType, gotType)
			}
			
			if gotRest != tt.wantRest {
				t.Errorf("Rest mismatch: want=%s, got=%s", tt.wantRest, gotRest)
			}
		})
	}
}