package magic

import "testing"

func TestDERStrengthCalculation(t *testing.T) {
	// Test DER type strength calculation
	// According to the original file command, DER type should add exactly MULT (10)
	// With base strength = 20, equals match = 10, empty desc = 1
	// Total should be 20 + 10 + 10 + 1 = 41

	tests := map[string]struct {
		magic    *Magic
		expected int
	}{
		"DER type with equals match and empty message": {
			magic: &Magic{
				TypeStr:     "der",
				OperatorStr: "=",
				MessageStr:  "", // Empty message gets +1 bonus
			},
			expected: 41, // BASE(20) + DER(10) + EQUALS(10) + EMPTY_DESC(1)
		},
		"DER type with equals match and message": {
			magic: &Magic{
				TypeStr:     "der",
				OperatorStr: "=",
				MessageStr:  "DER Encoded Certificate",
			},
			expected: 40, // BASE(20) + DER(10) + EQUALS(10)
		},
		"DER type with x relation": {
			magic: &Magic{
				TypeStr:     "der",
				OperatorStr: "x",
				MessageStr:  "Some message",
			},
			expected: 1, // x relation gives 0, but minimum is 1 for non-DEFAULT types
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			strength := tt.magic.apprenticeMagicStrength()
			if strength != tt.expected {
				t.Errorf("DER strength mismatch: got %d, want %d", strength, tt.expected)
			}
		})
	}
}
