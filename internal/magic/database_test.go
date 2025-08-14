package magic

import (
	"testing"
)

func TestDatabaseFormatForList(t *testing.T) {
	// Create a simple database with entries
	db := &Database{
		Sets: []Set{
			{
				Number: 0,
				BinaryEntries: []*Entry{
					{
						Mp: &Magic{
							Strength:   100,
							Lineno:     10,
							MessageStr: "Test binary pattern",
						},
					},
				},
				TextEntries: []*Entry{
					{
						Mp: &Magic{
							Strength:   50,
							Lineno:     20,
							MessageStr: "Test text pattern",
						},
					},
				},
			},
		},
	}

	output := db.FormatForList()

	if len(output) < 3 {
		t.Errorf("Expected at least 3 lines of output, got %d", len(output))
	}

	// Check that the output contains expected sections
	foundSet := false
	foundBinary := false
	foundText := false

	for _, line := range output {
		if line == "Set 0:" {
			foundSet = true
		}
		if line == "Binary patterns:" {
			foundBinary = true
		}
		if line == "Text patterns:" {
			foundText = true
		}
	}

	if !foundSet {
		t.Error("Missing 'Set 0:' in output")
	}
	if !foundBinary {
		t.Error("Missing 'Binary patterns:' in output")
	}
	if !foundText {
		t.Error("Missing 'Text patterns:' in output")
	}
}
