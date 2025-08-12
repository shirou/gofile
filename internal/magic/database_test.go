package magic

import (
	"testing"
)

func TestSortEntriesByStrength(t *testing.T) {
	// Create test entries with Magic structs
	entry1 := &Entry{
		Mp: &Magic{
			Strength: 50,
			Lineno:   10,
		},
	}
	
	entry2 := &Entry{
		Mp: &Magic{
			Strength: 100,
			Lineno:   20,
		},
	}
	
	entry3 := &Entry{
		Mp: &Magic{
			Strength: 100,
			Lineno:   15,
		},
	}
	
	entries := []*Entry{entry1, entry2, entry3}
	
	SortEntriesByStrength(entries)
	
	// Should be sorted by strength (descending), then by line number (ascending)
	// Expected order: entry2 (100, 15), entry3 (100, 20), entry1 (50, 10)
	if entries[0] != entry3 {
		t.Errorf("Expected entry3 first (strength 100, line 15)")
	}
	if entries[1] != entry2 {
		t.Errorf("Expected entry2 second (strength 100, line 20)")
	}
	if entries[2] != entry1 {
		t.Errorf("Expected entry1 last (strength 50)")
	}
}

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