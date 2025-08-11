package magic

import (
	"strings"
	"testing"
)

func TestParseTFlag(t *testing.T) {
	parser := NewParser()
	
	magicContent := `# Test with t flag
0	string	#!/bin/bash	Bash without t flag
0	string/t	#!/bin/sh	POSIX with t flag`
	
	err := parser.Parse(strings.NewReader(magicContent), "test.magic")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	
	db := parser.GetDatabase()
	if len(db.Entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(db.Entries))
	}
	
	// First entry should not have 't' flag and should be BINTEST
	entry1 := db.Entries[0]
	if entry1.Message != "Bash without t flag" {
		t.Errorf("Entry 1: wrong message: %s", entry1.Message)
	}
	hasTFlag := false
	for _, flag := range entry1.Flags {
		if flag == "t" || flag == "T" {
			hasTFlag = true
			break
		}
	}
	if hasTFlag {
		t.Errorf("Entry 1: should not have 't' flag, got flags: %v", entry1.Flags)
	}
	if entry1.Flag != BINTEST {
		t.Errorf("Entry 1: should be BINTEST, got %v", entry1.Flag)
	}
	
	// Second entry should have 't' flag and should be TEXTTEST
	entry2 := db.Entries[1]
	if entry2.Message != "POSIX with t flag" {
		t.Errorf("Entry 2: wrong message: %s", entry2.Message)
	}
	hasTFlag = false
	for _, flag := range entry2.Flags {
		if flag == "t" || flag == "T" {
			hasTFlag = true
			break
		}
	}
	if !hasTFlag {
		t.Errorf("Entry 2: should have 't' flag, got flags: %v", entry2.Flags)
	}
	if entry2.Flag != TEXTTEST {
		t.Errorf("Entry 2: should be TEXTTEST, got %v", entry2.Flag)
	}
}