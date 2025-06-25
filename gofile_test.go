package gofile

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	// Test creating with default magic files
	// This might fail if no magic files are available
	f, err := New()
	if err != nil {
		// This is expected in test environment without magic files
		t.Logf("Expected error when no magic files available: %v", err)
	} else {
		if f.database == nil {
			t.Error("Expected database to be initialized")
		}
	}
}

func TestNewWithOptions(t *testing.T) {
	opts := Options{
		MagicFiles: []string{"test/testdata/simple.magic"},
		Debug:      true,
	}
	
	f, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to create with options: %v", err)
	}
	
	if f.database == nil {
		t.Error("Expected database to be initialized")
	}
	
	// Check that options are set
	if !f.options.Debug {
		t.Error("Expected debug option to be set")
	}
}

func TestIdentifyFile(t *testing.T) {
	opts := Options{
		MagicFiles: []string{"test/testdata/simple.magic"},
	}
	
	f, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to create file detector: %v", err)
	}
	
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"Directory", ".", "directory"},
		{"Non-existent", "/non/existent/file", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := f.IdentifyFile(tt.path)
			
			if tt.expected == "" {
				if err == nil {
					t.Errorf("Expected error for %s", tt.path)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tt.path, err)
				}
				if result != tt.expected {
					t.Errorf("Expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestIdentify(t *testing.T) {
	opts := Options{
		MagicFiles: []string{"test/testdata/simple.magic"},
	}
	
	f, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to create file detector: %v", err)
	}
	
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"Empty", "", "empty"},
		{"ASCII text", "Hello, World!\n", "ASCII text"},
		{"Binary data", "\x00\x01\x02\x03", "data"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.data)
			result, err := f.Identify(reader)
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestListMagic(t *testing.T) {
	opts := Options{
		MagicFiles: []string{"test/testdata/simple.magic"},
	}
	
	f, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to create file detector: %v", err)
	}
	
	list := f.ListMagic()
	
	if len(list) == 0 {
		t.Error("Expected non-empty list")
	}
	
	// Check format
	foundSet := false
	foundBinary := false
	foundText := false
	
	for _, line := range list {
		if strings.HasPrefix(line, "Set ") {
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
		t.Error("Expected to find Set header")
	}
	if !foundBinary {
		t.Error("Expected to find Binary patterns header")
	}
	if !foundText {
		t.Error("Expected to find Text patterns header")
	}
}