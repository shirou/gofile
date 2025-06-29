// +build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shirou/gofile"
	"github.com/shirou/gofile/internal/magic"
)

// TestMagicFileLoading tests loading of magic.mgc file
func TestMagicFileLoading(t *testing.T) {
	projectRoot := getProjectRoot()
	magicFile := filepath.Join(projectRoot, "test", "testdata", "magic", "magic.mgc")
	
	if _, err := os.Stat(magicFile); os.IsNotExist(err) {
		t.Fatalf("Magic file not found. Run 'make setup-test' first.")
	}
	
	// Test magic file loading
	parser := magic.NewParser()
	db, err := parser.ParseFile(magicFile)
	if err != nil {
		t.Fatalf("Failed to parse magic file: %v", err)
	}
	
	if db == nil {
		t.Fatal("Magic database is nil")
	}
	
	// Verify we loaded some entries
	totalEntries := 0
	for i := 0; i < 2; i++ {
		totalEntries += int(db.NMagic[i])
	}
	
	if totalEntries == 0 {
		t.Fatal("No magic entries loaded")
	}
	
	t.Logf("Successfully loaded magic database with %d entries", totalEntries)
}

// TestFileDetection tests basic file detection functionality
func TestFileDetection(t *testing.T) {
	projectRoot := getProjectRoot()
	testDataDir := filepath.Join(projectRoot, "test", "testdata", "file-tests", "db")
	
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		t.Fatalf("Test data not found. Run 'make setup-test' first.")
	}
	
	// Test basic file types
	testCases := []struct {
		category string
		expected string
	}{
		{"txt", "text"},
		{"png", "PNG image"},
		{"jpg", "JPEG image"},
		{"pdf", "PDF document"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.category, func(t *testing.T) {
			categoryDir := filepath.Join(testDataDir, tc.category)
			if _, err := os.Stat(categoryDir); os.IsNotExist(err) {
				t.Skipf("Category %s not found", tc.category)
			}
			
			// Find first file in category
			files, err := filepath.Glob(filepath.Join(categoryDir, "*"))
			if err != nil || len(files) == 0 {
				t.Skipf("No files found in category %s", tc.category)
			}
			
			// Filter out .source.txt files
			var testFile string
			for _, file := range files {
				if filepath.Ext(file) != ".txt" && !contains(file, ".source.") {
					testFile = file
					break
				}
			}
			
			if testFile == "" {
				t.Skipf("No suitable test file found in category %s", tc.category)
			}
			
			// Test file detection
			result, err := gofile.DetectFile(testFile)
			if err != nil {
				t.Fatalf("Detection failed: %v", err)
			}
			
			if !strings.Contains(result, tc.expected) {
				t.Errorf("Expected description to contain '%s', got '%s'", 
					tc.expected, result)
			}
			
			t.Logf("Successfully detected file: %s -> %s", testFile, result)
		})
	}
}

// TestCLIInterface tests the command-line interface
func TestCLIInterface(t *testing.T) {
	projectRoot := getProjectRoot()
	binaryPath := filepath.Join(projectRoot, "gofile")
	
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Binary not found. Run 'make build' first.")
	}
	
	// Test CLI interface with a simple PNG file
	testPNG := filepath.Join(projectRoot, "test_minimal.png")
	if _, err := os.Stat(testPNG); os.IsNotExist(err) {
		t.Skip("Test PNG file not found")
	}
	
	// Test basic detection
	cmd := exec.Command(binaryPath, testPNG)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI command failed: %v, output: %s", err, string(output))
	}
	
	result := string(output)
	if !strings.Contains(result, "PNG") {
		t.Errorf("Expected PNG detection, got: %s", result)
	}
	
	// Test MIME mode
	cmd = exec.Command(binaryPath, "-i", testPNG)
	output, err = cmd.Output()
	if err != nil {
		t.Fatalf("CLI MIME command failed: %v", err)
	}
	
	mimeResult := string(output)
	if !strings.Contains(mimeResult, "image/png") {
		t.Errorf("Expected MIME type image/png, got: %s", mimeResult)
	}
	
	t.Logf("CLI test successful - Basic: %s, MIME: %s", 
		strings.TrimSpace(result), strings.TrimSpace(mimeResult))
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    s[:len(substr)] == substr || 
		    s[len(s)-len(substr):] == substr ||
		    containsInMiddle(s, substr))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// getProjectRoot finds the project root directory
func getProjectRoot() string {
	dir, _ := os.Getwd()
	
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	
	// Fallback
	dir, _ = os.Getwd()
	return filepath.Join(dir, "..", "..")
}
