// +build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMagicFileLoading tests loading of magic.mgc file
func TestMagicFileLoading(t *testing.T) {
	projectRoot := getProjectRoot()
	magicFile := filepath.Join(projectRoot, "test", "testdata", "magic", "magic.mgc")
	
	if _, err := os.Stat(magicFile); os.IsNotExist(err) {
		t.Fatalf("Magic file not found. Run 'make setup-test' first.")
	}
	
	// TODO: Test magic file loading
	// This will be implemented once the magic parser is ready
	t.Log("Magic file found:", magicFile)
}

// TestFileDetection tests basic file detection functionality
func TestFileDetection(t *testing.T) {
	projectRoot := getProjectRoot()
	testDataDir := filepath.Join(projectRoot, "test", "testdata", "file-tests", "db")
	
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		t.Fail("Test data not found. Run 'make setup-test' first.")
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
				if !filepath.Ext(file) == ".txt" || !contains(file, ".source.") {
					testFile = file
					break
				}
			}
			
			if testFile == "" {
				t.Skipf("No suitable test file found in category %s", tc.category)
			}
			
			// TODO: Test file detection
			// result, err := gofile.DetectFile(testFile)
			// if err != nil {
			//     t.Fatalf("Detection failed: %v", err)
			// }
			// 
			// if !strings.Contains(result.Description, tc.expected) {
			//     t.Errorf("Expected description to contain '%s', got '%s'", 
			//         tc.expected, result.Description)
			// }
			
			t.Logf("Would test file: %s (expecting: %s)", testFile, tc.expected)
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
	
	// TODO: Test CLI interface
	// This will test the command-line interface once it's implemented
	t.Log("Binary found:", binaryPath)
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
