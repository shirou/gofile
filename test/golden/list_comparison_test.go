//go:build golden
// +build golden

package golden

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var (
	updateGolden = flag.Bool("update", false, "Update golden (.expected) files")
	specificFile = flag.String("magic-file", "", "Test specific magic file only")
	verbose      = flag.Bool("verbose-diff", false, "Show detailed differences")
)

func TestListCommandComparison(t *testing.T) {
	// Skip test if file command is not available
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("System 'file' command not found, skipping comparison tests")
	}

	// Build gofile binary
	gofilePath := buildGofile(t)

	// Get source and destination directories
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Failed to get current file path")
	}
	testDir := filepath.Dir(filename)
	projectRoot := filepath.Join(testDir, "..", "..")
	sourceMagicDir := filepath.Join(projectRoot, "github.com", "file", "file", "magic", "Magdir")
	destMagicDir := filepath.Join(testDir, "Magdir")

	// Get list of magic files
	magicFiles, err := getMagicFiles(sourceMagicDir)
	if err != nil {
		t.Fatalf("Failed to get magic files: %v", err)
	}

	// Filter if specific file is requested
	if *specificFile != "" {
		found := false
		for _, mf := range magicFiles {
			if mf == *specificFile {
				magicFiles = []string{mf}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Magic file %s not found", *specificFile)
		}
	}

	// Create tests map for table-driven testing
	tests := make(map[string]struct {
		magicFile  string
		sourceFile string
		destFile   string
		expectFile string
	})

	for _, magicFile := range magicFiles {
		tests[magicFile] = struct {
			magicFile  string
			sourceFile string
			destFile   string
			expectFile string
		}{
			magicFile:  magicFile,
			sourceFile: filepath.Join(sourceMagicDir, magicFile),
			destFile:   filepath.Join(destMagicDir, magicFile),
			expectFile: filepath.Join(destMagicDir, magicFile+".expected"),
		}
	}

	// Run tests
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Allow parallel execution for better performance
			// if *specificFile == "" {
			// 	t.Parallel()
			// }

			// Ensure magic file is copied to test directory
			if err := ensureMagicFile(tt.sourceFile, tt.destFile); err != nil {
				t.Fatalf("Failed to ensure magic file: %v", err)
			}

			// Ensure expected output file exists
			if err := ensureExpectedFile(tt.destFile, tt.expectFile, *updateGolden); err != nil {
				// If we can't generate expected output, skip this test
				t.Skipf("Failed to ensure expected file: %v", err)
			}

			// If we're just updating golden files, skip the comparison
			if *updateGolden {
				t.Logf("Updated expected file for %s", tt.magicFile)
				return
			}

			// Read expected output
			expectedOutput, err := os.ReadFile(tt.expectFile)
			if err != nil {
				t.Fatalf("Failed to read expected output: %v", err)
			}

			// Run gofile --list
			actualOutput, err := runGofileList(gofilePath, tt.destFile)
			if err != nil {
				t.Fatalf("Failed to run gofile: %v", err)
			}

			// Normalize outputs for comparison
			actualOutput = normalizeOutput(actualOutput)
			expectedOutput = normalizeOutput(expectedOutput)

			// Compare outputs
			if equal, diff := compareOutputs(actualOutput, expectedOutput); !equal {
				if *verbose {
					// Show detailed diff
					t.Errorf("Output mismatch for %s:\n%s", tt.magicFile, diffOutputs(actualOutput, expectedOutput))
				} else {
					// Show summary
					t.Errorf("Output mismatch for %s:\n%s", tt.magicFile, diff)
					t.Logf("Run with -verbose-diff for detailed differences")
				}

				// Optionally save actual output for debugging
				actualFile := tt.expectFile + ".actual"
				if err := os.WriteFile(actualFile, actualOutput, 0644); err != nil {
					t.Logf("Failed to save actual output: %v", err)
				} else {
					t.Logf("Actual output saved to %s", actualFile)
				}
			}
		})
	}
}

// TestListCommandSpecificFiles tests a few important magic files in detail
func TestListCommandSpecificFiles(t *testing.T) {
	// Skip test if file command is not available
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("System 'file' command not found, skipping comparison tests")
	}

	// Important magic files to test
	importantFiles := []string{
		"elf",         // Executable and Linkable Format
		"jpeg",        // JPEG images
		"pdf",         // PDF documents
		"compress",    // Compressed files
		"archive",     // Archive formats
		"python",      // Python files
		"java",        // Java class files
		"msdos",       // MS-DOS executables
		"linux",       // Linux-specific formats
		"filesystems", // File system formats
	}

	// Build gofile binary
	gofilePath := buildGofile(t)

	// Get directories
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Failed to get current file path")
	}
	testDir := filepath.Dir(filename)
	projectRoot := filepath.Join(testDir, "..", "..")
	sourceMagicDir := filepath.Join(projectRoot, "github.com", "file", "file", "magic", "Magdir")
	destMagicDir := filepath.Join(testDir, "Magdir")

	tests := make(map[string]struct {
		magicFile  string
		sourceFile string
		destFile   string
		expectFile string
	})

	for _, magicFile := range importantFiles {
		sourceFile := filepath.Join(sourceMagicDir, magicFile)
		// Check if file exists
		if _, err := os.Stat(sourceFile); os.IsNotExist(err) {
			t.Logf("Warning: Magic file %s not found, skipping", magicFile)
			continue
		}

		tests[magicFile] = struct {
			magicFile  string
			sourceFile string
			destFile   string
			expectFile string
		}{
			magicFile:  magicFile,
			sourceFile: sourceFile,
			destFile:   filepath.Join(destMagicDir, magicFile),
			expectFile: filepath.Join(destMagicDir, magicFile+".expected"),
		}
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Ensure magic file is copied
			if err := ensureMagicFile(tt.sourceFile, tt.destFile); err != nil {
				t.Fatalf("Failed to ensure magic file: %v", err)
			}

			// Ensure expected output exists
			if err := ensureExpectedFile(tt.destFile, tt.expectFile, *updateGolden); err != nil {
				t.Skipf("Failed to ensure expected file: %v", err)
			}

			if *updateGolden {
				t.Logf("Updated expected file for %s", tt.magicFile)
				return
			}

			// Read expected output
			expectedOutput, err := os.ReadFile(tt.expectFile)
			if err != nil {
				t.Fatalf("Failed to read expected output: %v", err)
			}

			// Run gofile --list
			actualOutput, err := runGofileList(gofilePath, tt.destFile)
			if err != nil {
				t.Fatalf("Failed to run gofile: %v", err)
			}

			// Normalize outputs
			actualOutput = normalizeOutput(actualOutput)
			expectedOutput = normalizeOutput(expectedOutput)

			// Compare
			if equal, diff := compareOutputs(actualOutput, expectedOutput); !equal {
				t.Errorf("Output mismatch for %s:\n%s", tt.magicFile, diff)

				// Save actual output for debugging
				actualFile := tt.expectFile + ".actual"
				if err := os.WriteFile(actualFile, actualOutput, 0644); err != nil {
					t.Logf("Failed to save actual output: %v", err)
				} else {
					t.Logf("Actual output saved to %s for debugging", actualFile)
					t.Logf("You can compare with: diff %s %s", tt.expectFile, actualFile)
				}
			} else {
				t.Logf("✓ %s matches expected output", tt.magicFile)
			}
		})
	}
}

// TestListCommandBasic tests basic functionality without comparing to system file command
func TestListCommandBasic(t *testing.T) {
	// Build gofile binary
	gofilePath := buildGofile(t)

	// Get directories
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Failed to get current file path")
	}
	testDir := filepath.Dir(filename)
	projectRoot := filepath.Join(testDir, "..", "..")
	sourceMagicDir := filepath.Join(projectRoot, "github.com", "file", "file", "magic", "Magdir")
	destMagicDir := filepath.Join(testDir, "Magdir")

	// Test with a simple magic file
	testFile := "compress"
	sourceFile := filepath.Join(sourceMagicDir, testFile)
	destFile := filepath.Join(destMagicDir, testFile)

	// Ensure magic file is copied
	if err := ensureMagicFile(sourceFile, destFile); err != nil {
		t.Fatalf("Failed to ensure magic file: %v", err)
	}

	// Run gofile --list
	output, err := runGofileList(gofilePath, destFile)
	if err != nil {
		t.Fatalf("Failed to run gofile: %v", err)
	}

	// Basic validation
	outputStr := string(output)

	// Check that output contains expected sections
	if !contains(outputStr, "Set 0:") && !contains(outputStr, "Set 1:") {
		t.Error("Output doesn't contain expected Set headers")
	}

	if !contains(outputStr, "Binary patterns:") || !contains(outputStr, "Text patterns:") {
		t.Error("Output doesn't contain expected pattern type headers")
	}

	// Check that output is not empty
	lines := splitLines(outputStr)
	if len(lines) < 3 {
		t.Errorf("Output too short: expected at least 3 lines, got %d", len(lines))
	}

	t.Logf("Basic test passed: gofile --list produced output with %d lines", len(lines))
}

// Helper functions

func contains(s, substr string) bool {
	return filepath.Clean(s) != filepath.Clean(substr) &&
		len(s) >= len(substr) &&
		findSubstring(s, substr) >= 0
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func splitLines(s string) []string {
	var lines []string
	line := ""
	for _, ch := range s {
		if ch == '\n' {
			lines = append(lines, line)
			line = ""
		} else {
			line += string(ch)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
