//go:build golden
// +build golden

package golden

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// copyMagicFile copies a magic file from source to destination
func copyMagicFile(source, dest string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", source, err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dest, err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// generateExpectedOutput runs the system file command and saves the output as .expected
func generateExpectedOutput(magicFile string, expectedFile string) error {
	cmd := exec.Command("file", "-m", magicFile, "--list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if file command exists
		if _, err := exec.LookPath("file"); err != nil {
			return fmt.Errorf("file command not found: %w", err)
		}
		return fmt.Errorf("failed to run file --list: %w (output: %s)", err, string(output))
	}

	// Filter out warning messages from file command
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	var filteredLines []string
	for _, line := range lines {
		// Skip warning messages
		if strings.HasPrefix(line, "Warning:") {
			continue
		}
		filteredLines = append(filteredLines, line)
	}
	filteredOutput := []byte(strings.Join(filteredLines, "\n"))

	err = os.WriteFile(expectedFile, filteredOutput, 0644)
	if err != nil {
		return fmt.Errorf("failed to write expected output: %w", err)
	}

	return nil
}

// runGofileList runs the gofile command with --list flag
func runGofileList(gofilePath, magicFile string) ([]byte, error) {
	cmd := exec.Command(gofilePath, "-m", magicFile, "--list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run gofile --list: %w (output: %s)", err, string(output))
	}
	return output, nil
}

// compareOutputs compares actual output with expected output and returns differences
func compareOutputs(actual, expected []byte) (bool, string) {
	actualLines := strings.Split(strings.TrimSpace(string(actual)), "\n")
	expectedLines := strings.Split(strings.TrimSpace(string(expected)), "\n")

	if len(actualLines) != len(expectedLines) {
		return false, fmt.Sprintf("Line count mismatch: got %d lines, expected %d lines",
			len(actualLines), len(expectedLines))
	}

	var differences []string
	for i := 0; i < len(actualLines); i++ {
		if actualLines[i] != expectedLines[i] {
			differences = append(differences, fmt.Sprintf(
				"Line %d:\n  Expected: %s\n  Got:      %s",
				i+1, expectedLines[i], actualLines[i]))
		}
	}

	if len(differences) > 0 {
		return false, strings.Join(differences, "\n")
	}

	return true, ""
}

// ensureMagicFile ensures the magic file is copied to the test directory
func ensureMagicFile(sourcePath, destPath string) error {
	// Check if destination file exists
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		// Copy the file
		if err := copyMagicFile(sourcePath, destPath); err != nil {
			return fmt.Errorf("failed to copy magic file: %w", err)
		}
	}
	return nil
}

// ensureExpectedFile ensures the expected output file exists
func ensureExpectedFile(magicFile, expectedFile string, update bool) error {
	// If update flag is set or file doesn't exist, generate it
	if update {
		if err := generateExpectedOutput(magicFile, expectedFile); err != nil {
			return fmt.Errorf("failed to generate expected output: %w", err)
		}
		return nil
	}

	// Check if expected file exists
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		if err := generateExpectedOutput(magicFile, expectedFile); err != nil {
			return fmt.Errorf("failed to generate expected output: %w", err)
		}
	}
	return nil
}

// getMagicFiles returns a list of all magic files in the source directory
func getMagicFiles(sourceDir string) ([]string, error) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", sourceDir, err)
	}

	var magicFiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			magicFiles = append(magicFiles, entry.Name())
		}
	}

	return magicFiles, nil
}

// buildGofile builds the gofile binary and returns its path
func buildGofile(t *testing.T) string {
	t.Helper()

	// Build gofile binary in temp directory
	tempDir := t.TempDir()
	gofilePath := filepath.Join(tempDir, "gofile")

	// Get the project root correctly
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Failed to get current file path")
	}
	testDir := filepath.Dir(filename)
	projectRoot := filepath.Join(testDir, "..", "..")
	cmdPath := filepath.Join(projectRoot, "cmd", "gofile")

	cmd := exec.Command("go", "build", "-o", gofilePath, cmdPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build gofile: %v (output: %s)", err, string(output))
	}

	return gofilePath
}

// getTestDir returns the directory of the test file
func getTestDir() string {
	// Get the directory of this file using runtime
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		// Fallback to working directory
		dir, _ := os.Getwd()
		return dir
	}
	return filepath.Dir(filename)
}

// normalizeOutput normalizes the output for comparison
// This handles potential differences in formatting between implementations
func normalizeOutput(output []byte) []byte {
	// Remove trailing whitespace from each line
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}

	// Join back and trim final newlines
	normalized := strings.Join(lines, "\n")
	normalized = strings.TrimRight(normalized, "\n")

	return []byte(normalized)
}

// diffOutputs provides a detailed diff between two outputs
func diffOutputs(actual, expected []byte) string {
	actualLines := strings.Split(string(actual), "\n")
	expectedLines := strings.Split(string(expected), "\n")

	var buf bytes.Buffer

	// Find the maximum line count
	maxLines := len(actualLines)
	if len(expectedLines) > maxLines {
		maxLines = len(expectedLines)
	}

	for i := 0; i < maxLines; i++ {
		var actualLine, expectedLine string

		if i < len(actualLines) {
			actualLine = actualLines[i]
		}
		if i < len(expectedLines) {
			expectedLine = expectedLines[i]
		}

		if actualLine != expectedLine {
			fmt.Fprintf(&buf, "Line %d differs:\n", i+1)
			fmt.Fprintf(&buf, "- Expected: %q\n", expectedLine)
			fmt.Fprintf(&buf, "+ Got:      %q\n", actualLine)
			fmt.Fprintln(&buf)
		}
	}

	if len(actualLines) != len(expectedLines) {
		fmt.Fprintf(&buf, "Line count: got %d, expected %d\n",
			len(actualLines), len(expectedLines))
	}

	return buf.String()
}
