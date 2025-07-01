//go:build golden
// +build golden

package utils

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GoldenTest represents a single golden test case
type GoldenTest struct {
	Name         string
	FilePath     string
	ExpectedPath string
	Category     string
}

// GoldenTestSuite manages a collection of golden tests
type GoldenTestSuite struct {
	Tests []GoldenTest
}

// LoadGoldenTests loads all golden test cases from the test data directory
func LoadGoldenTests(goldenDir string) (*GoldenTestSuite, error) {
	suite := &GoldenTestSuite{}

	samplesDir := filepath.Join(goldenDir, "samples")
	expectedDir := filepath.Join(goldenDir, "expected")

	err := filepath.Walk(samplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path from samples directory
		relPath, err := filepath.Rel(samplesDir, path)
		if err != nil {
			return err
		}

		// Construct expected file path
		expectedFile := filepath.Join(expectedDir, relPath+".out")

		// Check if expected file exists
		if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
			// Skip files without expected results
			return nil
		}

		// Extract category (first directory in path)
		category := strings.Split(relPath, string(filepath.Separator))[0]

		test := GoldenTest{
			Name:         relPath,
			FilePath:     path,
			ExpectedPath: expectedFile,
			Category:     category,
		}

		suite.Tests = append(suite.Tests, test)
		return nil
	})

	return suite, err
}

// ExpectedResult represents the expected output from file command
type ExpectedResult struct {
	Description string
	MimeType    string
	Encoding    string
	Brief       string
}

// LoadExpectedResult loads expected results for a test case
func (gt *GoldenTest) LoadExpectedResult() (*ExpectedResult, error) {
	result := &ExpectedResult{}

	// Load basic description
	if desc, err := loadFileOutput(gt.ExpectedPath); err == nil {
		result.Description = desc
	}

	// Load MIME type
	mimeFile := strings.TrimSuffix(gt.ExpectedPath, ".out") + ".mime"
	if mime, err := loadFileOutput(mimeFile); err == nil {
		result.MimeType = mime
	}

	// Load encoding
	encodingFile := strings.TrimSuffix(gt.ExpectedPath, ".out") + ".encoding"
	if encoding, err := loadFileOutput(encodingFile); err == nil {
		result.Encoding = encoding
	}

	// Load brief description
	briefFile := strings.TrimSuffix(gt.ExpectedPath, ".out") + ".brief"
	if brief, err := loadFileOutput(briefFile); err == nil {
		result.Brief = brief
	}

	return result, nil
}

// loadFileOutput loads and parses file command output
func loadFileOutput(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", fmt.Errorf("empty file: %s", filePath)
	}

	line := scanner.Text()

	// Extract description part (after filename and colon)
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid format in %s: %s", filePath, line)
	}

	return strings.TrimSpace(parts[1]), nil
}

// RunGoldenTest runs a single golden test
func RunGoldenTest(t *testing.T, test GoldenTest, detectFunc func(string) (string, string, error)) {
	t.Run(test.Name, func(t *testing.T) {
		// Load expected results
		expected, err := test.LoadExpectedResult()
		if err != nil {
			t.Fatalf("Failed to load expected results: %v", err)
		}

		// Run detection
		description, mimeType, err := detectFunc(test.FilePath)
		if err != nil {
			t.Fatalf("Detection failed: %v", err)
		}

		// Compare results
		if description != expected.Description {
			t.Errorf("Description mismatch:\nExpected: %s\nGot:      %s",
				expected.Description, description)
		}

		if mimeType != "" && expected.MimeType != "" && mimeType != expected.MimeType {
			t.Errorf("MIME type mismatch:\nExpected: %s\nGot:      %s",
				expected.MimeType, mimeType)
		}
	})
}

// FilterTestsByCategory filters tests by category
func (suite *GoldenTestSuite) FilterByCategory(categories ...string) *GoldenTestSuite {
	if len(categories) == 0 {
		return suite
	}

	categoryMap := make(map[string]bool)
	for _, cat := range categories {
		categoryMap[cat] = true
	}

	filtered := &GoldenTestSuite{}
	for _, test := range suite.Tests {
		if categoryMap[test.Category] {
			filtered.Tests = append(filtered.Tests, test)
		}
	}

	return filtered
}

// GetCategories returns all unique categories in the test suite
func (suite *GoldenTestSuite) GetCategories() []string {
	categoryMap := make(map[string]bool)
	for _, test := range suite.Tests {
		categoryMap[test.Category] = true
	}

	categories := make([]string, 0, len(categoryMap))
	for cat := range categoryMap {
		categories = append(categories, cat)
	}

	return categories
}
