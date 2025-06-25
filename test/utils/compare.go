package utils

import (
	"fmt"
	"strings"
)

// ComparisonResult represents the result of comparing two file detection results
type ComparisonResult struct {
	Match            bool
	DescriptionMatch bool
	MimeTypeMatch    bool
	EncodingMatch    bool
	Differences      []string
}

// CompareResults compares actual results with expected results
func CompareResults(actual, expected *DetectionResult) *ComparisonResult {
	result := &ComparisonResult{
		Match:            true,
		DescriptionMatch: true,
		MimeTypeMatch:    true,
		EncodingMatch:    true,
		Differences:      []string{},
	}
	
	// Compare descriptions
	if !compareStrings(actual.Description, expected.Description) {
		result.Match = false
		result.DescriptionMatch = false
		result.Differences = append(result.Differences, 
			fmt.Sprintf("Description: expected '%s', got '%s'", 
				expected.Description, actual.Description))
	}
	
	// Compare MIME types
	if !compareStrings(actual.MimeType, expected.MimeType) {
		result.Match = false
		result.MimeTypeMatch = false
		result.Differences = append(result.Differences, 
			fmt.Sprintf("MIME type: expected '%s', got '%s'", 
				expected.MimeType, actual.MimeType))
	}
	
	// Compare encodings
	if !compareStrings(actual.Encoding, expected.Encoding) {
		result.Match = false
		result.EncodingMatch = false
		result.Differences = append(result.Differences, 
			fmt.Sprintf("Encoding: expected '%s', got '%s'", 
				expected.Encoding, actual.Encoding))
	}
	
	return result
}

// DetectionResult represents the result of file detection
type DetectionResult struct {
	Description string
	MimeType    string
	Encoding    string
	Confidence  float64
}

// compareStrings compares two strings with normalization
func compareStrings(actual, expected string) bool {
	// Normalize strings
	actual = normalizeString(actual)
	expected = normalizeString(expected)
	
	return actual == expected
}

// normalizeString normalizes a string for comparison
func normalizeString(s string) string {
	// Trim whitespace
	s = strings.TrimSpace(s)
	
	// Convert to lowercase for case-insensitive comparison
	s = strings.ToLower(s)
	
	// Normalize common variations
	replacements := map[string]string{
		"jpeg":     "jpg",
		"tiff":     "tif", 
		"mpeg":     "mpg",
		"ascii":    "text",
		"utf-8":    "utf8",
		"iso-8859": "iso8859",
	}
	
	for old, new := range replacements {
		s = strings.ReplaceAll(s, old, new)
	}
	
	return s
}

// CalculateAccuracy calculates accuracy percentage from comparison results
func CalculateAccuracy(results []*ComparisonResult) float64 {
	if len(results) == 0 {
		return 0.0
	}
	
	matches := 0
	for _, result := range results {
		if result.Match {
			matches++
		}
	}
	
	return float64(matches) / float64(len(results)) * 100.0
}

// GenerateReport generates a detailed comparison report
func GenerateReport(results []*ComparisonResult, testNames []string) string {
	var report strings.Builder
	
	accuracy := CalculateAccuracy(results)
	
	report.WriteString(fmt.Sprintf("Test Results Summary\n"))
	report.WriteString(fmt.Sprintf("====================\n"))
	report.WriteString(fmt.Sprintf("Total tests: %d\n", len(results)))
	report.WriteString(fmt.Sprintf("Passed: %d\n", countMatches(results)))
	report.WriteString(fmt.Sprintf("Failed: %d\n", len(results)-countMatches(results)))
	report.WriteString(fmt.Sprintf("Accuracy: %.2f%%\n\n", accuracy))
	
	// Detailed failures
	report.WriteString("Failed Tests:\n")
	report.WriteString("=============\n")
	
	for i, result := range results {
		if !result.Match {
			testName := "unknown"
			if i < len(testNames) {
				testName = testNames[i]
			}
			
			report.WriteString(fmt.Sprintf("Test: %s\n", testName))
			for _, diff := range result.Differences {
				report.WriteString(fmt.Sprintf("  - %s\n", diff))
			}
			report.WriteString("\n")
		}
	}
	
	return report.String()
}

// countMatches counts the number of matching results
func countMatches(results []*ComparisonResult) int {
	count := 0
	for _, result := range results {
		if result.Match {
			count++
		}
	}
	return count
}
