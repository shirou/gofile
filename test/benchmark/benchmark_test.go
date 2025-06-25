package benchmark

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkFileDetection benchmarks file detection performance
func BenchmarkFileDetection(b *testing.B) {
	projectRoot := getProjectRoot()
	testDataDir := filepath.Join(projectRoot, "test", "testdata", "file-tests", "db")
	
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		b.Skip("Test data not found. Run 'make setup-test' first.")
	}
	
	// Collect test files
	testFiles := collectTestFiles(testDataDir, 100) // Limit to 100 files for benchmarking
	
	if len(testFiles) == 0 {
		b.Skip("No test files found")
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, file := range testFiles {
			// TODO: Replace with actual detection
			// _, err := gofile.DetectFile(file)
			// if err != nil {
			//     b.Fatalf("Detection failed: %v", err)
			// }
			
			// Placeholder to prevent optimization
			_ = file
		}
	}
}

// BenchmarkMagicLoading benchmarks magic file loading
func BenchmarkMagicLoading(b *testing.B) {
	projectRoot := getProjectRoot()
	magicFile := filepath.Join(projectRoot, "test", "testdata", "magic", "magic.mgc")
	
	if _, err := os.Stat(magicFile); os.IsNotExist(err) {
		b.Skip("Magic file not found. Run 'make setup-test' first.")
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// TODO: Replace with actual magic loading
		// _, err := magic.LoadMagicFile(magicFile)
		// if err != nil {
		//     b.Fatalf("Magic loading failed: %v", err)
		// }
		
		// Placeholder
		_ = magicFile
	}
}

// BenchmarkByCategory benchmarks detection by file category
func BenchmarkByCategory(b *testing.B) {
	projectRoot := getProjectRoot()
	testDataDir := filepath.Join(projectRoot, "test", "testdata", "file-tests", "db")
	
	categories := []string{"txt", "png", "jpg", "pdf", "zip", "doc"}
	
	for _, category := range categories {
		categoryDir := filepath.Join(testDataDir, category)
		if _, err := os.Stat(categoryDir); os.IsNotExist(err) {
			continue
		}
		
		files := collectTestFiles(categoryDir, 20) // Limit per category
		if len(files) == 0 {
			continue
		}
		
		b.Run(category, func(b *testing.B) {
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				for _, file := range files {
					// TODO: Replace with actual detection
					// _, err := gofile.DetectFile(file)
					// if err != nil {
					//     b.Fatalf("Detection failed: %v", err)
					// }
					
					_ = file
				}
			}
		})
	}
}

// TestMemoryUsage tests memory usage during file detection
func TestMemoryUsage(t *testing.T) {
	projectRoot := getProjectRoot()
	testDataDir := filepath.Join(projectRoot, "test", "testdata", "file-tests", "db")
	
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		t.Skip("Test data not found. Run 'make setup-test' first.")
	}
	
	// Find a large file for testing
	var largeFile string
	err := filepath.Walk(testDataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && info.Size() > 1024*1024 { // > 1MB
			largeFile = path
			return filepath.SkipDir // Stop after finding one
		}
		
		return nil
	})
	
	if err != nil || largeFile == "" {
		t.Skip("No large files found for memory testing")
	}
	
	// TODO: Test memory usage
	// This would typically involve:
	// 1. Measuring memory before detection
	// 2. Running detection
	// 3. Measuring memory after detection
	// 4. Checking for memory leaks
	
	t.Logf("Would test memory usage with file: %s", largeFile)
}

// collectTestFiles collects test files from a directory
func collectTestFiles(dir string, limit int) []string {
	var files []string
	
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && !isSourceFile(path) {
			files = append(files, path)
			if len(files) >= limit {
				return filepath.SkipDir
			}
		}
		
		return nil
	})
	
	return files
}

// isSourceFile checks if a file is a .source.txt file
func isSourceFile(path string) bool {
	return filepath.Ext(path) == ".txt" && 
		   len(path) > 10 && 
		   path[len(path)-10:] == ".source.txt"
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
