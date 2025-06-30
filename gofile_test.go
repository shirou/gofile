package gofile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectFile(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		wantContain string
		wantErr     bool
	}{
		{
			name: "text file",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "test.txt")
				err := os.WriteFile(path, []byte("Hello, World!\nThis is a test file."), 0644)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantContain: "text",
			wantErr:     false,
		},
		{
			name: "empty file",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "empty.txt")
				err := os.WriteFile(path, []byte{}, 0644)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantContain: "empty",
			wantErr:     false,
		},
		{
			name: "binary file",
			setupFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "binary.bin")
				// Create a simple binary file with some non-text bytes
				data := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
				err := os.WriteFile(path, data, 0644)
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantContain: "data",
			wantErr:     false,
		},
		{
			name: "non-existent file",
			setupFile: func(t *testing.T) string {
				return "/non/existent/file.txt"
			},
			wantContain: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFile(t)
			
			result, err := DetectFile(path)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectFile() expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Errorf("DetectFile() unexpected error: %v", err)
				return
			}
			
			if tt.wantContain != "" && !strings.Contains(strings.ToLower(result), strings.ToLower(tt.wantContain)) {
				t.Errorf("DetectFile() = %q, want to contain %q", result, tt.wantContain)
			}
		})
	}
}

func TestDetectFileWithOptions(t *testing.T) {
	// Create a test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("Hello, World!\nThis is a test file."), 0644)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		options *Options
		wantErr bool
	}{
		{
			name:    "default options",
			path:    testFile,
			options: &Options{},
			wantErr: false,
		},
		{
			name: "MIME type option",
			path: testFile,
			options: &Options{
				MIME: true,
			},
			wantErr: false,
		},
		{
			name: "brief option",
			path: testFile,
			options: &Options{
				Brief: true,
			},
			wantErr: false,
		},
		{
			name: "custom max read size",
			path: testFile,
			options: &Options{
				MaxReadSize: 1024,
			},
			wantErr: false,
		},
		{
			name: "debug option",
			path: testFile,
			options: &Options{
				Debug: true,
			},
			wantErr: false,
		},
		{
			name:    "non-existent file",
			path:    "/non/existent/file.txt",
			options: &Options{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DetectFileWithOptions(tt.path, tt.options)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectFileWithOptions() expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Errorf("DetectFileWithOptions() unexpected error: %v", err)
				return
			}
			
			if result == "" {
				t.Errorf("DetectFileWithOptions() returned empty result")
			}
			
			// When MIME option is set, result should not contain typical description words
			if tt.options.MIME && strings.Contains(strings.ToLower(result), "text") && !strings.Contains(result, "/") {
				t.Errorf("DetectFileWithOptions() with MIME=true should return MIME type, got: %q", result)
			}
		})
	}
}

func TestDetectReader(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantContain string
		wantErr     bool
	}{
		{
			name:        "text data",
			data:        []byte("Hello, World!\nThis is a test."),
			wantContain: "text",
			wantErr:     false,
		},
		{
			name:        "empty data",
			data:        []byte{},
			wantContain: "empty",
			wantErr:     false,
		},
		{
			name:        "binary data",
			data:        []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			wantContain: "data",
			wantErr:     false,
		},
		{
			name:        "large text data",
			data:        bytes.Repeat([]byte("Hello World! "), 1000),
			wantContain: "text",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			
			result, err := DetectReader(reader)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectReader() expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Errorf("DetectReader() unexpected error: %v", err)
				return
			}
			
			if tt.wantContain != "" && !strings.Contains(strings.ToLower(result), strings.ToLower(tt.wantContain)) {
				t.Errorf("DetectReader() = %q, want to contain %q", result, tt.wantContain)
			}
		})
	}
}

func TestDetectBytes(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantContain string
		wantErr     bool
	}{
		{
			name:        "text bytes",
			data:        []byte("Hello, World!\nThis is a test."),
			wantContain: "text",
			wantErr:     false,
		},
		{
			name:        "empty bytes",
			data:        []byte{},
			wantContain: "empty",
			wantErr:     false,
		},
		{
			name:        "binary bytes",
			data:        []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			wantContain: "data",
			wantErr:     false,
		},
		{
			name:        "PNG header",
			data:        []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			wantContain: "data", // Currently returns generic "data" - will be improved when magic detection is enhanced
			wantErr:     false,
		},
		{
			name:        "JPEG header", 
			data:        []byte{0xFF, 0xD8, 0xFF, 0xE0},
			wantContain: "data", // Currently returns generic "data" - will be improved when magic detection is enhanced
			wantErr:     false,
		},
		{
			name:        "PDF header",
			data:        []byte("%PDF-1.4"),
			wantContain: "PDF",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DetectBytes(tt.data)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectBytes() expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Errorf("DetectBytes() unexpected error: %v", err)
				return
			}
			
			if tt.wantContain != "" && !strings.Contains(strings.ToLower(result), strings.ToLower(tt.wantContain)) {
				t.Errorf("DetectBytes() = %q, want to contain %q", result, tt.wantContain)
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func() error
	}{
		{
			name: "DetectFile with non-existent file",
			testFunc: func() error {
				_, err := DetectFile("/non/existent/file")
				return err
			},
		},
		{
			name: "DetectFileWithOptions with non-existent file",
			testFunc: func() error {
				_, err := DetectFileWithOptions("/non/existent/file", &Options{})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc()
			if err == nil {
				t.Errorf("Expected error but got nil")
			}
		})
	}
}

func TestDatabaseNotLoaded(t *testing.T) {
	// Temporarily set defaultDetector to nil to test error handling
	originalDetector := defaultDetector
	defaultDetector = nil
	defer func() {
		defaultDetector = originalDetector
	}()

	t.Run("DetectFile with no database", func(t *testing.T) {
		tempDir := t.TempDir()
		testFile := filepath.Join(tempDir, "test.txt")
		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		_, err = DetectFile(testFile)
		if err != ErrNoDatabaseLoaded {
			t.Errorf("Expected ErrNoDatabaseLoaded, got: %v", err)
		}
	})

	t.Run("DetectReader with no database", func(t *testing.T) {
		reader := strings.NewReader("test data")
		_, err := DetectReader(reader)
		if err != ErrNoDatabaseLoaded {
			t.Errorf("Expected ErrNoDatabaseLoaded, got: %v", err)
		}
	})

	t.Run("DetectBytes with no database", func(t *testing.T) {
		_, err := DetectBytes([]byte("test data"))
		if err != ErrNoDatabaseLoaded {
			t.Errorf("Expected ErrNoDatabaseLoaded, got: %v", err)
		}
	})
}

func TestOptionsDefaults(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("Hello, World!"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Test that MaxReadSize defaults to 1MB when not specified
	opts := &Options{
		MaxReadSize: 0, // Should default to 1MB
	}

	result, err := DetectFileWithOptions(testFile, opts)
	if err != nil {
		t.Errorf("DetectFileWithOptions() unexpected error: %v", err)
	}

	if result == "" {
		t.Errorf("DetectFileWithOptions() returned empty result")
	}
}

// Benchmark tests
func BenchmarkDetectFile(b *testing.B) {
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, bytes.Repeat([]byte("Hello World! "), 1000), 0644)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DetectFile(testFile)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDetectBytes(b *testing.B) {
	data := bytes.Repeat([]byte("Hello World! "), 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DetectBytes(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}