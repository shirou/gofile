package gofile

import (
	"testing"
)

func TestIdentifyFile(t *testing.T) {
	fi, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result, err := fi.IdentifyFile("testdata/test.pdf")
	if err != nil {
		t.Fatalf("IdentifyFile() error: %v", err)
	}
	if result == "" {
		t.Error("IdentifyFile() returned empty string")
	}
	t.Logf("result: %s", result)
}

func TestIdentifyBuffer(t *testing.T) {
	fi, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result := fi.IdentifyBuffer([]byte("%PDF-1.4 test"))
	if result == "" {
		t.Error("IdentifyBuffer() returned empty string")
	}
	t.Logf("result: %s", result)
}

func TestIdentifyFile_Empty(t *testing.T) {
	fi, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result, err := fi.IdentifyFile("testdata/empty")
	if err != nil {
		t.Fatalf("IdentifyFile() error: %v", err)
	}
	if result != "empty" {
		t.Errorf("expected 'empty', got %q", result)
	}
}

func TestIdentifyFile_Directory(t *testing.T) {
	fi, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result, err := fi.IdentifyFile("testdata")
	if err != nil {
		t.Fatalf("IdentifyFile() error: %v", err)
	}
	if result != "directory" {
		t.Errorf("expected 'directory', got %q", result)
	}
}
