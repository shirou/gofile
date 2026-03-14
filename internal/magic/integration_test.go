package magic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testDir  = "testdata/tests"
	magicDir = "magicdata/Magdir"
)

func loadTestMagicSet(t *testing.T) *MagicSet {
	t.Helper()
	set, err := ParseMagicDir(magicDir)
	if err != nil {
		t.Fatalf("ParseMagicDir: %v", err)
	}
	return set
}

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}
	if _, err := os.Stat(testDir); os.IsNotExist(err) {
		t.Skip("testdata/tests not found; run 'make update-testdata' to set up")
	}

	set := loadTestMagicSet(t)

	entries, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".testfile") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".testfile")
		t.Run(base, func(t *testing.T) {
			// Read expected result
			resultPath := filepath.Join(testDir, base+".result")
			resultBytes, err := os.ReadFile(resultPath)
			if err != nil {
				t.Skipf("no result file: %v", err)
			}
			expected := strings.TrimRight(string(resultBytes), "\n")

			// Read testfile
			testfilePath := filepath.Join(testDir, e.Name())
			buf, err := os.ReadFile(testfilePath)
			if err != nil {
				t.Fatalf("reading testfile: %v", err)
			}

			// Check for custom magic
			customMagic := findCustomMagic(testDir, base)
			testSet := set
			if len(customMagic) > 0 {
				testSet = loadCustomMagic(t, customMagic)
			}

			// Check for flags file (e.g., -k for keep going/all matches)
			flagsPath := filepath.Join(testDir, base+".flags")
			flagsBytes, _ := os.ReadFile(flagsPath)
			flags := strings.TrimSpace(string(flagsBytes))

			m := NewMatcher(testSet)
			// 'x' flag: simulate executable file mode for ${x?...} expansion
			if strings.Contains(flags, "x") {
				m.fileMode = 0755
			}
			var result string
			if strings.Contains(flags, "k") {
				result = m.MatchAll(buf)
			} else {
				result = m.Match(buf)
			}

			if result != expected {
				t.Errorf("\ngot:  %q\nwant: %q", result, expected)
			}
		})
	}
}

func findCustomMagic(dir, base string) []string {
	pattern := filepath.Join(dir, base+"*.magic")
	matches, _ := filepath.Glob(pattern)
	return matches
}

func loadCustomMagic(t *testing.T, files []string) *MagicSet {
	t.Helper()
	set := &MagicSet{NamedRules: make(map[string]int)}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading custom magic %s: %v", f, err)
		}
		entries, err := ParseMagicBytes(filepath.Base(f), data)
		if err != nil {
			t.Fatalf("parsing custom magic %s: %v", f, err)
		}
		for _, e := range entries {
			idx := len(set.Entries)
			set.Entries = append(set.Entries, e)
			if e.Type == TypeName {
				set.NamedRules[string(e.Value.Str)] = idx
			}
		}
	}
	return set
}
