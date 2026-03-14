package magic

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

//go:embed all:magicdata
var embeddedMagicFS embed.FS

// Options controls the behavior of file identification.
type Options struct {
	MimeType bool
	Brief    bool
}

// FileIdentifier is the main entry point for file identification.
type FileIdentifier struct {
	set     *MagicSet
	matcher *Matcher
	options Options
}

// New creates a FileIdentifier loading magic from the embedded database.
func New(opts Options) (*FileIdentifier, error) {
	magicFS, err := fs.Sub(embeddedMagicFS, "magicdata/Magdir")
	if err != nil {
		return nil, fmt.Errorf("embedded magic data: %w", err)
	}
	return NewFromFS(magicFS, opts)
}

// NewFromFS creates a FileIdentifier loading magic from a filesystem.
func NewFromFS(magicFS fs.FS, opts Options) (*FileIdentifier, error) {
	set := &MagicSet{NamedRules: make(map[string]int)}

	entries, err := fs.ReadDir(magicFS, ".")
	if err != nil {
		return nil, fmt.Errorf("reading magic dir: %w", err)
	}

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		data, err := fs.ReadFile(magicFS, de.Name())
		if err != nil {
			continue
		}
		parsed, err := ParseMagicBytes(de.Name(), data)
		if err != nil {
			continue
		}
		set.Entries = append(set.Entries, parsed...)
	}

	set.buildGroups()

	return &FileIdentifier{
		set:     set,
		matcher: NewMatcher(set),
		options: opts,
	}, nil
}

// NewFromDir creates a FileIdentifier loading magic from a directory path.
func NewFromDir(dir string, opts Options) (*FileIdentifier, error) {
	set, err := ParseMagicDir(dir)
	if err != nil {
		return nil, err
	}
	return &FileIdentifier{
		set:     set,
		matcher: NewMatcher(set),
		options: opts,
	}, nil
}

// IdentifyFile identifies a file by path.
func (fi *FileIdentifier) IdentifyFile(path string) (string, error) {
	// Check filesystem magic first
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	if !info.Mode().IsRegular() {
		return identifyFS(info), nil
	}

	if info.Size() == 0 {
		return "empty", nil
	}

	// Read file content
	maxBytes := 1024 * 1024 // 1MB max
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	buf = buf[:n]

	// Run ELF analysis for additional info (dynamically linked, interpreter, etc.)
	elfResult := tryELF(buf, f, info.Size())

	fileMode := info.Mode()
	if elfResult != nil && elfResult.isPIE {
		// DF_1_PIE sets execute bits for ${x?pie executable:shared object} expansion
		fileMode |= 0111
	} else if elfResult != nil && !elfResult.isPIE {
		// No DF_1_PIE: clear execute bits like C does (ms->mode &= ~0111)
		fileMode &^= 0111
	}

	result := fi.matcher.MatchWithMode(buf, fileMode)

	// Append ELF details after magic match
	if elfResult != nil {
		if extra := formatELFInfo(elfResult); extra != "" {
			result += ", " + extra
		}
	}

	return result, nil
}

// IdentifyBuffer identifies content from a byte buffer.
func (fi *FileIdentifier) IdentifyBuffer(buf []byte) string {
	return fi.matcher.Match(buf)
}

// identifyFS identifies a file by its filesystem metadata.
func identifyFS(info os.FileInfo) string {
	mode := info.Mode()
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "fifo (named pipe)"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0:
		if mode&os.ModeCharDevice != 0 {
			return "character special"
		}
		return "block special"
	default:
		return "special file"
	}
}

// ListEntry represents a magic entry for the -l flag.
type ListEntry struct {
	Strength int
	LineNo   int
	Desc     string
	MimeType string
	IsText   bool
}

// List returns all top-level magic entries with their strengths.
// Matches the C file(1) apprentice_list() behavior: propagates desc and
// mimetype from continuations when the top-level entry has empty values.
func (fi *FileIdentifier) List() []ListEntry {
	var result []ListEntry
	for _, g := range fi.set.Groups {
		top := g.Entries[0]
		if top.Type == TypeName {
			continue
		}
		desc := top.Desc
		mime := top.MimeType
		// Propagate desc/mime from first continuation that has one.
		for _, e := range g.Entries[1:] {
			if desc == "" && e.Desc != "" {
				desc = e.Desc
			}
			if mime == "" && e.MimeType != "" {
				mime = e.MimeType
			}
			if desc != "" && mime != "" {
				break
			}
		}
		// Strip leading \b escape (backspace) from propagated descriptions.
		// In C file(1), \b is stored as byte 0x08 which acts as backspace
		// when printed, effectively removing the preceding space.
		if strings.HasPrefix(desc, `\b`) {
			desc = desc[2:]
		}
		entry := ListEntry{
			Strength: g.Strength,
			LineNo:   top.LineNo,
			Desc:     desc,
			MimeType: mime,
			IsText:   top.StrFlags&StrFlagTextTest != 0 || isAutoTextTest(top),
		}
		result = append(result, entry)
	}
	return result
}
