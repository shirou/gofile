package magic

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Parser handles parsing of magic files
type Parser struct {
	database   *Database
	currentSet int
	errors     []error
}

// NewParser creates a new magic file parser
func NewParser() *Parser {
	return &Parser{
		database: &Database{
			Entries: make([]*Entry, 0),
			Sets:    make([]Set, 0),
		},
		currentSet: 0,
		errors:     make([]error, 0),
	}
}

// ParseFile parses a single magic file
func (p *Parser) ParseFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open magic file %s: %w", filename, err)
	}
	defer file.Close()
	
	return p.Parse(file, filename)
}

// Parse parses magic data from a reader
func (p *Parser) Parse(r io.Reader, filename string) error {
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	var currentEntry *Entry
	var entryStack []*Entry
	
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		
		// Skip empty lines and comments
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		
		// Handle special directives
		if strings.HasPrefix(line, "!:") {
			if currentEntry != nil {
				p.parseDirective(line, currentEntry)
				// Recalculate strength after applying directive
				if strings.HasPrefix(line, "!:strength") {
					currentEntry.Strength = currentEntry.CalculateStrength()
				}
			}
			continue
		}
		
		// Parse the magic line
		parsed, err := p.parseLine(line, lineNumber)
		if err != nil {
			p.errors = append(p.errors, fmt.Errorf("line %d: %w", lineNumber, err))
			continue
		}
		
		// Create entry from parsed line
		entry := &Entry{
			Level:      parsed.Level,
			Offset:     parsed.Offset,
			Type:       parsed.Type,
			Test:       parsed.Test,
			Message:    parsed.Message,
			LineNumber: lineNumber,
			SourceFile: filename,
			Children:   make([]*Entry, 0),
		}
		
		// Check if this is a FILE_NAME type (name pattern)
		if strings.ToLower(parsed.Type) == "name" {
			entry.IsNameType = true
		}
		
		// Determine if this is a binary or text pattern
		entry.Binary = p.isBinaryPattern(entry)
		
		// Handle hierarchy
		if entry.Level == 0 {
			// Top-level entry
			p.database.Entries = append(p.database.Entries, entry)
			currentEntry = entry
			entryStack = []*Entry{entry}
		} else {
			// Continuation line
			if len(entryStack) > 0 {
				// Find parent at appropriate level
				for len(entryStack) > entry.Level {
					entryStack = entryStack[:len(entryStack)-1]
				}
				if len(entryStack) > 0 {
					parent := entryStack[len(entryStack)-1]
					parent.Children = append(parent.Children, entry)
					if len(entryStack) == entry.Level {
						entryStack = append(entryStack, entry)
					} else {
						entryStack[entry.Level] = entry
					}
				}
			}
		}
		
		// Calculate initial strength
		entry.Strength = entry.CalculateStrength()
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading magic file: %w", err)
	}
	
	return nil
}

// parseLine parses a single magic line
func (p *Parser) parseLine(line string, lineNumber int) (*ParsedLine, error) {
	parsed := &ParsedLine{
		LineNumber: lineNumber,
		Raw:        line,
	}
	
	// Count leading '>' for level
	level := 0
	for i := 0; i < len(line) && line[i] == '>'; i++ {
		level++
	}
	parsed.Level = level
	
	// Remove leading '>' characters
	line = strings.TrimLeft(line, ">")
	
	// Split the line into fields
	// Format: offset type test message
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid magic line format: too few fields")
	}
	
	parsed.Offset = fields[0]
	parsed.Type = fields[1]
	
	// Find where the message starts (after test value)
	messageStart := -1
	inQuote := false
	escapeNext := false
	testEnd := len(parsed.Offset) + len(parsed.Type) + 2 // Account for spaces
	
	for i := testEnd; i < len(line); i++ {
		ch := line[i]
		if escapeNext {
			escapeNext = false
			continue
		}
		if ch == '\\' {
			escapeNext = true
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = !inQuote
		}
		if !inQuote && ch == '\t' {
			messageStart = i + 1
			break
		}
		if !inQuote && ch == ' ' && i+1 < len(line) && line[i+1] != ' ' {
			// Check if next non-space might be start of message
			nextFields := strings.Fields(line[i+1:])
			if len(nextFields) > 0 && !p.looksLikeTest(nextFields[0]) {
				messageStart = i + 1
				break
			}
		}
	}
	
	if messageStart > 0 && messageStart < len(line) {
		testPart := strings.TrimSpace(line[testEnd:messageStart])
		parsed.Test = testPart
		parsed.Message = strings.TrimSpace(line[messageStart:])
	} else {
		// Assume third field is test, rest is message
		parsed.Test = fields[2]
		if len(fields) > 3 {
			remainingFields := fields[3:]
			parsed.Message = strings.Join(remainingFields, " ")
		}
	}
	
	return parsed, nil
}

// looksLikeTest determines if a string looks like a test value
func (p *Parser) looksLikeTest(s string) bool {
	// Test values typically start with operators or are hex/numeric
	if len(s) == 0 {
		return false
	}
	
	// Check for operators
	if strings.ContainsAny(s[:1], "=!<>&^~") {
		return true
	}
	
	// Check for hex values
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return true
	}
	
	// Check if it's a number
	if _, err := strconv.ParseInt(s, 0, 64); err == nil {
		return true
	}
	
	return false
}

// parseDirective parses special directives like !:mime
func (p *Parser) parseDirective(line string, entry *Entry) {
	directive := strings.TrimPrefix(line, "!:")
	
	if strings.HasPrefix(directive, "mime") {
		// Handle both space and tab separators
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			entry.MimeType = strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(directive, "ext") {
		parts := strings.SplitN(directive, " ", 2)
		if len(parts) > 1 {
			exts := strings.Split(parts[1], "/")
			for _, ext := range exts {
				entry.Extensions = append(entry.Extensions, strings.TrimSpace(ext))
			}
		}
	} else if strings.HasPrefix(directive, "strength") {
		// Store strength modifier for later application
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			entry.StrengthMod = parts[1]
		}
		entry.Flags = append(entry.Flags, directive)
	}
}

// isBinaryPattern determines if a pattern is for binary data
func (p *Parser) isBinaryPattern(entry *Entry) bool {
	// In the original file command, most patterns are treated as binary
	// Only explicitly text-oriented patterns are classified as text
	
	// For compatibility with original file command, 
	// default all string patterns to binary
	// This matches the observed behavior where even shell scripts
	// are listed under "Binary patterns"
	return true
}

// GetDatabase returns the parsed database
func (p *Parser) GetDatabase() *Database {
	return p.database
}

// GetErrors returns any parsing errors encountered
func (p *Parser) GetErrors() []error {
	return p.errors
}

// OrganizeSets organizes entries into sets for --list output
func (p *Parser) OrganizeSets() {
	// Set 0: Regular file content patterns (FILE_CHECK)
	// Set 1: File name patterns (FILE_NAME)
	
	set0 := Set{
		Number:        0,
		BinaryEntries: make([]*Entry, 0),
		TextEntries:   make([]*Entry, 0),
	}
	
	set1 := Set{
		Number:        1,
		BinaryEntries: make([]*Entry, 0),
		TextEntries:   make([]*Entry, 0),
	}
	
	for _, entry := range p.database.Entries {
		if entry.IsNameType {
			// FILE_NAME type patterns go to Set 1
			if entry.Binary {
				set1.BinaryEntries = append(set1.BinaryEntries, entry)
			} else {
				set1.TextEntries = append(set1.TextEntries, entry)
			}
		} else {
			// Regular patterns go to Set 0
			if entry.Binary {
				set0.BinaryEntries = append(set0.BinaryEntries, entry)
			} else {
				set0.TextEntries = append(set0.TextEntries, entry)
			}
		}
	}
	
	p.database.Sets = []Set{set0, set1}
}

// LoadDefaultMagicFiles loads magic files from standard locations
func LoadDefaultMagicFiles() (*Database, error) {
	parser := NewParser()
	
	// Standard magic file locations
	magicPaths := []string{
		"/etc/magic",
		"/usr/share/misc/magic",
		"/usr/share/file/magic",
		filepath.Join(os.Getenv("HOME"), ".magic"),
	}
	
	// Check MAGIC environment variable
	if magicEnv := os.Getenv("MAGIC"); magicEnv != "" {
		// MAGIC can contain colon-separated paths
		customPaths := strings.Split(magicEnv, ":")
		magicPaths = append(customPaths, magicPaths...)
	}
	
	foundAny := false
	for _, path := range magicPaths {
		// Check if it's a file or directory
		info, err := os.Stat(path)
		if err != nil {
			continue // Skip if doesn't exist
		}
		
		if info.IsDir() {
			// If directory, look for magic files within
			magicFile := filepath.Join(path, "magic")
			if _, err := os.Stat(magicFile); err == nil {
				if err := parser.ParseFile(magicFile); err == nil {
					foundAny = true
				}
			}
			
			// Also check for magic.mgc (compiled magic)
			mgcFile := filepath.Join(path, "magic.mgc")
			if _, err := os.Stat(mgcFile); err == nil {
				// Note: We'd need to implement compiled magic parsing
				// For now, skip compiled files
			}
		} else {
			// It's a file, parse it directly
			if err := parser.ParseFile(path); err == nil {
				foundAny = true
			}
		}
	}
	
	if !foundAny {
		return nil, fmt.Errorf("no magic files found in standard locations")
	}
	
	// Organize into sets
	parser.OrganizeSets()
	
	return parser.GetDatabase(), nil
}

// ParseMagicData parses magic data from a string (for testing)
func ParseMagicData(data string) (*Database, error) {
	parser := NewParser()
	reader := strings.NewReader(data)
	
	if err := parser.Parse(reader, "inline"); err != nil {
		return nil, err
	}
	
	parser.OrganizeSets()
	return parser.GetDatabase(), nil
}