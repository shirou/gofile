package magic

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
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

// LoadFile loads a single magic file
func (p *Parser) LoadFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open magic file %s: %w", filename, err)
	}
	defer file.Close()

	return p.LoadOne(file, filename)
}

// addEntry adds a magic entry to the appropriate location in the database
// This corresponds to C's addentry function in apprentice.c
func (p *Parser) addEntry(me *Entry) {
	if me == nil || me.Mp == nil {
		return
	}

	// Determine which set based on type (FILE_NAME goes to set 1, others to set 0)
	setIndex := 0
	if me.Mp.Type == TypeName {
		setIndex = 1
	}

	// Get or create the set
	for len(p.database.Sets) <= setIndex {
		p.database.Sets = append(p.database.Sets, Set{
			Number:        len(p.database.Sets),
			BinaryEntries: make([]*Entry, 0),
			TextEntries:   make([]*Entry, 0),
		})
	}

	set := &p.database.Sets[setIndex]

	// Determine test type using the same logic as the C implementation
	// This will properly classify entries as binary or text based on their type and flags
	testType := me.GetTestType()
	if testType == TEXTTEST {
		set.TextEntries = append(set.TextEntries, me)
	} else {
		set.BinaryEntries = append(set.BinaryEntries, me)
	}

	// Also add to the main entries list for backward compatibility
	p.database.Entries = append(p.database.Entries, me)
}

// LoadOne loads magic data from a reader (port of load_1 from apprentice.c)
func (p *Parser) LoadOne(r io.Reader, filename string) error {
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	var me Entry // Current magic entry being processed (like C's me)

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Handle empty lines (skip them) - corresponds to len == 0 check in C
		if len(line) == 0 {
			continue
		}

		// Skip comments (lines starting with #) and empty lines after stripping newline
		if line[0] == '#' || line[0] == '\x00' {
			continue
		}
		

		// Handle bang directives (!:mime, !:apple, !:ext, !:strength)
		if len(line) > 2 && line[0] == '!' && line[1] == ':' {
			// In C code, this operates on 'me' (current magic entry)
			if me.Mp != nil {
				// parseExtra handles !:mime, !:apple, !:ext, !:strength
				p.parseExtra(line, &me)
			}
			continue
		}

		// default case in C switch - parse the line
	again:
		// Parse the magic line - returns (shouldAdd, error)
		shouldAdd, err := p.parseLineWithResult(&me, line, lineNumber, filename)
		if err != nil {
			p.errors = append(p.errors, fmt.Errorf("line %d: %w", lineNumber, err))
			continue
		}

		if shouldAdd {
			// Line parsed and ready to add (addentry in C)
			// Make a copy of the entry to add
			copyEntry := me
			p.addEntry(&copyEntry)
			// Reset me for next entry
			me = Entry{}
			// Now parse the same line again as a new top-level entry
			goto again // C code uses goto again to reparse
		}
		// Otherwise continue to next line
	}

	// Add final entry if exists (like C code line 1415-1416)
	if me.Mp != nil {
		copyEntry := me
		p.addEntry(&copyEntry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading magic file: %w", err)
	}

	return nil
}

// parseLineWithResult parses a magic line and returns whether to add the entry
// Returns: (shouldAdd bool, err error)
// - shouldAdd=true means add current entry and reparse this line
// - shouldAdd=false means continue to next line
// - err!=nil means parsing error occurred
func (p *Parser) parseLineWithResult(me *Entry, line string, lineNumber int, filename string) (bool, error) {
	// Check if this is a top-level line (no leading whitespace)
	// If we have a current entry and this is a new top-level, we need to save current first
	if len(line) > 0 && line[0] != '>' && line[0] != '\t' && line[0] != ' ' {
		if me.Mp != nil {
			// We have a current entry, need to add it before processing this new one
			return true, nil
		}
	}

	// Parse the line into a Magic structure
	m, err := p.parseMagicLine(line, lineNumber)
	if err != nil {
		return false, err
	}

	if m == nil {
		return false, nil // Empty or comment line, continue
	}

	// Handle continuation levels
	if m.ContLevel != 0 {
		// Continuation line
		if me.Mp == nil {
			return false, fmt.Errorf("continuation with no current entry")
		}
		// Store as continuation
		// Find the correct parent based on continuation level
		newEntry := &Entry{
			Mp:       m,
			Children: make([]*Entry, 0),
		}

		// For level 1, add directly to top-level entry
		if m.ContLevel == 1 {
			me.Children = append(me.Children, newEntry)
		} else {
			// For level 2+, add to the last child at the appropriate level
			// Find parent at level m.ContLevel - 1
			parent := me
			for i := 1; i < int(m.ContLevel); i++ {
				if len(parent.Children) > 0 {
					parent = parent.Children[len(parent.Children)-1]
				} else {
					return false, fmt.Errorf("continuation level %d with no parent at level %d", m.ContLevel, i)
				}
			}
			parent.Children = append(parent.Children, newEntry)
		}
		me.ContCount++
	} else {
		// Top level entry - start new entry
		me.Mp = m
		me.ContCount = 1
		me.MaxCount = 32
		me.Children = make([]*Entry, 0)
	}

	return false, nil
}

// parseMagicLine parses one line from magic file into a Magic structure
// This is a helper for parseLineWithResult
func (p *Parser) parseMagicLine(line string, lineNumber int) (*Magic, error) {
	if line == "" {
		return nil, nil // Empty line, not an error
	}

	var m *Magic
	l := line
	contLevel := uint32(0)

	// Parse continuation level (>>>>>)
	for len(l) > 0 && l[0] == '>' {
		l = l[1:]
		contLevel++
	}

	if contLevel != 0 {
		// Continuation line - this will be handled by the caller
		// For now, we'll create a new magic entry for it
		m = &Magic{}
		m.ContLevel = uint8(contLevel)
	} else {
		// New top-level entry
		m = &Magic{}
		m.ContLevel = 0
		m.FactorOp = FILE_FACTOR_OP_NONE
	}

	m.Lineno = uint32(lineNumber)

	// Check for '&' (OFFADD flag)
	if len(l) > 0 && l[0] == '&' {
		l = l[1:]
		m.Flag |= OFFADD
	}

	// Check for '(' (indirect offset)
	if len(l) > 0 && l[0] == '(' {
		l = l[1:]
		m.Flag |= INDIR
		if m.Flag&OFFADD != 0 {
			m.Flag = (m.Flag &^ OFFADD) | INDIROFFADD
		}

		// Check for another '&' inside parentheses
		if len(l) > 0 && l[0] == '&' {
			l = l[1:]
			m.Flag |= OFFADD
		}
	}

	// Indirect offsets are not valid at level 0
	if m.ContLevel == 0 && (m.Flag&(OFFADD|INDIROFFADD)) != 0 {
		return nil, fmt.Errorf("relative offset at level 0")
	}

	// Get offset, then skip over it
	if len(l) > 0 && (l[0] == '-' || l[0] == '+') {
		l = l[1:]
		if l[0] == '-' {
			m.Flag |= OFFNEGATIVE
		} else {
			m.Flag |= OFFPOSITIVE
		}
	}

	// Parse offset number
	offsetStr, newL := parseNumber(l)
	if offsetStr == "" {
		return nil, fmt.Errorf("invalid offset '%s'", l)
	}
	l = newL

	if offset, err := strconv.ParseInt(offsetStr, 0, 32); err == nil {
		m.Offset = int32(offset)
	} else {
		return nil, fmt.Errorf("invalid offset '%s': %v", offsetStr, err)
	}

	// Parse indirect offset details if present
	if m.Flag&INDIR != 0 {
		m.InType = TypeLong
		m.InOffset = 0
		m.InOp = 0

		// Read [.,lbs][+-]nnnnn)
		if len(l) > 0 && (l[0] == '.' || l[0] == ',') {
			if l[0] == ',' {
				m.InOp |= FILE_OPSIGNED
			}
			l = l[1:]

			if len(l) > 0 {
				switch l[0] {
				case 'l':
					m.InType = TypeLelong
				case 'L':
					m.InType = TypeBelong
				case 'm':
					m.InType = TypeMelong
				case 'h', 's':
					m.InType = TypeLeshort
				case 'H', 'S':
					m.InType = TypeBeshort
				case 'c', 'b', 'C', 'B':
					m.InType = TypeByte
				case 'e', 'f', 'g':
					m.InType = TypeLedouble
				case 'E', 'F', 'G':
					m.InType = TypeBedouble
				case 'i':
					m.InType = TypeLeid3
				case 'I':
					m.InType = TypeBeid3
				case 'o':
					m.InType = TypeOctal
				case 'q':
					m.InType = TypeLequad
				case 'Q':
					m.InType = TypeBequad
				default:
					return nil, fmt.Errorf("indirect offset type '%c' invalid", l[0])
				}
				l = l[1:]
			}
		}

		// Handle ~ (inverse)
		if len(l) > 0 && l[0] == '~' {
			m.InOp |= FILE_OPINVERSE
			l = l[1:]
		}

		// Handle operators
		if len(l) > 0 {
			if op := getOp(l[0]); op != 0xFF {
				m.InOp |= op
				l = l[1:]
			}
		}

		// Handle nested indirect
		if len(l) > 0 && l[0] == '(' {
			m.InOp |= FILE_OPINDIRECT
			l = l[1:]
		}

		// Parse in_offset
		if len(l) > 0 && (isDigit(l[0]) || l[0] == '-') {
			offsetStr, newL := parseNumber(l)
			if offset, err := strconv.ParseInt(offsetStr, 0, 32); err == nil {
				m.InOffset = int32(offset)
				l = newL
			}
		}

		// Check for closing parentheses
		if len(l) == 0 || l[0] != ')' {
			return nil, fmt.Errorf("missing ')' in indirect offset")
		}
		l = l[1:]

		if (m.InOp&FILE_OPINDIRECT) != 0 && (len(l) == 0 || l[0] != ')') {
			return nil, fmt.Errorf("missing ')' in indirect offset")
		}
		if (m.InOp & FILE_OPINDIRECT) != 0 {
			l = l[1:]
		}
	}

	// Skip whitespace (EATAB)
	l = strings.TrimLeft(l, " \t")

	// Parse the type
	typeStr := ""
	if len(l) > 0 && l[0] == 'u' {
		// Unsigned type prefix
		l = l[1:]
		magicType, rest, err := getType(l)
		if err == nil {
			typeStr = magicType.ToString()
			l = rest
		} else {
			// Try as SUS integer type
			magicType, rest := getStandardIntegerType("u" + l)
			typeStr = magicType.ToString()
			l = rest
		}
		m.Flag |= UNSIGNED
	} else {
		// Regular type
		magicType, rest, err := getType(l)
		if err == nil {
			typeStr = magicType.ToString()
			l = rest
		} else {
			// Try SUS integer type
			if len(l) > 0 && l[0] == 'd' {
				magicType, rest := getStandardIntegerType(l)
				typeStr = magicType.ToString()
				l = rest
			} else if len(l) > 0 && l[0] == 's' && (len(l) == 1 || !isAlpha(l[1])) {
				typeStr = "string"
				l = l[1:]
			}
		}
	}

	if typeStr == "" {
		// Try special types
		typeStr, l = getSpecialType(l)
	}

	if typeStr == "" {
		return nil, fmt.Errorf("type '%s' invalid", l)
	}

	m.TypeStr = typeStr
	
	// Convert TypeStr to Type enum
	m.Type = StringToMagicType(typeStr)
	if m.Type == TypeInvalid {
		return nil, fmt.Errorf("invalid magic type '%s'", typeStr)
	}

	// Check FILE_NAME restrictions
	if typeStr == "name" && contLevel != 0 {
		return nil, fmt.Errorf("'name' entries can only be declared at top level")
	}

	// Handle mask operations
	m.MaskOp = 0
	if len(l) > 0 && l[0] == '~' {
		if !isStringType(typeStr) {
			m.MaskOp |= FILE_OPINVERSE
		}
		l = l[1:]
	}

	m.Count = 0
	m.Flags = 0
	if typeStr == "pstring" {
		m.Flags = PSTRING_1_LE
	}

	// Handle operators and modifiers
	if len(l) > 0 {
		if op := getOp(l[0]); op != 0xFF {
			if isStringType(typeStr) {
				if op != FILE_OPDIVIDE {
					return nil, fmt.Errorf("invalid string/indirect op: '%c'", l[0])
				}
				// Parse string modifiers
				if typeStr == "indirect" {
					if err := parseIndirectModifier(m, &l); err != nil {
						return nil, err
					}
				} else {
					if err := ParseStringModifier(m, &l); err != nil {
						return nil, err
					}
				}
			} else {
				ParseOpModifier(m, &l, op)
			}
		}
	}

	// Skip whitespace (EATAB)
	l = strings.TrimLeft(l, " \t")

	// Parse relation
	if len(l) > 0 {
		switch l[0] {
		case '>', '<':
			m.Reln = l[0]
			l = l[1:]
			if len(l) > 0 && l[0] == '=' {
				// >= and <= not officially supported but skip it
				l = l[1:]
			}
		case '&', '^', '=':
			m.Reln = l[0]
			l = l[1:]
			if len(l) > 0 && l[0] == '=' {
				// Skip extra '=' for compatibility
				l = l[1:]
			}
		case '!':
			m.Reln = l[0]
			l = l[1:]
		default:
			// Check for 'x' (any value) but only if it's followed by whitespace or end of string
			if l[0] == 'x' && (len(l) == 1 || isSpace(l[1])) {
				m.Reln = 'x'
				l = l[1:]
			} else {
				m.Reln = '=' // Default relation
			}
		}
	} else {
		m.Reln = '='
	}

	// Store relation in OperatorStr for compatibility
	m.OperatorStr = string(m.Reln)

	// Get value part (except for 'x' relation)
	if m.Reln != 'x' {
		if len(l) == 0 {
			return nil, fmt.Errorf("incomplete magic '%s'", line)
		}
		// Parse the value up to whitespace
		valueEnd := 0
		for valueEnd < len(l) && !isSpace(l[valueEnd]) {
			valueEnd++
		}
		if valueEnd > 0 {
			m.TestStr = l[:valueEnd]
			// Parse the test value into the appropriate Value field
			if err := getValue(m, m.TestStr); err != nil {
				return nil, fmt.Errorf("error parsing value '%s': %w", m.TestStr, err)
			}
			l = l[valueEnd:]
		} else {
			m.TestStr = ""
		}
	} else {
		// For 'x' relation, TestStr should be "x"
		m.TestStr = "x"
	}

	// Skip whitespace (EATAB)
	l = strings.TrimLeft(l, " \t")

	// Get description
	if len(l) > 0 {
		// Handle \b for no space
		if l[0] == '\b' {
			l = l[1:]
			m.Flag |= NOSPACE
		} else if len(l) > 1 && l[0] == '\\' && l[1] == 'b' {
			l = l[2:]
			m.Flag |= NOSPACE
		}

		// Copy description
		if len(l) > MAXDESC-1 {
			l = l[:MAXDESC-1]
		}
		copy(m.Desc[:], []byte(l))
		m.MessageStr = l
	}

	// Store original values for easier access
	m.OffsetStr = fmt.Sprintf("%d", m.Offset)

	// Calculate initial strength
	m.Strength = m.apprenticeMagicStrength()

	return m, nil
}

// Helper functions

// getStr converts a string containing C character escapes.
// Stops at an unescaped space or tab.
// This is a port of the getstr function from apprentice.c line 3021
func getStr(s string, warn bool) (string, error) {
	if s == "" {
		return "", nil
	}

	var result []byte
	i := 0
	bracketNesting := 0

	for i < len(s) {
		c := s[i]

		// Stop at unescaped whitespace
		if c == ' ' || c == '\t' {
			break
		}

		if c != '\\' {
			// Handle bracket nesting for regex patterns
			if c == '[' {
				bracketNesting++
			}
			if c == ']' && bracketNesting > 0 {
				bracketNesting--
			}
			result = append(result, c)
			i++
			continue
		}

		// Handle escape sequences
		i++ // Skip the backslash
		if i >= len(s) {
			// Incomplete escape at end of string
			if warn {
				return "", fmt.Errorf("incomplete escape sequence at end of string")
			}
			break
		}

		switch s[i] {
		case ' ':
			// Escaped space
			result = append(result, ' ')
		case '>', '<', '&', '^', '=', '!':
			// Relations - keep as-is
			result = append(result, s[i])
		case '\\':
			// Escaped backslash
			result = append(result, '\\')
		case 'a':
			result = append(result, '\a')
		case 'b':
			result = append(result, '\b')
		case 'f':
			result = append(result, '\f')
		case 'n':
			result = append(result, '\n')
		case 'r':
			result = append(result, '\r')
		case 't':
			result = append(result, '\t')
		case 'v':
			result = append(result, '\v')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			// Octal escape sequence (up to 3 digits)
			val := s[i] - '0'
			j := 1
			for j < 3 && i+j < len(s) && s[i+j] >= '0' && s[i+j] <= '7' {
				val = val*8 + (s[i+j] - '0')
				j++
			}
			result = append(result, byte(val))
			i += j - 1
		case 'x':
			// Hex escape sequence (up to 2 hex digits)
			val := byte('x') // Default if no valid hex digits
			if i+1 < len(s) {
				c1 := hexToInt(s[i+1])
				if c1 >= 0 {
					val = byte(c1)
					i++ // Increment for first hex digit
					if i+1 < len(s) {
						c2 := hexToInt(s[i+1])
						if c2 >= 0 {
							val = byte((c1 << 4) + c2)
							i++ // Extra increment for second hex digit
						}
					}
				}
			}
			result = append(result, val)
		case '.':
			// Special handling for regex dot - the C code warns about this
			if warn && bracketNesting == 0 {
				// In production, we'd log a warning about escaped dot in regex
			}
			result = append(result, '.')
		default:
			// For any other character after backslash, keep it as-is
			// The C code has more complex warning logic here
			result = append(result, s[i])
		}
		i++
	}

	return string(result), nil
}

// hexToInt converts a single hex character to its integer value
// Returns -1 if not a valid hex character
// This is a port of the hextoint function from apprentice.c line 3199
func hexToInt(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	if c >= 'A' && c <= 'F' {
		return int(c - 'A' + 10)
	}
	return -1
}

// parseNumber extracts a number from the beginning of a string
func parseNumber(s string) (string, string) {
	if len(s) == 0 {
		return "", s
	}

	i := 0
	if s[0] == '-' || s[0] == '+' {
		i++
	}

	// Hex number
	if len(s) > i+1 && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		i += 2
		for i < len(s) && isHexDigit(s[i]) {
			i++
		}
		return s[:i], s[i:]
	}

	// Regular number
	for i < len(s) && isDigit(s[i]) {
		i++
	}

	if i == 0 || (i == 1 && (s[0] == '-' || s[0] == '+')) {
		return "", s
	}

	return s[:i], s[i:]
}

// getOp returns the operation code for a character
func getOp(c byte) uint8 {
	switch c {
	case '&':
		return FILE_OPAND
	case '|':
		return FILE_OPOR
	case '^':
		return FILE_OPXOR
	case '+':
		return FILE_OPADD
	case '-':
		return FILE_OPMINUS
	case '*':
		return FILE_OPMULTIPLY
	case '/':
		return FILE_OPDIVIDE
	case '%':
		return FILE_OPMODULO
	default:
		return 0xFF // Invalid
	}
}

// getType extracts a type name from the string
func getType(s string) (MagicType, string, error) {
	types := []string{
		"byte", "short", "long", "quad",
		"beshort", "belong", "bequad",
		"leshort", "lelong", "lequad",
		"melong",
		"float", "befloat", "lefloat",
		"double", "bedouble", "ledouble",
		"date", "bedate", "ledate", "medate",
		"ldate", "beldate", "leldate", "meldate",
		"qdate", "beqdate", "leqdate",
		"qldate", "beqldate", "leqldate",
		"qwdate", "beqwdate", "leqwdate",
		"string", "pstring", "bestring16", "lestring16",
		"search", "regex", "default",
		"indirect", "use", "name", "clear",
		"der", "guid", "offset",
		"bevarint", "levarint",
		"msdosdate", "bemsdosdate", "lemsdosdate",
		"msdostime", "bemsdostime", "lemsdostime",
		"beid3", "leid3",
		"octal",
	}

	for _, typ := range types {
		if strings.HasPrefix(s, typ) {
			return MagicTypeFromString(typ), s[len(typ):], nil // rest of the string
		}
	}

	return TypeInvalid, s, fmt.Errorf("unknown type: %s", s)
}

// getSpecialType extracts special type names
func getSpecialType(s string) (string, string) {
	types := []string{
		"der", "name", "use", "octal",
	}

	for _, typ := range types {
		if strings.HasPrefix(s, typ) {
			return typ, s[len(typ):]
		}
	}

	return "", s
}

// getStandardIntegerType parses SUS integer types (d, dC, dS, dL, dQ, u, uC, uS, uL, uQ)
func getStandardIntegerType(s string) (MagicType, string) {
	if len(s) < 1 {
		return TypeInvalid, s
	}

	unsigned := false
	idx := 0

	if s[0] == 'u' {
		unsigned = true
		idx = 1
	} else if s[0] == 'd' {
		idx = 1
	} else {
		return TypeInvalid, s
	}

	if idx >= len(s) {
		// Just 'd' or 'u' - default to long
		if unsigned {
			return TypeUlong, s[idx:]
		}
		return TypeLong, s[idx:]
	}

	if isAlpha(s[idx]) {
		switch s[idx] {
		case 'C': // char/byte
			if unsigned {
				return TypeUbyte, s[idx+1:]
			}
			return TypeByte, s[idx+1:]
		case 'S': // short
			if unsigned {
				return TypeUshort, s[idx+1:]
			}
			return TypeShort, s[idx+1:]
		case 'I', 'L': // int/long
			if unsigned {
				return TypeUlong, s[idx+1:]
			}
			return TypeLong, s[idx+1:]
		case 'Q': // quad
			if unsigned {
				return TypeUquad, s[idx+1:]
			}
			return TypeQuad, s[idx+1:]
		}
	} else if isDigit(s[idx]) {
		switch s[idx] {
		case '1':
			if unsigned {
				return TypeUbyte, s[idx+1:]
			}
			return TypeByte, s[idx+1:]
		case '2':
			if unsigned {
				return TypeUshort, s[idx+1:]
			}
			return TypeShort, s[idx+1:]
		case '4':
			if unsigned {
				return TypeUlong, s[idx+1:]
			}
			return TypeLong, s[idx+1:]
		case '8':
			if unsigned {
				return TypeUquad, s[idx+1:]
			}
			return TypeQuad, s[idx+1:]
		}
	}

	// Default to long
	if unsigned {
		return TypeUlong, s[idx:]
	}
	return TypeLong, s[idx:]
}

// isAlpha checks if a character is alphabetic
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isStringType checks if a type is a string type
func isStringType(typ string) bool {
	return typ == "string" || typ == "pstring" ||
		typ == "bestring16" || typ == "lestring16" ||
		typ == "search" || typ == "regex" ||
		typ == "indirect" || typ == "name" ||
		typ == "use" || typ == "der" || typ == "octal"
}

// parseIndirectModifier parses indirect type modifiers
func parseIndirectModifier(m *Magic, input *string) error {
	if input == nil || *input == "" {
		return nil
	}

	l := *input
	if len(l) > 0 {
		l = l[1:] // Skip first character
	}

	for len(l) > 0 && !isSpace(l[0]) {
		switch l[0] {
		case 'r': // CHAR_INDIRECT_RELATIVE
			m.Flags |= INDIRECT_RELATIVE
		default:
			return fmt.Errorf("indirect modifier '%c' invalid", l[0])
		}
		l = l[1:]
	}

	*input = l
	return nil
}

// parseExtra corresponds to parse_extra in apprentice.c
// This handles the bang[] table directives (!:mime, !:apple, !:ext, !:strength)
func (p *Parser) parseExtra(line string, entry *Entry) {
	if entry.Mp == nil {
		return
	}

	directive := strings.TrimPrefix(line, "!:")

	// The C code's bang[] table has: mime, apple, ext, strength
	if strings.HasPrefix(directive, "mime") {
		// Handle !:mime directive
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			mime := strings.TrimSpace(parts[1])
			// Store in the byte array (converting string to bytes)
			copy(entry.Mp.Mimetype[:], []byte(mime))
		}
	} else if strings.HasPrefix(directive, "apple") {
		// Handle !:apple directive
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			apple := strings.TrimSpace(parts[1])
			// Store Apple file type/creator code
			copy(entry.Mp.Apple[:], []byte(apple))
		}
	} else if strings.HasPrefix(directive, "ext") {
		// Handle !:ext directive
		// Use Fields to properly split on any whitespace
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			// The extension list starts from parts[1]
			extList := strings.Join(parts[1:], " ")
			// Split by '/' to get individual extensions
			exts := strings.Split(extList, "/")
			for _, ext := range exts {
				ext = strings.TrimSpace(ext)
				if ext != "" {
					entry.Mp.Extensions = append(entry.Mp.Extensions, ext)
				}
			}
		}
	} else if strings.HasPrefix(directive, "strength") {
		// Handle !:strength directive
		parts := strings.Fields(directive)
		if len(parts) > 1 {
			strengthValue := strings.Join(parts[1:], " ")
			if err := entry.Mp.ParseStrength(strengthValue); err != nil {
				p.errors = append(p.errors, fmt.Errorf("line %d: strength parse error: %w", entry.Mp.Lineno, err))
			}
			// Recalculate strength after applying the directive
			entry.Mp.Strength = entry.Mp.apprenticeMagicStrength()
		}
	}
	// Unknown directives are silently ignored (as in C code)
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

	// First, set the test type for all entries and their continuations
	// This mirrors the behavior of set_text_binary in apprentice.c
	for i := 0; i < len(p.database.Entries); {
		i = SetTextBinary(p.database.Entries, i)
	}

	for _, entry := range p.database.Entries {
		if entry.Mp == nil {
			continue
		}

		if entry.Mp.IsNameType {
			// FILE_NAME type patterns go to Set 1
			if entry.Mp.TestType == BINTEST {
				set1.BinaryEntries = append(set1.BinaryEntries, entry)
			} else {
				set1.TextEntries = append(set1.TextEntries, entry)
			}
		} else {
			// Regular patterns go to Set 0
			if entry.Mp.TestType == BINTEST {
				set0.BinaryEntries = append(set0.BinaryEntries, entry)
			} else {
				set0.TextEntries = append(set0.TextEntries, entry)
			}
		}
	}

	// Sort entries by strength using apprentice_sort algorithm
	apprenticeSort(set0.BinaryEntries)
	apprenticeSort(set0.TextEntries)
	apprenticeSort(set1.BinaryEntries)
	apprenticeSort(set1.TextEntries)

	p.database.Sets = []Set{set0, set1}
}

// SetTextBinary sets the test type (binary or text) for entries and their continuations
// This is equivalent to set_text_binary() in apprentice.c
func SetTextBinary(entries []*Entry, startIndex int) int {
	if startIndex >= len(entries) {
		return startIndex
	}

	startEntry := entries[startIndex]
	if startEntry.Mp == nil {
		return startIndex + 1
	}

	// Set the test type for the top-level entry
	testType := startEntry.GetTestType()
	startEntry.Mp.TestType = testType

	// Process continuation entries
	i := startIndex + 1
	for i < len(entries) && entries[i].Mp != nil && entries[i].Mp.ContLevel > 0 {
		// Continuation entries inherit the test type from the parent
		entries[i].Mp.TestType = testType
		i++
	}

	return i
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
				if err := parser.LoadFile(magicFile); err == nil {
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
			if err := parser.LoadFile(path); err == nil {
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

	if err := parser.LoadOne(reader, "inline"); err != nil {
		return nil, err
	}

	parser.OrganizeSets()
	return parser.GetDatabase(), nil
}

// apprenticeSort sorts entries by strength (descending)
// This is a port of the apprentice_sort function from apprentice.c
func apprenticeSort(entries []*Entry) {
	sort.Slice(entries, func(i, j int) bool {
		return apprenticeSortCompare(entries[i], entries[j]) < 0
	})
}

// apprenticeSortCompare compares two entries for sorting
// Returns negative if a should come before b (a has higher strength)
// Returns positive if b should come before a (b has higher strength)
// Returns 0 if they are equal
func apprenticeSortCompare(a, b *Entry) int {
	if a.Mp == nil || b.Mp == nil {
		if a.Mp == nil && b.Mp == nil {
			return 0
		}
		if a.Mp == nil {
			return 1 // b comes first
		}
		return -1 // a comes first
	}

	// Calculate strength using file_magic_strength equivalent
	sa := fileMagicStrength(a.Mp, a.ContCount)
	sb := fileMagicStrength(b.Mp, b.ContCount)

	if sa == sb {
		// When strengths are equal, compare the magic structures
		// Create copies to zero out line numbers for comparison
		mpa := *a.Mp
		mpb := *b.Mp
		mpa.Lineno = 0
		mpb.Lineno = 0

		// Compare the structures byte-by-byte
		x := compareMagicStructs(&mpa, &mpb)
		if x == 0 {
			// Don't warn for DER type
			if mpa.TypeStr != "der" {
				// Duplicate magic entry detected
				fmt.Fprintf(os.Stderr, "Warning: Duplicate magic entry `%s'\n",
					string(bytes.TrimRight(a.Mp.Desc[:], "\x00")))
			}
			return 0
		}
		// Reverse the comparison result to maintain consistency with C code
		if x > 0 {
			return -1
		}
		return 1
	}

	// Higher strength comes first (descending order)
	if sa > sb {
		return -1
	}
	return 1
}

// compareMagicStructs compares two Magic structures field by field
// Returns 0 if equal, negative if a < b, positive if a > b
func compareMagicStructs(a, b *Magic) int {
	// Compare the main fields that affect pattern matching
	// Exclude Lineno as per the original C code

	// Compare basic fields
	if a.Flag != b.Flag {
		if a.Flag < b.Flag {
			return -1
		}
		return 1
	}

	if a.ContLevel != b.ContLevel {
		if a.ContLevel < b.ContLevel {
			return -1
		}
		return 1
	}

	if a.Type != b.Type {
		if a.Type < b.Type {
			return -1
		}
		return 1
	}

	if a.Offset != b.Offset {
		if a.Offset < b.Offset {
			return -1
		}
		return 1
	}

	if a.Reln != b.Reln {
		if a.Reln < b.Reln {
			return -1
		}
		return 1
	}

	// Compare string fields
	if a.TypeStr != b.TypeStr {
		return strings.Compare(a.TypeStr, b.TypeStr)
	}

	if a.TestStr != b.TestStr {
		return strings.Compare(a.TestStr, b.TestStr)
	}

	if a.OperatorStr != b.OperatorStr {
		return strings.Compare(a.OperatorStr, b.OperatorStr)
	}

	// Compare description
	descCmp := bytes.Compare(a.Desc[:], b.Desc[:])
	if descCmp != 0 {
		return descCmp
	}

	// Compare MIME type
	mimeCmp := bytes.Compare(a.Mimetype[:], b.Mimetype[:])
	if mimeCmp != 0 {
		return mimeCmp
	}

	// Compare Value union (simplified comparison)
	valueCmp := bytes.Compare(a.Value.S[:], b.Value.S[:])
	if valueCmp != 0 {
		return valueCmp
	}

	return 0
}

// fileMagicStrength calculates the strength of a magic entry
// This is a wrapper around the Magic struct's Strength field
// but also considers continuation entries when needed
func fileMagicStrength(m *Magic, _ uint32) int {
	if m == nil {
		return 0
	}

	// Get the base strength from the Magic struct
	val := m.Strength

	// If the description is empty, add a small bonus
	// (matching the original C code logic)
	if len(bytes.TrimRight(m.Desc[:], "\x00")) == 0 {
		val++
	}

	// Ensure we only return 0 for FILE_DEFAULT type
	if val <= 0 && m.TypeStr != "default" {
		val = 1
	}

	return val
}

// getValue parses the test value string and stores it in the appropriate Value field
// This is equivalent to the getvalue() function in apprentice.c
func getValue(m *Magic, p string) error {
	// Handle string types
	switch m.Type {
	case TypeBestring16, TypeLestring16, TypeString, TypePstring,
		TypeRegex, TypeSearch, TypeName, TypeUse, TypeDer, TypeOctal:
		// Parse string value using getStr
		parsedStr, err := getStr(p, false)
		if err != nil {
			return fmt.Errorf("cannot get string from '%s': %w", p, err)
		}
		if parsedStr == "" && p != "" {
			return fmt.Errorf("cannot get string from '%s'", p)
		}
		
		// Store in Value.S array
		copy(m.Value.S[:], []byte(parsedStr))
		if len(parsedStr) > 255 {
			m.Vallen = 255
		} else {
			m.Vallen = uint8(len(parsedStr))
		}
		
		// For regex, we could validate it here if needed
		// In the C code, they compile the regex to validate it
		
		return nil
		
	case TypeFloat, TypeBefloat, TypeLefloat:
		// Parse as float32
		val, err := strconv.ParseFloat(strings.TrimSpace(p), 32)
		if err != nil {
			return fmt.Errorf("unparsable float '%s': %w", p, err)
		}
		m.Value.F = float32(val)
		return nil
		
	case TypeDouble, TypeBedouble, TypeLedouble:
		// Parse as float64
		val, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return fmt.Errorf("unparsable double '%s': %w", p, err)
		}
		m.Value.D = val
		return nil
		
	case TypeGuid:
		// Parse GUID
		guid, err := parseGUID(p)
		if err != nil {
			return fmt.Errorf("error parsing guid '%s': %w", p, err)
		}
		m.Value.Guid = guid
		return nil
		
	default:
		// Handle numeric types
		if m.Reln == 'x' {
			// 'x' means any value matches
			return nil
		}
		
		// Parse as unsigned integer with automatic base detection
		p = strings.TrimSpace(p)
		if p == "" {
			return fmt.Errorf("empty numeric value")
		}
		
		// Check for negative sign
		negative := false
		if p[0] == '-' {
			negative = true
			p = p[1:]
		}
		
		// Parse the number (strtoull equivalent)
		var val uint64
		var err error
		
		if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
			// Hexadecimal
			val, err = strconv.ParseUint(p[2:], 16, 64)
		} else if len(p) > 1 && p[0] == '0' {
			// Octal
			val, err = strconv.ParseUint(p, 8, 64)
			if err != nil {
				// Try decimal if octal fails
				val, err = strconv.ParseUint(p, 10, 64)
			}
		} else {
			// Decimal
			val, err = strconv.ParseUint(p, 10, 64)
		}
		
		if err != nil {
			return fmt.Errorf("unparsable number '%s': %w", p, err)
		}
		
		// Apply sign if negative
		if negative && val != math.MaxUint64 {
			val = uint64(-int64(val))
		}
		
		// Check for overflow based on type size
		ts := typeSize(m.Type)
		if ts == 0 {
			return fmt.Errorf("expected numeric type got type %d", m.Type)
		}
		
		if err := checkOverflow(val, ts); err != nil {
			return err
		}
		
		// Apply sign extension
		m.Value.Q = signExtend(m, val)
		
		return nil
	}
}

// checkOverflow checks if a value overflows for the given type size
func checkOverflow(val uint64, typeSize uint8) error {
	var x uint64
	var overflow bool
	
	switch typeSize {
	case 1:
		x = val & ^uint64(0xff)
		overflow = x != 0 && x != ^uint64(0xff)
	case 2:
		x = val & ^uint64(0xffff)
		overflow = x != 0 && x != ^uint64(0xffff)
	case 4:
		x = val & ^uint64(0xffffffff)
		overflow = x != 0 && x != ^uint64(0xffffffff)
	case 8:
		// No overflow possible for 64-bit
		overflow = false
	default:
		return fmt.Errorf("bad width %d", typeSize)
	}
	
	if overflow {
		return fmt.Errorf("overflow for numeric type value %#x", val)
	}
	
	return nil
}

// parseGUID parses a GUID string into two uint64 values
func parseGUID(s string) ([2]uint64, error) {
	// GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	// Or without dashes: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	
	// Remove dashes if present
	s = strings.ReplaceAll(s, "-", "")
	
	// Should be exactly 32 hex characters
	if len(s) != 32 {
		return [2]uint64{}, fmt.Errorf("invalid GUID length: %d", len(s))
	}
	
	// Parse as two 64-bit values
	high, err := strconv.ParseUint(s[:16], 16, 64)
	if err != nil {
		return [2]uint64{}, fmt.Errorf("invalid GUID high part: %w", err)
	}
	
	low, err := strconv.ParseUint(s[16:], 16, 64)
	if err != nil {
		return [2]uint64{}, fmt.Errorf("invalid GUID low part: %w", err)
	}
	
	return [2]uint64{high, low}, nil
}

// typeSize returns the size in bytes for a given type
func typeSize(t MagicType) uint8 {
	switch t {
	case TypeByte, TypeUbyte:
		return 1
	case TypeShort, TypeUshort, TypeBeshort, TypeLeshort, TypeBeshort16, TypeLeshort16:
		return 2
	case TypeLong, TypeUlong, TypeBelong, TypeLelong, TypeMelong,
		TypeFloat, TypeBefloat, TypeLefloat,
		TypeDate, TypeBedate, TypeLedate, TypeLdate,
		TypeBeldate, TypeLeldate, TypeMedate, TypeMeldate,
		TypeMsdosdate, TypeBemsdosdate, TypeLemsdosdate,
		TypeMsdostime, TypeBemsdostime, TypeLemsdostime:
		return 4
	case TypeQuad, TypeUquad, TypeBequad, TypeLequad,
		TypeDouble, TypeBedouble, TypeLedouble,
		TypeQdate, TypeLeqdate, TypeBeqdate,
		TypeQldate, TypeLeqldate, TypeBeqldate,
		TypeQwdate, TypeLeqwdate, TypeBeqwdate:
		return 8
	case TypeGuid:
		return 16
	default:
		return 0
	}
}
