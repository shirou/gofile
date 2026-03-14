package magic

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// typeNames maps magic type name strings to FileType constants.
var typeNames = map[string]FileType{
	"byte":    TypeByte,
	"short":   TypeShort,
	"long":    TypeLong,
	"quad":    TypeQuad,
	"float":   TypeFloat,
	"double":  TypeDouble,
	"string":  TypeString,
	"pstring": TypePString,
	"date":    TypeDate,
	"ldate":   TypeLDate,
	"qdate":   TypeQDate,
	"qldate":  TypeQLDate,
	"qwdate":  TypeQWDate,

	"beshort":    TypeBEShort,
	"belong":     TypeBELong,
	"bequad":     TypeBEQuad,
	"befloat":    TypeBEFloat,
	"bedouble":   TypeBEDouble,
	"bedate":     TypeBEDate,
	"beldate":    TypeBELDate,
	"beqdate":    TypeBEQDate,
	"beqldate":   TypeBEQLDate,
	"beqwdate":   TypeBEQWDate,
	"beid3":      TypeBEID3,
	"bestring16": TypeBEString16,

	"leshort":    TypeLEShort,
	"lelong":     TypeLELong,
	"lequad":     TypeLEQuad,
	"lefloat":    TypeLEFloat,
	"ledouble":   TypeLEDouble,
	"ledate":     TypeLEDate,
	"leldate":    TypeLELDate,
	"leqdate":    TypeLEQDate,
	"leqldate":   TypeLEQLDate,
	"leqwdate":   TypeLEQWDate,
	"leid3":      TypeLEID3,
	"lestring16": TypeLEString16,

	"melong":  TypeMELong,
	"medate":  TypeMEDate,
	"meldate": TypeMELDate,

	"regex":       TypeRegex,
	"search":      TypeSearch,
	"default":     TypeDefault,
	"clear":       TypeClear,
	"name":        TypeName,
	"use":         TypeUse,
	"indirect":    TypeIndirect,
	"der":         TypeDER,
	"guid":        TypeGUID,
	"offset":      TypeOffset,
	"octal":       TypeOctal,
	"lemsdosdate": TypeLEMSDOSDate,
	"lemsdostime": TypeLEMSDOSTime,
	"bemsdosdate": TypeBEMSDOSDate,
	"bemsdostime": TypeBEMSDOSTime,
}

// isStringTypeName returns true if the type name refers to a string-like type.
func isStringTypeName(name string) bool {
	switch name {
	case "string", "pstring", "bestring16", "lestring16", "search", "regex", "octal":
		return true
	}
	return false
}

// isStringType returns true if the type is a string-like type.
func isStringType(t FileType) bool {
	switch t {
	case TypeString, TypePString, TypeBEString16, TypeLEString16,
		TypeSearch, TypeRegex, TypeOctal:
		return true
	}
	return false
}

// ParseMagicDir loads and parses all magic files from a directory.
func ParseMagicDir(dir string) (*MagicSet, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading magic dir: %w", err)
	}

	// Sort for deterministic order
	sort.Slice(dirEntries, func(i, j int) bool {
		return dirEntries[i].Name() < dirEntries[j].Name()
	})

	set := &MagicSet{
		NamedRules: make(map[string]int),
	}

	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		path := filepath.Join(dir, de.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		entries, err := ParseMagicBytes(de.Name(), data)
		if err != nil {
			continue
		}
		set.Entries = append(set.Entries, entries...)
	}

	// Build groups from flat entries
	set.buildGroups()

	return set, nil
}

// buildGroups organizes flat entries into groups and sorts by strength.
func (set *MagicSet) buildGroups() {
	set.Groups = nil
	set.NamedRules = make(map[string]int)

	var current *MagicGroup
	for _, e := range set.Entries {
		if e.ContLevel == 0 {
			if current != nil {
				set.Groups = append(set.Groups, *current)
			}
			current = &MagicGroup{Entries: []*MagicEntry{e}}
			current.Strength = calcStrength(e)
			if e.Type == TypeName {
				set.NamedRules[string(e.Value.Str)] = len(set.Groups)
			}
		} else if current != nil {
			current.Entries = append(current.Entries, e)
			// In C file, !:strength always applies to mp[0] (group's top-level entry).
			// If a continuation has a strength modifier, propagate it to the top-level entry.
			if e.StrengthOp != 0 && current.Entries[0].StrengthOp == 0 {
				current.Entries[0].StrengthOp = e.StrengthOp
				current.Entries[0].StrengthDelta = e.StrengthDelta
				e.StrengthOp = 0
				e.StrengthDelta = 0
				// Recalculate group strength with the propagated modifier
				current.Strength = calcStrength(current.Entries[0])
			}
		}
	}
	if current != nil {
		set.Groups = append(set.Groups, *current)
	}

	// Sort groups by strength (highest first).
	// For equal strength, compare top-level entries field-by-field to match
	// the C file(1) apprentice_sort() which uses memcmp on struct magic.
	sort.SliceStable(set.Groups, func(i, j int) bool {
		si, sj := set.Groups[i].Strength, set.Groups[j].Strength
		if si != sj {
			return si > sj
		}
		return compareMagicEntry(set.Groups[i].Entries[0], set.Groups[j].Entries[0]) > 0
	})

	// Rebuild named rules index after sort
	set.NamedRules = make(map[string]int)
	for i, g := range set.Groups {
		if g.Entries[0].Type == TypeName {
			set.NamedRules[string(g.Entries[0].Value.Str)] = i
		}
	}
}

// ParseMagicBytes parses a magic file from its raw bytes, returning all entries.
func ParseMagicBytes(name string, data []byte) ([]*MagicEntry, error) {
	lines := strings.Split(string(data), "\n")
	var entries []*MagicEntry
	for i, line := range lines {
		lineNo := i + 1
		// Skip empty lines and comments
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		// Handle metadata lines (!:mime, !:ext, !:apple, !:strength)
		if strings.HasPrefix(line, "!:") {
			if len(entries) == 0 {
				continue
			}
			parseMetadata(entries[len(entries)-1], line)
			continue
		}
		entry, err := parseLine(line, lineNo)
		if err != nil {
			// Skip unparseable lines rather than failing
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseMetadata applies a !:directive to the given entry.
func parseMetadata(entry *MagicEntry, line string) {
	// !:mime application/pdf
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) < 2 {
		// Try space separation
		parts = strings.SplitN(line, " ", 2)
	}
	if len(parts) < 2 {
		return
	}
	directive := parts[0]
	value := strings.TrimSpace(parts[1])
	// Strip inline comments (e.g., "text/PGP # encoding: data")
	if idx := strings.Index(value, " #"); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	switch directive {
	case "!:mime":
		entry.MimeType = value
	case "!:ext":
		entry.Ext = value
	case "!:apple":
		entry.Apple = value
	case "!:strength":
		// NOTE: !:strength is applied to entry but must be propagated to the
		// group's top-level entry (mp[0] in C). This is handled in buildGroups.
		if len(value) >= 2 {
			op := value[0]
			if op == '+' || op == '-' || op == '*' || op == '/' {
				n, err := strconv.Atoi(strings.TrimSpace(value[1:]))
				if err == nil {
					entry.StrengthOp = op
					entry.StrengthDelta = n
				}
			}
		}
	}
}

// parseLine parses a single magic file line into a MagicEntry.
func parseLine(line string, lineNo int) (*MagicEntry, error) {
	entry := &MagicEntry{LineNo: lineNo}

	// 1. Count and strip leading '>' for continuation level
	i := 0
	for i < len(line) && line[i] == '>' {
		i++
	}
	entry.ContLevel = uint8(i)
	line = line[i:]

	// 2. Split into fields: offset, type, test, description
	fields := splitFields(line)
	if len(fields) < 2 {
		return nil, fmt.Errorf("line %d: too few fields", lineNo)
	}

	// 3. Parse offset
	offsetStr := fields[0]
	if strings.HasPrefix(offsetStr, "&") {
		entry.Flag |= FlagOffAdd
	}
	if strings.HasPrefix(offsetStr, "(") || strings.Contains(offsetStr, "(") {
		entry.Flag |= FlagIndir
		parseFullIndirect(entry, offsetStr)
	} else {
		offset, err := parseOffset(offsetStr)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad offset %q: %w", lineNo, offsetStr, err)
		}
		entry.Offset = int32(offset)
		// Detect negative offset (from end of file, like C's OFFNEGATIVE)
		// Strip leading & for relative offset check
		rawOff := strings.TrimPrefix(offsetStr, "&")
		if strings.HasPrefix(rawOff, "-") {
			entry.Flag |= FlagNegative
		}
	}

	// 4. Parse type (may include /flags, /range, or &mask)
	typeName := fields[1]
	unsigned := false

	// Handle unsigned prefix
	rawType := typeName
	if strings.HasPrefix(rawType, "u") {
		// Strip 'u', check if the rest (before &, /, or %) is a valid type
		rest := rawType[1:]
		baseName := rest
		if idx := strings.IndexAny(baseName, "&/%"); idx >= 0 {
			baseName = baseName[:idx]
		}
		if _, ok := typeNames[baseName]; ok {
			unsigned = true
			rawType = rest
		}
	}

	// Extract inline mask: type&mask, type%mask, type/mask (e.g., byte&0x03, ubelong%44100)
	inlineMask := ""
	inlineMaskOp := byte('&')
	// Find the first mask operator (&, %, or / if followed by a digit for numeric types)
	maskIdx := -1
	for mi := 0; mi < len(rawType); mi++ {
		c := rawType[mi]
		if c == '&' || c == '%' {
			maskIdx = mi
			inlineMaskOp = c
			break
		}
		if c == '/' && mi+1 < len(rawType) && rawType[mi+1] >= '0' && rawType[mi+1] <= '9' {
			// Distinguish numeric mask from string flags: check if the base type is numeric
			base := rawType[:mi]
			if _, ok := typeNames[base]; ok && !isStringTypeName(base) {
				maskIdx = mi
				inlineMaskOp = c
				break
			}
		}
	}
	if maskIdx >= 0 {
		inlineMask = rawType[maskIdx+1:]
		rawType = rawType[:maskIdx]
		// Mask may also have /flags after it
		if inlineMaskOp != '/' {
			if slashIdx := strings.IndexByte(inlineMask, '/'); slashIdx >= 0 {
				inlineMask = inlineMask[:slashIdx]
			}
		}
	}

	// Extract date bias: type+N or type-N (e.g., leldate+631065600)
	var dateBias int64
	hasDateBias := false
	for bi := 1; bi < len(rawType); bi++ {
		c := rawType[bi]
		if (c == '+' || c == '-') && bi+1 < len(rawType) && rawType[bi+1] >= '0' && rawType[bi+1] <= '9' {
			base := rawType[:bi]
			if _, ok := typeNames[base]; ok {
				n, err := strconv.ParseInt(rawType[bi:], 10, 64)
				if err == nil {
					dateBias = n
					hasDateBias = true
					rawType = base
				}
				break
			}
		}
	}

	// Split type/flags
	typeFlags := ""
	if idx := strings.IndexByte(rawType, '/'); idx >= 0 {
		typeFlags = rawType[idx+1:]
		rawType = rawType[:idx]
	}

	ft, ok := typeNames[rawType]
	if !ok {
		return nil, fmt.Errorf("line %d: unknown type %q", lineNo, rawType)
	}
	entry.Type = ft
	entry.Unsigned = unsigned

	if hasDateBias {
		entry.DateBias = dateBias
	}

	// Parse inline mask
	if inlineMask != "" {
		mask, err := strconv.ParseUint(inlineMask, 0, 64)
		if err == nil {
			entry.NumMask = mask
			entry.MaskOp = inlineMaskOp
			entry.HasMask = true
		}
	}

	// Parse search range or string flags
	if typeFlags != "" {
		switch ft {
		case TypeSearch:
			// search/N or search/N/flags
			parts := strings.SplitN(typeFlags, "/", 2)
			if r, err := strconv.ParseUint(parts[0], 0, 32); err == nil {
				entry.StrRange = uint32(r)
			}
			if len(parts) > 1 {
				parseStringFlags(entry, parts[1])
			}
		case TypeRegex:
			parseRegexFlags(entry, typeFlags)
		case TypePString:
			parseStringFlags(entry, typeFlags)
		default:
			parseStringFlags(entry, typeFlags)
		}
	}

	// 5. Parse test value and relation
	if len(fields) >= 3 {
		parseTestValue(entry, fields[2])
	}

	// 6. Parse description
	if len(fields) >= 4 {
		entry.Desc = strings.Join(fields[3:], "\t")
	}

	return entry, nil
}

// splitFields splits a magic line by whitespace (tabs or spaces), preserving structure.
// The magic file format uses tabs primarily but some files use spaces.
// Fields: offset, type, test, description (description preserves original spacing).
func splitFields(line string) []string {
	var fields []string
	rest := line

	for i := 0; i < 3; i++ {
		// Skip leading whitespace
		start := 0
		for start < len(rest) && (rest[start] == ' ' || rest[start] == '\t') {
			start++
		}
		rest = rest[start:]
		if rest == "" {
			break
		}

		// Find end of field (next whitespace)
		end := 0
		// For the test field (field 2) and description (field 3), handle specially
		if i < 2 {
			for end < len(rest) && rest[end] != ' ' && rest[end] != '\t' {
				end++
			}
		} else {
			// Test field: find end using tab or 2+ consecutive spaces
			end = findTestFieldEnd(rest)
		}

		if end == 0 {
			fields = append(fields, rest)
			rest = ""
			break
		}
		fields = append(fields, rest[:end])
		rest = rest[end:]
	}

	// Rest is description (field 3+)
	if rest != "" {
		rest = strings.TrimLeft(rest, " \t")
		if rest != "" {
			fields = append(fields, rest)
		}
	}

	return fields
}

// findTestFieldEnd finds where the test field ends and description begins.
// In space-separated lines, test and description are separated by 2+ spaces or tab.
// For numeric test values, a single space after the value is also a boundary.
func findTestFieldEnd(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			return i
		}
		// Stop at unescaped space followed by space or tab (whitespace run = field boundary)
		if s[i] == ' ' && (i == 0 || s[i-1] != '\\') && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
			return i
		}
		// (numeric test values are handled in parseTestValue via extractNumericTest)
	}
	return len(s)
}

// extractNumericTest extracts the numeric part from a test field that may contain
// trailing description text (when lines use single-space separation).
// Returns (numericStr, descriptionTail).
// Strips C-style suffixes (L, l, U, u) from numeric constants.
func extractNumericTest(test string) (string, string) {
	// Find the end of the numeric token
	// Numeric values: optional 0x prefix, then hex/decimal digits, optional L/l/U/u suffix
	i := 0
	if i < len(test) && (test[i] == '0' || test[i] == '-' || test[i] == '+') {
		i++
		if i < len(test) && (test[i] == 'x' || test[i] == 'X') {
			i++
			// Hex digits
			for i < len(test) && isHexDigit(test[i]) {
				i++
			}
		} else {
			// Octal or decimal
			for i < len(test) && test[i] >= '0' && test[i] <= '9' {
				i++
			}
		}
	} else {
		for i < len(test) && test[i] >= '0' && test[i] <= '9' {
			i++
		}
	}
	// Skip C-style suffix
	for i < len(test) && (test[i] == 'L' || test[i] == 'l' || test[i] == 'U' || test[i] == 'u') {
		i++
	}

	numStr := strings.TrimRight(test[:i], "LlUu")
	if i >= len(test) {
		return numStr, ""
	}
	if test[i] == ' ' || test[i] == '\t' {
		return numStr, strings.TrimLeft(test[i:], " \t")
	}
	// No space found — return as-is (might be something like "0x1F|0x02")
	return strings.TrimRight(test, "LlUu"), ""
}

// splitStringTest splits a string-type test field into test and description.
// In C, string test values end at the first unescaped whitespace.
// Returns (testPart, descriptionPart).
func splitStringTest(s string) (string, string) {
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2 // skip escaped character
			continue
		}
		if s[i] == ' ' || s[i] == '\t' {
			desc := strings.TrimLeft(s[i:], " \t")
			return s[:i], desc
		}
		i++
	}
	return s, ""
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Flag constants
const (
	FlagIndir    uint16 = 0x01
	FlagOffAdd   uint16 = 0x02
	FlagNegative uint16 = 0x04 // Offset from end of file (e.g., -22 = filesize-22)
	FlagUnsigned uint16 = 0x08
	FlagNoSpace  uint16 = 0x10
)

// parseOffset parses an offset string. Supports:
// - Simple: 0, 0x1A
// - Relative: &2
// - Indirect: (4.l), (0x3c.l+0x18)
func parseOffset(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	// Relative offset
	if s[0] == '&' {
		n, err := strconv.ParseInt(s[1:], 0, 64)
		return n, err
	}
	// Indirect offset — parse the base, but full indirect handling is in parseLine
	if s[0] == '(' {
		return parseIndirectOffset(s)
	}
	return strconv.ParseInt(s, 0, 64)
}

// parseIndirectOffset parses (base[.type][op disp]) returning the base offset.
func parseIndirectOffset(s string) (int64, error) {
	if len(s) < 3 || s[0] != '(' {
		return 0, fmt.Errorf("invalid indirect offset: %s", s)
	}
	inner := strings.TrimSuffix(s[1:], ")")
	end := 0
	for end < len(inner) && inner[end] != '.' && inner[end] != '+' && inner[end] != '-' && inner[end] != '*' && inner[end] != ')' {
		end++
	}
	base, err := strconv.ParseInt(inner[:end], 0, 64)
	if err != nil {
		return 0, err
	}
	return base, nil
}

// indirectTypeLetter maps indirect type letters to FileType.
var indirectTypeLetter = map[byte]FileType{
	'b': TypeByte, 'c': TypeByte, 'B': TypeByte, 'C': TypeByte,
	'h': TypeLEShort, 's': TypeLEShort,
	'H': TypeBEShort, 'S': TypeBEShort,
	'l': TypeLELong,
	'L': TypeBELong,
	'q': TypeLEQuad,
	'Q': TypeBEQuad,
	'm': TypeMELong,
	'i': TypeLEID3,
	'I': TypeBEID3,
}

// parseFullIndirect parses the full indirect offset including type and displacement.
// Format: [&](base[.type][op disp])
// The & inside (...) is a relative flag for the indirect read (like C FILE_OPINVERSE).
func parseFullIndirect(entry *MagicEntry, s string) {
	// Strip leading & if present (OFFADD = relative to parent match)
	if len(s) > 0 && s[0] == '&' {
		entry.Flag |= FlagOffAdd
		s = s[1:]
	}
	if len(s) < 3 || s[0] != '(' {
		return
	}
	inner := s[1:]
	inner = strings.TrimSuffix(inner, ")")

	// Skip & inside (...) — this is a relative flag for the indirect base
	// In C file, this sets FILE_OPINVERSE on in_type.
	// For our purposes, the outer FlagOffAdd already handles relative addressing.
	if len(inner) > 0 && inner[0] == '&' {
		inner = inner[1:]
	}

	// Parse base offset (may be negative, e.g., -1, -2)
	end := 0
	// Allow leading '-' for negative offsets
	if end < len(inner) && inner[end] == '-' {
		end++
	}
	for end < len(inner) && inner[end] != '.' && !isIndirOp(inner[end]) {
		end++
	}
	base, err := strconv.ParseInt(inner[:end], 0, 64)
	if err != nil {
		return
	}
	entry.Offset = int32(base)
	inner = inner[end:]

	// Parse .type
	if len(inner) > 0 && inner[0] == '.' {
		inner = inner[1:]
		if len(inner) > 0 {
			if ft, ok := indirectTypeLetter[inner[0]]; ok {
				entry.InType = ft
				inner = inner[1:]
			}
		}
	}

	// Parse operator and displacement
	if len(inner) > 0 && isIndirOp(inner[0]) {
		entry.InOp = inner[0]
		disp, err := strconv.ParseInt(inner[1:], 0, 64)
		if err == nil {
			entry.InOffset = int32(disp)
		}
	}
}

func isIndirOp(c byte) bool {
	return c == '+' || c == '-' || c == '*' || c == '&' || c == '|' || c == '^'
}

// parseTestValue parses the test field into relation + value.
// For numeric types, also parses masks: &0xFF00 before the test value.
func parseTestValue(entry *MagicEntry, test string) {
	if test == "x" {
		entry.Relation = 'x'
		return
	}

	if entry.Type == TypeName || entry.Type == TypeUse {
		entry.Value.Str = []byte(test)
		entry.Value.IsString = true
		// Desc is set from the description field (fields[3:]) in the caller, not from test.
		return
	}

	// Check for relation prefix
	rel := byte('=')
	if len(test) > 0 {
		switch test[0] {
		case '=', '!', '<', '>', '&', '^':
			rel = test[0]
			test = strings.TrimLeft(test[1:], " ")
		}
	}
	entry.Relation = rel

	if entry.Type == TypeGUID {
		guid, err := parseGUID(test)
		if err == nil {
			entry.Value.Str = guid
			entry.Value.IsString = true
		}
		return
	}

	if isStringType(entry.Type) {
		// For string/search/regex types, C parses the test value until unescaped
		// whitespace. If description wasn't already extracted (single-space separated),
		// split the test at the first unescaped whitespace boundary.
		testStr, descTail := splitStringTest(test)
		entry.Value.Str = parseStringValue(testStr)
		entry.Value.IsString = true
		if descTail != "" && entry.Desc == "" {
			entry.Desc = descTail
		}
	} else {
		numStr, descTail := extractNumericTest(test)
		n, err := strconv.ParseUint(numStr, 0, 64)
		if err != nil {
			sn, serr := strconv.ParseInt(numStr, 0, 64)
			if serr == nil {
				n = uint64(sn)
			}
		}
		entry.Value.Numeric = n
		// If the test field contained the description (single-space-separated),
		// use it as the description if none was set yet.
		if descTail != "" && entry.Desc == "" {
			entry.Desc = descTail
		}
	}
}

// parseGUID parses a GUID string "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" into 16 bytes.
// Uses MS mixed-endian format: data1 (4B LE), data2 (2B LE), data3 (2B LE), data4 (8B raw).
func parseGUID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid GUID format: %s", s)
	}
	// data1: 8 hex chars → 4 bytes LE
	d1, err := hex.DecodeString(parts[0])
	if err != nil || len(d1) != 4 {
		return nil, fmt.Errorf("invalid GUID data1: %s", parts[0])
	}
	// data2: 4 hex chars → 2 bytes LE
	d2, err := hex.DecodeString(parts[1])
	if err != nil || len(d2) != 2 {
		return nil, fmt.Errorf("invalid GUID data2: %s", parts[1])
	}
	// data3: 4 hex chars → 2 bytes LE
	d3, err := hex.DecodeString(parts[2])
	if err != nil || len(d3) != 2 {
		return nil, fmt.Errorf("invalid GUID data3: %s", parts[2])
	}
	// data4: 4 hex chars + 12 hex chars → 8 bytes raw
	d4a, err := hex.DecodeString(parts[3])
	if err != nil || len(d4a) != 2 {
		return nil, fmt.Errorf("invalid GUID data4a: %s", parts[3])
	}
	d4b, err := hex.DecodeString(parts[4])
	if err != nil || len(d4b) != 6 {
		return nil, fmt.Errorf("invalid GUID data4b: %s", parts[4])
	}

	// Build 16-byte GUID in mixed-endian MS format
	guid := make([]byte, 16)
	// data1: stored as LE uint32
	binary.LittleEndian.PutUint32(guid[0:4], binary.BigEndian.Uint32(d1))
	// data2: stored as LE uint16
	binary.LittleEndian.PutUint16(guid[4:6], binary.BigEndian.Uint16(d2))
	// data3: stored as LE uint16
	binary.LittleEndian.PutUint16(guid[6:8], binary.BigEndian.Uint16(d3))
	// data4: stored as raw bytes
	copy(guid[8:10], d4a)
	copy(guid[10:16], d4b)
	return guid, nil
}

// formatGUID formats 16 bytes as a GUID string.
func formatGUID(data []byte) string {
	if len(data) < 16 {
		return "00000000-0000-0000-0000-000000000000"
	}
	d1 := binary.LittleEndian.Uint32(data[0:4])
	d2 := binary.LittleEndian.Uint16(data[4:6])
	d3 := binary.LittleEndian.Uint16(data[6:8])
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		d1, d2, d3,
		data[8], data[9],
		data[10], data[11], data[12], data[13], data[14], data[15])
}

// String flag constants
const (
	StrFlagCompactWS   uint32 = 1 << 0  // W: compact whitespace
	StrFlagOptionalWS  uint32 = 1 << 1  // w: optional whitespace
	StrFlagIgnoreLower uint32 = 1 << 2  // c: case insensitive (lower)
	StrFlagIgnoreUpper uint32 = 1 << 3  // C: case insensitive (upper)
	StrFlagPStringH    uint32 = 1 << 8  // H: pstring 2-byte BE length
	StrFlagPStringh    uint32 = 1 << 9  // h: pstring 2-byte LE length
	StrFlagPStringL    uint32 = 1 << 10 // L: pstring 4-byte BE length
	StrFlagPStringl    uint32 = 1 << 11 // l: pstring 4-byte LE length
	StrFlagRegexLines  uint32 = 1 << 12 // l: regex range is in lines
	StrFlagTrim        uint32 = 1 << 13 // T: trim whitespace
	StrFlagFullWord    uint32 = 1 << 14 // f: full word match
	StrFlagTextTest    uint32 = 1 << 15 // t: text file test
	StrFlagBinaryTest  uint32 = 1 << 16 // b: binary file test
	StrFlagRegexStart  uint32 = 1 << 17 // s: regex offset from start of match
)

// parseStringFlags parses /flags on string types.
func parseStringFlags(entry *MagicEntry, flags string) {
	for _, c := range flags {
		switch c {
		case 'W':
			entry.StrFlags |= StrFlagCompactWS
		case 'w':
			entry.StrFlags |= StrFlagOptionalWS
		case 'c':
			entry.StrFlags |= StrFlagIgnoreLower
		case 'C':
			entry.StrFlags |= StrFlagIgnoreUpper
		case 'T':
			entry.StrFlags |= StrFlagTrim
		case 'f':
			entry.StrFlags |= StrFlagFullWord
		case 'H':
			entry.StrFlags |= StrFlagPStringH
		case 'h':
			entry.StrFlags |= StrFlagPStringh
		case 'L':
			entry.StrFlags |= StrFlagPStringL
		case 'l':
			entry.StrFlags |= StrFlagPStringl
		case 'b':
			entry.StrFlags |= StrFlagBinaryTest
		case 't':
			entry.StrFlags |= StrFlagTextTest
		case 's':
			// Don't include match length in offset
		}
	}
}

// parseRegexFlags parses /flags on regex types (e.g., /1l, /1024, /1024c).
func parseRegexFlags(entry *MagicEntry, flags string) {
	// Extract leading number
	numEnd := 0
	for numEnd < len(flags) && flags[numEnd] >= '0' && flags[numEnd] <= '9' {
		numEnd++
	}
	if numEnd > 0 {
		if r, err := strconv.ParseUint(flags[:numEnd], 0, 32); err == nil {
			entry.StrRange = uint32(r)
		}
	}
	// Parse remaining character flags
	rest := flags[numEnd:]
	for _, c := range rest {
		switch c {
		case 'l':
			entry.StrFlags |= StrFlagRegexLines
		case 'c':
			entry.StrFlags |= StrFlagIgnoreLower
		case 's':
			entry.StrFlags |= StrFlagRegexStart
		}
	}
}

// parseStringValue parses a string value with escape sequences.
func parseStringValue(s string) []byte {
	var buf []byte
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				buf = append(buf, '\n')
			case 'r':
				buf = append(buf, '\r')
			case 't':
				buf = append(buf, '\t')
			case '\\':
				buf = append(buf, '\\')
			case '0', '1', '2', '3', '4', '5', '6', '7':
				// Octal escape: up to 3 octal digits (matching C file(1))
				val := s[i] - '0'
				i++
				for j := 0; j < 2 && i < len(s) && s[i] >= '0' && s[i] <= '7'; j++ {
					val = val*8 + (s[i] - '0')
					i++
				}
				buf = append(buf, val)
				continue
			case 'x':
				// Hex escape
				i++
				val := byte(0)
				for j := 0; j < 2 && i < len(s); j++ {
					c := s[i]
					switch {
					case c >= '0' && c <= '9':
						val = val*16 + (c - '0')
					case c >= 'a' && c <= 'f':
						val = val*16 + (c - 'a' + 10)
					case c >= 'A' && c <= 'F':
						val = val*16 + (c - 'A' + 10)
					default:
						goto hexDone
					}
					i++
				}
			hexDone:
				buf = append(buf, val)
				continue
			default:
				buf = append(buf, s[i])
			}
			i++
		} else {
			buf = append(buf, s[i])
			i++
		}
	}
	return buf
}
