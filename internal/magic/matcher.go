package magic

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

// Matcher performs pattern matching against a file buffer using magic rules.
type Matcher struct {
	set   *MagicSet
	depth int // recursion depth for indirect type
}

const maxIndirectDepth = 16

// NewMatcher creates a new Matcher with the given magic rule set.
func NewMatcher(set *MagicSet) *Matcher {
	if len(set.Groups) == 0 && len(set.Entries) > 0 {
		set.buildGroups()
	}
	return &Matcher{set: set}
}

// Match identifies the type of the given buffer.
func (m *Matcher) Match(buf []byte) string {
	// Try soft magic first
	if result := m.matchSoftMagic(buf); result != "" {
		return result
	}

	// Try JSON detection (like is_json.c)
	if result := detectJSON(buf); result != "" {
		return result
	}

	// Try text magic: detect encoding, decode if needed, run TEXTTEST rules
	if enc := detectEncoding(buf); enc != "" && enc != "data" {
		// For UTF-16/UTF-32, decode and try text magic on decoded content
		if decoded := decodeUTF16(buf); decoded != nil {
			if textResult := m.matchTextMagic(decoded); textResult != "" {
				return appendTextEncoding(textResult, enc)
			}
		}
		return enc
	}

	return "data"
}

// MatchAll identifies the type of the given buffer, returning all matches
// (like C's file -k flag). Results are joined with "\012- " separator.
func (m *Matcher) MatchAll(buf []byte) string {
	results := m.matchSoftMagicAll(buf)

	// Try JSON detection
	if len(results) == 0 {
		if result := detectJSON(buf); result != "" {
			results = append(results, result)
		}
	}

	// Try text encoding
	if enc := detectEncoding(buf); enc != "" && enc != "data" {
		if len(results) == 0 {
			if decoded := decodeUTF16(buf); decoded != nil {
				if textResult := m.matchTextMagic(decoded); textResult != "" {
					results = append(results, appendTextEncoding(textResult, enc))
				}
			}
			if len(results) == 0 {
				results = append(results, enc)
			}
		} else {
			// Append encoding to last result
			last := results[len(results)-1]
			results[len(results)-1] = last + ", " + enc
		}
	} else if len(results) == 0 {
		results = append(results, "data")
	}

	return strings.Join(results, "\\012- ")
}

// matchSoftMagicAll returns all matching soft magic results (for -k mode).
func (m *Matcher) matchSoftMagicAll(buf []byte) []string {
	type matchResult struct {
		result   string
		score    int
		strength int
	}
	var matches []matchResult

	for _, group := range m.set.Groups {
		top := group.Entries[0]
		if top.Type == TypeName {
			continue
		}
		result, score := m.matchGroupScored(buf, &group, 0)
		if result != "" {
			matches = append(matches, matchResult{result, score, group.Strength})
		}
	}

	// Sort by score (highest first, already sorted by strength from group ordering)
	var results []string
	for _, mr := range matches {
		results = append(results, mr.result)
	}
	return results
}

// matchSoftMagic tries to match against soft magic rules only.
// It evaluates all groups and returns the result from the best match.
func (m *Matcher) matchSoftMagic(buf []byte) string {
	bestResult := ""
	bestScore := 0
	bestMime := ""
	bestIsTextTest := false
	var bestTop *MagicEntry

	for _, group := range m.set.Groups {
		top := group.Entries[0]
		if top.Type == TypeName {
			continue
		}

		result, score := m.matchGroupScored(buf, &group, 0)
		if result != "" && score > bestScore {
			bestResult = result
			bestScore = score
			bestMime = top.MimeType
			bestIsTextTest = top.StrFlags&StrFlagTextTest != 0
			bestTop = top
			// If we have a high-quality match (non-default, with continuations),
			// and we've checked all groups with equal or higher strength, stop early
			if score >= 100 && group.Strength < bestScore {
				break
			}
		}
	}

	// Append text encoding detection (like C's file_ascmagic)
	// Also append for search/regex rules with text patterns (C auto-classifies these as TEXTTEST)
	if bestResult != "" {
		shouldAppendText := strings.HasPrefix(bestMime, "text/") || bestIsTextTest
		if !shouldAppendText && bestTop != nil && isAutoTextTest(bestTop) {
			shouldAppendText = true
		}
		if shouldAppendText {
			if enc := detectEncoding(buf); enc != "" && enc != "data" {
				bestResult = appendTextEncoding(bestResult, enc)
			}
		}
	}

	return bestResult
}

// matchGroupScored tries to match a group and returns (result, score).
// Score reflects match quality: higher = more specific continuations matched.
func (m *Matcher) matchGroupScored(buf []byte, group *MagicGroup, baseOffset int) (string, int) {
	top := group.Entries[0]

	// Check text/binary test flags: /t means only match text files, /b only binary
	// When both /t and /b are set, the rule matches any content (both passes in C)
	hasTT := top.StrFlags&StrFlagTextTest != 0
	hasBT := top.StrFlags&StrFlagBinaryTest != 0
	if hasTT && !hasBT {
		if isBinaryData(buf) {
			return "", 0
		}
	}
	if hasBT && !hasTT {
		if !isBinaryData(buf) {
			return "", 0
		}
	}

	matched, val, matchedOffset := m.tryMatch(buf, top, baseOffset)
	if !matched {
		return "", 0
	}

	var out strings.Builder
	out.WriteString(formatDesc(top.Desc, val))

	contScore := m.processContinuations(&out, buf, group.Entries[1:], baseOffset, matchedOffset)

	// Score is primarily group strength. Continuations are a minor tiebreaker only,
	// never enough to override a strength difference between groups.
	// In C file, match priority is determined by strength alone.
	score := group.Strength*100 + contScore

	return out.String(), score
}

// processContinuations handles continuation entries.
// Returns the number of non-default continuations that matched (for scoring).
func (m *Matcher) processContinuations(out *strings.Builder, buf []byte, entries []*MagicEntry, baseOffset int, parentOffset int) int {
	score := 0
	type levelState struct {
		matched       bool
		matchedOffset int
		siblingMatch  bool // for default type
	}
	levels := make([]levelState, 64) // max nesting depth
	levels[0] = levelState{matched: true, matchedOffset: parentOffset}

	for _, cont := range entries {
		cl := int(cont.ContLevel)
		if cl >= len(levels) {
			continue
		}

		// Check if parent level matched
		if cl > 0 && !levels[cl-1].matched {
			continue
		}

		// Handle 'use' type — call a named rule set
		if cont.Type == TypeUse {
			name := cont.Desc
			if name == "" && len(cont.Value.Str) > 0 {
				name = string(cont.Value.Str)
			}
			groupIdx, ok := m.set.NamedRules[name]
			if ok {
				namedGroup := &m.set.Groups[groupIdx]
				// Calculate use base offset (same logic as tryMatch)
				useBase := baseOffset + int(cont.Offset)
				if cont.Flag&FlagOffAdd != 0 {
					if cl > 0 {
						useBase = levels[cl-1].matchedOffset + int(cont.Offset)
					}
				}
				// Resolve indirect offset if needed
				if cont.Flag&FlagIndir != 0 {
					resolved, err := m.resolveIndirect(buf, useBase, cont)
					if err == nil {
						// INDIROFFADD: add parent offset to result
						if cont.Flag&FlagOffAdd != 0 && cl > 0 {
							resolved += levels[cl-1].matchedOffset
						}
						useBase = resolved
					} else {
						continue
					}
				}
				useResult := m.matchNamedGroup(buf, namedGroup, useBase)
				if useResult != "" {
					// Check if the named group's first continuation has \b prefix
					// in its description, meaning the result should be appended without space
					hasBackspace := false
					for _, e := range namedGroup.Entries[1:] {
						if e.Desc != "" {
							hasBackspace = strings.HasPrefix(e.Desc, "\\b")
							break
						}
					}
					// Handle ": " prefix: replace entire previous output with specific identification.
				// In OLE2/CDF magic rules, ": Type" means "this is a more specific identification
				// that replaces the generic type". C's file handles this via a dedicated CDF parser.
				if strings.HasPrefix(useResult, ": ") {
					out.Reset()
					out.WriteString(useResult[2:])
				} else if hasBackspace || (len(useResult) > 0 && (useResult[0] == ',' || useResult[0] == '.' || useResult[0] == ';' || useResult[0] == ':')) {
					out.WriteString(useResult)
				} else {
					appendDesc(out, useResult)
				}
					levels[cl] = levelState{matched: true, matchedOffset: useBase, siblingMatch: true}
					score++
				}
			}
			continue
		}

		// Handle 'clear' type — resets sibling match tracking
		if cont.Type == TypeClear {
			levels[cl] = levelState{matched: true, matchedOffset: levels[cl].matchedOffset, siblingMatch: false}
			continue
		}

		// Handle 'default' type
		if cont.Type == TypeDefault {
			if levels[cl].siblingMatch {
				// Mark as not matched so children (deeper levels) don't run
				levels[cl] = levelState{matched: false, matchedOffset: levels[cl].matchedOffset, siblingMatch: levels[cl].siblingMatch}
				continue // skip default if a sibling already matched
			}
			appendDesc(out, formatDesc(cont.Desc, Value{}))
			levels[cl] = levelState{matched: true, matchedOffset: levels[cl-1].matchedOffset, siblingMatch: true}
			continue
		}

		// Handle 'indirect' type — recursively match at computed offset
		if cont.Type == TypeIndirect {
			indirectOffset := baseOffset + int(cont.Offset)
			if cont.Flag&FlagOffAdd != 0 {
				indirectOffset = levels[cl-1].matchedOffset + int(cont.Offset)
			}
			if cont.Flag&FlagIndir != 0 {
				resolved, err := m.resolveIndirect(buf, indirectOffset, cont)
				if err == nil {
					indirectOffset = resolved
				}
			}
			if indirectOffset >= 0 && indirectOffset < len(buf) && m.depth < maxIndirectDepth {
				m.depth++
				subResult := m.matchSoftMagic(buf[indirectOffset:])
				m.depth--
				if subResult != "" {
					appendDesc(out, formatDesc(cont.Desc, Value{}))
					appendDesc(out, subResult)
					levels[cl] = levelState{matched: true, matchedOffset: indirectOffset, siblingMatch: true}
				}
			}
			continue
		}

		// Determine effective base offset for this continuation
		effectiveBase := baseOffset
		if cont.Flag&FlagOffAdd != 0 {
			// Relative offset: add to parent's matched end
			effectiveBase = levels[cl-1].matchedOffset
		}

		contMatched, contVal, contOffset := m.tryMatch(buf, cont, effectiveBase)
		if contMatched {
			desc := formatDesc(cont.Desc, contVal)
			appendDesc(out, desc)
			levels[cl] = levelState{matched: true, matchedOffset: contOffset, siblingMatch: true}
			score++
			// Reset deeper levels
			for k := cl + 1; k < len(levels); k++ {
				levels[k] = levelState{}
			}
		} else {
			levels[cl] = levelState{matched: false, matchedOffset: levels[cl].matchedOffset, siblingMatch: levels[cl].siblingMatch}
			// Reset deeper levels
			for k := cl + 1; k < len(levels); k++ {
				levels[k] = levelState{}
			}
		}
	}
	return score
}

// matchNamedGroup matches a named group (called via 'use') and returns formatted output.
func (m *Matcher) matchNamedGroup(buf []byte, group *MagicGroup, baseOffset int) string {
	if len(group.Entries) <= 1 {
		return ""
	}

	var out strings.Builder
	// Include the name entry's description if present (set when magic has explicit desc)
	top := group.Entries[0]
	if top.Desc != "" {
		out.WriteString(formatDesc(top.Desc, Value{}))
	}
	// Named groups start from their continuations (skip the 'name' entry itself)
	_ = m.processContinuations(&out, buf, group.Entries[1:], baseOffset, baseOffset)
	return out.String()
}

// tryMatch tests a single entry against the buffer.
// Returns (matched, value, offset after match).
func (m *Matcher) tryMatch(buf []byte, entry *MagicEntry, baseOffset int) (bool, Value, int) {
	offset := baseOffset + int(entry.Offset)

	// Handle relative offset (OFFADD flag)
	if entry.Flag&FlagOffAdd != 0 {
		offset = baseOffset + int(entry.Offset)
	}

	// Resolve indirect offset
	if entry.Flag&FlagIndir != 0 {
		// Use the computed offset (which already includes baseOffset for relative)
		// as the base for the indirect read
		resolved, err := m.resolveIndirect(buf, offset, entry)
		if err != nil {
			return false, Value{}, 0
		}
		// When both OFFADD and INDIR are set (INDIROFFADD in C),
		// add the parent offset to the result
		if entry.Flag&FlagOffAdd != 0 {
			resolved += baseOffset
		}
		offset = resolved
	}

	// Handle negative offset (from end of file, like C's OFFNEGATIVE)
	if entry.Flag&FlagNegative != 0 && offset < 0 {
		offset = len(buf) + offset
	}

	if offset < 0 {
		return false, Value{}, 0
	}

	// For types that don't need file content
	if entry.Type == TypeDefault {
		return true, Value{}, offset
	}

	if offset >= len(buf) {
		return false, Value{}, 0
	}

	// Handle regex type
	if entry.Type == TypeRegex {
		return m.tryMatchRegex(buf, offset, entry)
	}

	val, err := extractValue(buf, offset, entry)
	if err != nil {
		// For search type with '!' relation, not-found means match succeeds
		// (C behavior: FILE_SEARCH with '!' matches when pattern is absent)
		if entry.Type == TypeSearch && entry.Relation == '!' {
			return true, Value{IsString: true}, offset
		}
		return false, Value{}, 0
	}

	// Apply numeric mask
	if entry.HasMask && !val.IsString {
		val.Numeric = applyMask(val.Numeric, entry.NumMask, entry.MaskOp)
	}

	if !compare(val, entry) {
		return false, Value{}, 0
	}

	// Calculate offset after match (before date formatting which changes IsString)
	matchEnd := offset
	if isDateType(entry.Type) {
		matchEnd = offset + typeSize(entry.Type)
	} else if val.IsString {
		switch entry.Type {
		case TypeSearch:
			matchEnd = int(val.Numeric) // search sets Numeric to end position
		case TypePString:
			if val.Numeric > 0 {
				matchEnd = int(val.Numeric) // pstring sets Numeric to end position
			} else {
				matchEnd = offset + len(val.Str) + 1
			}
		default:
			if entry.Relation == 'x' || entry.Relation == '>' || entry.Relation == '<' || entry.Relation == '!' {
				matchEnd = offset + len(val.Str) // use actual extracted length
			} else {
				matchEnd = offset + len(entry.Value.Str)
			}
		}
	} else {
		matchEnd = offset + typeSize(entry.Type)
	}

	// Convert date types to formatted strings for display (after matchEnd calculation)
	if isDateType(entry.Type) {
		val = formatDateValue(val, entry)
	}

	// Convert GUID to formatted string for display
	if entry.Type == TypeGUID && val.IsString && len(val.Str) == 16 {
		formatted := formatGUID(val.Str)
		val = Value{Str: []byte(formatted), IsString: true}
	}

	return true, val, matchEnd
}

// tryMatchRegex matches a regex pattern against the buffer.
func (m *Matcher) tryMatchRegex(buf []byte, offset int, entry *MagicEntry) (bool, Value, int) {
	pattern := string(entry.Value.Str)
	// Strip leading = if present
	if strings.HasPrefix(pattern, "=") {
		pattern = pattern[1:]
	}
	// Enable multiline mode (like C's REG_NEWLINE) so ^ matches at line boundaries
	if strings.Contains(pattern, "^") {
		pattern = "(?m)" + pattern
	}

	// Determine search range
	searchRange := int(entry.StrRange)
	if searchRange == 0 {
		searchRange = 8192
	}

	var region string
	if entry.StrFlags&StrFlagRegexLines != 0 {
		// Range is in lines, not bytes — exclude trailing newline
		lineCount := searchRange
		data := buf[offset:]
		pos := 0
		for n := 0; n < lineCount && pos < len(data); n++ {
			nl := 0
			for nl+pos < len(data) && data[pos+nl] != '\n' {
				nl++
			}
			pos += nl
			if pos < len(data) && data[pos] == '\n' {
				if n < lineCount-1 {
					pos++ // include newline between lines, but not at end
				}
			}
		}
		region = string(data[:pos])
	} else {
		end := offset + searchRange
		if end > len(buf) {
			end = len(buf)
		}
		region = string(buf[offset:end])
	}

	// C's file uses C strings (null-terminated) for regex matching.
	// Truncate at first null byte to match C behavior and avoid
	// false positive matches in binary content.
	if nullIdx := strings.IndexByte(region, 0); nullIdx >= 0 {
		region = region[:nullIdx]
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, Value{}, 0
	}

	loc := re.FindStringIndex(region)
	if loc == nil {
		return false, Value{}, 0
	}

	matched := region[loc[0]:loc[1]]
	matchEnd := offset + loc[1]
	// REGEX_OFFSET_START (/s flag): set matchEnd to start of match instead of end
	if entry.StrFlags&StrFlagRegexStart != 0 {
		matchEnd = offset + loc[0]
	}
	return true, Value{Str: []byte(matched), IsString: true}, matchEnd
}

// applyMask applies a mask operation to a numeric value.
func applyMask(v, mask uint64, op byte) uint64 {
	switch op {
	case '&':
		return v & mask
	case '|':
		return v | mask
	case '^':
		return v ^ mask
	case '+':
		return v + mask
	case '-':
		return v - mask
	case '*':
		return v * mask
	case '/':
		if mask != 0 {
			return v / mask
		}
		return v
	case '%':
		if mask != 0 {
			return v % mask
		}
		return v
	}
	return v
}

// typeSize returns the byte size for a given type.
func typeSize(t FileType) int {
	switch t {
	case TypeByte:
		return 1
	case TypeShort, TypeBEShort, TypeLEShort,
		TypeLEMSDOSDate, TypeLEMSDOSTime, TypeBEMSDOSDate, TypeBEMSDOSTime:
		return 2
	case TypeLong, TypeBELong, TypeLELong, TypeMELong,
		TypeDate, TypeBEDate, TypeLEDate, TypeMEDate,
		TypeLDate, TypeBELDate, TypeLELDate, TypeMELDate,
		TypeFloat, TypeBEFloat, TypeLEFloat:
		return 4
	case TypeQuad, TypeBEQuad, TypeLEQuad,
		TypeDouble, TypeBEDouble, TypeLEDouble,
		TypeQDate, TypeBEQDate, TypeLEQDate,
		TypeQLDate, TypeBEQLDate, TypeLEQLDate,
		TypeQWDate, TypeBEQWDate, TypeLEQWDate:
		return 8
	case TypeGUID:
		return 16
	default:
		return 1
	}
}

// resolveIndirect reads the offset value from the file and computes the real offset.
func (m *Matcher) resolveIndirect(buf []byte, baseOffset int, entry *MagicEntry) (int, error) {
	// Handle negative indirect base (from end of file)
	if baseOffset < 0 {
		baseOffset = len(buf) + baseOffset
	}
	if baseOffset < 0 || baseOffset >= len(buf) {
		return 0, fmt.Errorf("indirect base out of bounds")
	}

	// For ID3 types, read as BE/LE long then convert syncsafe
	inType := entry.InType
	switch inType {
	case TypeBEID3:
		inType = TypeBELong
	case TypeLEID3:
		inType = TypeLELong
	}

	indirEntry := &MagicEntry{Type: inType}
	val, err := extractValue(buf, baseOffset, indirEntry)
	if err != nil {
		return 0, err
	}

	offset := int(val.Numeric)

	// Convert ID3 syncsafe integer: 7 bits per byte
	if entry.InType == TypeBEID3 || entry.InType == TypeLEID3 {
		v := uint32(offset)
		offset = int(((v >> 0) & 0x7f) |
			(((v >> 8) & 0x7f) << 7) |
			(((v >> 16) & 0x7f) << 14) |
			(((v >> 24) & 0x7f) << 21))
	}

	if entry.InOp != 0 {
		disp := int(entry.InOffset)
		switch entry.InOp {
		case '+':
			offset += disp
		case '-':
			offset -= disp
		case '*':
			offset *= disp
		case '&':
			offset &= disp
		case '|':
			offset |= disp
		case '^':
			offset ^= disp
		}
	}

	return offset, nil
}

// isDateType returns true if the type is a date type.
func isDateType(t FileType) bool {
	switch t {
	case TypeDate, TypeBEDate, TypeLEDate, TypeMEDate,
		TypeLDate, TypeBELDate, TypeLELDate, TypeMELDate,
		TypeQDate, TypeBEQDate, TypeLEQDate,
		TypeQLDate, TypeBEQLDate, TypeLEQLDate,
		TypeQWDate, TypeBEQWDate, TypeLEQWDate,
		TypeLEMSDOSDate, TypeLEMSDOSTime,
		TypeBEMSDOSDate, TypeBEMSDOSTime:
		return true
	}
	return false
}

// formatDesc formats the description using the matched value.
func formatDesc(desc string, val Value) string {
	if desc == "" {
		return ""
	}
	if !strings.Contains(desc, "%") {
		return desc
	}
	return printfFormat(desc, val)
}

// formatDateValue converts a numeric timestamp to a date string for date types.
// All date types use UTC, matching the C file command behavior.
func formatDateValue(val Value, entry *MagicEntry) Value {
	if !isDateType(entry.Type) {
		return val
	}

	switch entry.Type {
	case TypeLEMSDOSDate, TypeBEMSDOSDate:
		return formatMSDOSDate(uint16(val.Numeric))
	case TypeLEMSDOSTime, TypeBEMSDOSTime:
		return formatMSDOSTime(uint16(val.Numeric))
	}

	ts := int64(val.Numeric) + entry.DateBias
	t := time.Unix(ts, 0).UTC()
	dateStr := t.Format("Mon Jan _2 15:04:05 2006")
	return Value{Str: []byte(dateStr), IsString: true}
}

// formatMSDOSDate formats an MS-DOS date (16-bit: YYYYYYYMMMMDDDDD).
func formatMSDOSDate(v uint16) Value {
	day := int(v & 0x1F)
	month := int((v >> 5) & 0x0F)
	year := int((v>>9)&0x7F) + 1980
	months := []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	// C file uses 0-indexed month: tm_mon = month - 1; out-of-range clamps to 0 (Jan)
	if month < 1 || month > 12 {
		month = 1
	}
	mon := months[month]
	dateStr := fmt.Sprintf("%s %02d %04d", mon, day, year)
	return Value{Str: []byte(dateStr), IsString: true}
}

// formatMSDOSTime formats an MS-DOS time (16-bit: HHHHHMMMMMMSSSS0).
func formatMSDOSTime(v uint16) Value {
	sec := int(v&0x1F) * 2
	min := int((v >> 5) & 0x3F)
	hour := int((v >> 11) & 0x1F)
	timeStr := fmt.Sprintf("%02d:%02d:%02d", hour, min, sec)
	return Value{Str: []byte(timeStr), IsString: true}
}

// printfFormat handles printf-style format strings.
func printfFormat(format string, val Value) string {
	var out strings.Builder
	i := 0
	for i < len(format) {
		if format[i] != '%' || i+1 >= len(format) {
			out.WriteByte(format[i])
			i++
			continue
		}
		start := i
		i++
		for i < len(format) && (format[i] == '-' || format[i] == '+' || format[i] == ' ' || format[i] == '0' || format[i] == '#') {
			i++
		}
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		if i < len(format) && format[i] == '.' {
			i++
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}
		for i < len(format) && (format[i] == 'l' || format[i] == 'h' || format[i] == 'L') {
			i++
		}
		if i >= len(format) {
			break
		}
		verb := format[i]
		i++

		goFmt := buildGoFmt(format[start:i], verb)

		switch verb {
		case 'd', 'i', 'u':
			fmt.Fprintf(&out, goFmt, val.Numeric)
		case 'x', 'X', 'o':
			// C behavior: %#x with value 0 suppresses the 0x prefix
			if val.Numeric == 0 && strings.Contains(goFmt, "#") {
				goFmt = strings.ReplaceAll(goFmt, "#", "")
			}
			fmt.Fprintf(&out, goFmt, val.Numeric)
		case 'c':
			out.WriteByte(byte(val.Numeric))
		case 's':
			if val.IsString {
				fmt.Fprintf(&out, goFmt, string(val.Str))
			} else {
				fmt.Fprintf(&out, "%d", val.Numeric)
			}
		case '%':
			out.WriteByte('%')
		default:
			out.WriteString(format[start:i])
		}
	}
	return out.String()
}

func buildGoFmt(cFmt string, verb byte) string {
	var b strings.Builder
	b.WriteByte('%')
	for i := 1; i < len(cFmt)-1; i++ {
		c := cFmt[i]
		if c == 'l' || c == 'h' || c == 'L' {
			continue
		}
		b.WriteByte(c)
	}
	switch verb {
	case 'd', 'i', 'u':
		b.WriteByte('d')
	case 'x':
		b.WriteByte('x')
	case 'X':
		b.WriteByte('X')
	case 'o':
		b.WriteByte('o')
	case 's':
		b.WriteByte('s')
	default:
		b.WriteByte(verb)
	}
	return b.String()
}

// isAutoTextTest checks if a top-level entry is automatically classified as TEXTTEST
// by the C file implementation. For search/regex types without explicit /t or /b,
// if the pattern looks like text (printable ASCII), it's classified as TEXTTEST.
func isAutoTextTest(entry *MagicEntry) bool {
	if entry.StrFlags&(StrFlagTextTest|StrFlagBinaryTest) != 0 {
		return false // explicit flag set
	}
	switch entry.Type {
	case TypeSearch, TypeRegex:
		// Check if pattern is text (printable ASCII)
		for _, b := range entry.Value.Str {
			if b < 0x20 || b > 0x7e {
				return false
			}
		}
		return len(entry.Value.Str) > 0
	default:
		return false
	}
}

// appendTextEncoding merges text encoding info into the magic result.
// Mimics C file's behavior: replaces " text executable" or " text" suffix
// with ", {encoding} text [executable]".
func appendTextEncoding(result, encoding string) string {
	if strings.HasSuffix(result, " text executable") {
		return result[:len(result)-len(" text executable")] + ", " + encoding + " executable"
	}
	if strings.HasSuffix(result, " text") {
		return result[:len(result)-len(" text")] + ", " + encoding
	}
	return result + ", " + encoding
}

// decodeUTF16 decodes UTF-16 LE/BE (with BOM) content to UTF-8 bytes.
// Returns nil if not UTF-16.
func decodeUTF16(buf []byte) []byte {
	if len(buf) < 2 {
		return nil
	}
	var littleEndian bool
	var start int
	if buf[0] == 0xFF && buf[1] == 0xFE {
		littleEndian = true
		start = 2
	} else if buf[0] == 0xFE && buf[1] == 0xFF {
		littleEndian = false
		start = 2
	} else {
		return nil
	}

	data := buf[start:]
	if len(data) < 2 {
		return nil
	}

	// Decode UTF-16 to runes
	nUnits := len(data) / 2
	u16s := make([]uint16, nUnits)
	for i := 0; i < nUnits; i++ {
		if littleEndian {
			u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
		} else {
			u16s[i] = binary.BigEndian.Uint16(data[i*2:])
		}
	}

	runes := utf16.Decode(u16s)
	var out strings.Builder
	for _, r := range runes {
		out.WriteRune(r)
	}
	return []byte(out.String())
}

// matchTextMagic runs TEXTTEST magic rules against decoded text content.
// This is used for UTF-16/UTF-32 content after decoding to UTF-8.
func (m *Matcher) matchTextMagic(decoded []byte) string {
	bestResult := ""
	bestScore := 0

	for _, group := range m.set.Groups {
		top := group.Entries[0]
		if top.Type == TypeName {
			continue
		}
		// Only try rules that are TEXTTEST or auto-TEXTTEST
		if top.StrFlags&StrFlagTextTest == 0 && !isAutoTextTest(top) {
			continue
		}
		result, score := m.matchGroupScored(decoded, &group, 0)
		if result != "" && score > bestScore {
			bestResult = result
			bestScore = score
		}
	}

	return bestResult
}

func appendDesc(out *strings.Builder, desc string) {
	if desc == "" {
		return
	}
	// Handle \b at the start: suppress space before this output
	if strings.HasPrefix(desc, "\\b") {
		desc = desc[2:]
		out.WriteString(desc)
	} else if out.Len() > 0 {
		out.WriteByte(' ')
		out.WriteString(desc)
	} else {
		out.WriteString(desc)
	}
}
