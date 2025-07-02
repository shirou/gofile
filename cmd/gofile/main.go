package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/shirou/gofile/internal/detector"
	"github.com/shirou/gofile/internal/magic"
)

var (
	brief     = flag.Bool("b", false, "Brief mode - don't prepend filenames to output lines")
	mimeType  = flag.Bool("i", false, "Output MIME type strings")
	magicFile = flag.String("m", "", "Use specified magic file")
	debug     = flag.Bool("d", false, "Enable debug mode - show detailed detection process")
	version   = flag.Bool("version", false, "Show version information")
	help      = flag.Bool("h", false, "Show help")
	list      = flag.Bool("l", false, "List magic patterns and their strength sorted by strength")
)

const (
	programName    = "gofile"
	programVersion = "0.1.0"
)

func main() {
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *version {
		showVersion()
		return
	}

	if *list {
		showMagicList()
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] file...\n", programName)
		fmt.Fprintf(os.Stderr, "Try '%s -h' for more information.\n", programName)
		os.Exit(1)
	}

	// Load magic database
	var db *magic.Database
	if *magicFile != "" {
		db = magic.NewDatabase()
		err := db.Load(*magicFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading magic database from %s: %v\n", *magicFile, err)
			os.Exit(1)
		}
	} else {
		var err error
		db, err = magic.LoadDatabase()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading default magic database: %v\n", err)
			os.Exit(1)
		}
	}

	// Configure detector options
	opts := detector.DefaultOptions()
	opts.MIME = *mimeType
	opts.Brief = *brief
	opts.Debug = *debug

	// Create detector
	det := detector.New(db, opts)

	// Process each file
	exitCode := 0
	for _, filename := range args {
		if err := processFile(filename, det); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %v\n", programName, filename, err)
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}


func processFile(filename string, det *detector.Detector) error {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("cannot stat (%s)", err)
	}

	// Detect file type
	result, err := det.DetectFile(filename)
	if err != nil {
		return err
	}

	// Output result
	fmt.Printf("%s: %s\n", filename, result)

	return nil
}

func showHelp() {
	fmt.Printf("Usage: %s [OPTION...] [FILE...]\n", programName)
	fmt.Println("Determine file type")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -b                    Brief mode - don't prepend filenames")
	fmt.Println("  -i                    Output MIME type strings")
	fmt.Println("  -l                    List magic patterns and their strength")
	fmt.Println("  -m FILE               Use specified magic file")
	fmt.Println("  -d                    Enable debug mode - show detailed detection process")
	fmt.Println("  --version             Show version information")
	fmt.Println("  -h                    Show this help")
	fmt.Println()
	fmt.Printf("Report bugs to: https://github.com/shirou/gofile\n")
}

func showVersion() {
	fmt.Printf("%s %s\n", programName, programVersion)
	fmt.Println("Go implementation of the file command")
}


func showMagicList() {
	// Load magic database
	var db *magic.Database
	if *magicFile != "" {
		db = magic.NewDatabase()
		err := db.Load(*magicFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading magic database from %s: %v\n", *magicFile, err)
			os.Exit(1)
		}
	} else {
		var err error
		db, err = magic.LoadDatabase()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading default magic database: %v\n", err)
			os.Exit(1)
		}
	}

	// Process each set separately to match official output
	mdb := db.GetDatabase()
	if mdb == nil {
		fmt.Fprintf(os.Stderr, "Error: No database loaded\n")
		os.Exit(1)
	}
	
	// Remove debug output
	_ = mdb.Version

	// First, print all empty headers to match file -l output
	for set := 0; set < 2; set++ {
		fmt.Printf("Set %d:\n", set)
		fmt.Println("Binary patterns:")
		fmt.Println("Text patterns:")
	}
	
	// Then process and print actual entries
	for set := 0; set < 2; set++ {
		// Get entries for this set
		setEntries := db.GetEntriesForSet(set)
		if len(setEntries) == 0 {
			continue
		}

		// Process entries in groups based on ContLevel structure
		// This correctly interprets the database format where entries are grouped
		var groupRepresentatives []*magic.MagicEntry
		
		for i := 0; i < len(setEntries); i++ {
			entry := setEntries[i]
			if entry == nil {
				continue
			}
			
			// Start of a new group - collect all continuations
			// This follows the official apprentice_list logic exactly
			groupStart := i
			j := i + 1
			
			// Collect all continuations (entries with cont_level > 0) 
			for j < len(setEntries) && setEntries[j] != nil && setEntries[j].ContLevel > 0 {
				j++
			}
			
			groupEnd := j
			
			// Grouping complete
			
			// Process this group to create a representative entry
			representative := processEntryGroup(setEntries[groupStart:groupEnd])
			if representative != nil {
				groupRepresentatives = append(groupRepresentatives, representative)
			}
			
			// Move to next group
			i = groupEnd - 1
		}
		
		if len(groupRepresentatives) == 0 {
			continue
		}
		
		// Separate entries by mode (binary vs text) using proper type classification
		var binaryPatterns, textPatterns []*magic.MagicEntry
		
		for _, entry := range groupRepresentatives {
			// Set proper mode flags based on entry type (equivalent to set_test_type)
			setTestTypeFlags(entry)
			
			// Add to binary patterns if it has BINTEST flag
			if (entry.Flag & magic.BINTEST) != 0 {
				binaryPatterns = append(binaryPatterns, entry)
			}
			// Add to text patterns if it has TEXTTEST flag  
			if (entry.Flag & magic.TEXTTEST) != 0 {
				textPatterns = append(textPatterns, entry)
			}
		}
		
		// Sort by strength (descending)
		sort.SliceStable(binaryPatterns, func(i, j int) bool {
			return binaryPatterns[i].Strength > binaryPatterns[j].Strength
		})
		sort.SliceStable(textPatterns, func(i, j int) bool {
			return textPatterns[i].Strength > textPatterns[j].Strength
		})
		
		// Print set header with actual entries
		fmt.Printf("Set %d:\n", set)
		
		// Print binary patterns
		fmt.Println("Binary patterns:")
		for _, entry := range binaryPatterns {
			printMagicEntry(entry)
		}
		
		// Print text patterns
		fmt.Println("Text patterns:")
		for _, entry := range textPatterns {
			printMagicEntry(entry)
		}
	}
}


// processEntryGroup creates a representative entry from a group of related magic entries
// This implements the grouping logic similar to apprentice_list in the official file command
func processEntryGroup(group []*magic.MagicEntry) *magic.MagicEntry {
	if len(group) == 0 {
		return nil
	}
	
	// Use the first entry as the base (group leader)
	base := group[0]
	if base == nil {
		return nil
	}
	
	// Find the best description and MIME type from the group
	descIndex := 0
	mimeIndex := 0
	
	for i, entry := range group {
		if entry == nil {
			continue
		}
		
		desc := entry.GetDescription()
		
		// Find first non-empty descriptions and MIME types
		// This follows the official apprentice_list logic exactly
		if len(group[descIndex].GetDescription()) == 0 && len(desc) > 0 {
			descIndex = i
		}
		
		// Prefer non-empty MIME types
		if len(group[mimeIndex].GetMimeType()) == 0 && len(entry.GetMimeType()) > 0 {
			mimeIndex = i
		}
	}
	
	// Only include groups that have a meaningful description
	if len(group[descIndex].GetDescription()) == 0 {
		return nil
	}
	
	// Create representative entry using base entry structure but best description/mime
	representative := &magic.MagicEntry{
		Flag:           base.Flag,
		ContLevel:      base.ContLevel,
		Factor:         base.Factor,
		Reln:           base.Reln,
		Vallen:         base.Vallen,
		Type:           base.Type,
		InType:         base.InType,
		InOp:           base.InOp,
		MaskOp:         base.MaskOp,
		Cond:           base.Cond,
		FactorOp:       base.FactorOp,
		Offset:         base.Offset,
		InOffset:       base.InOffset,
		Lineno:         base.Lineno,
		NumMask:        base.NumMask,
		Value:          base.Value,
		Desc:           group[descIndex].Desc,
		MimeType:       group[mimeIndex].MimeType,
		Apple:          base.Apple,
		Ext:            base.Ext,
		Strength:       base.Strength,
		ManualStrength: base.ManualStrength,
		StrengthOp:     base.StrengthOp,
	}
	
	return representative
}

// setTestTypeFlags sets BINTEST/TEXTTEST flags based on entry type
// This implements the equivalent of set_test_type from apprentice.c
func setTestTypeFlags(entry *magic.MagicEntry) {
	// Reset test flags
	entry.Flag &^= (magic.BINTEST | magic.TEXTTEST)
	
	// Set flags based on entry type
	switch entry.Type {
	// Binary types get BINTEST flag
	case magic.FILE_BYTE, magic.FILE_SHORT, magic.FILE_LONG, magic.FILE_DATE,
		magic.FILE_BESHORT, magic.FILE_BELONG, magic.FILE_BEDATE,
		magic.FILE_LESHORT, magic.FILE_LELONG, magic.FILE_LEDATE,
		magic.FILE_LDATE, magic.FILE_BELDATE, magic.FILE_LELDATE,
		magic.FILE_MEDATE, magic.FILE_MELDATE, magic.FILE_MELONG,
		magic.FILE_QUAD, magic.FILE_LEQUAD, magic.FILE_BEQUAD,
		magic.FILE_QDATE, magic.FILE_LEQDATE, magic.FILE_BEQDATE,
		magic.FILE_QLDATE, magic.FILE_LEQLDATE, magic.FILE_BEQLDATE,
		magic.FILE_QWDATE, magic.FILE_LEQWDATE, magic.FILE_BEQWDATE,
		magic.FILE_FLOAT, magic.FILE_BEFLOAT, magic.FILE_LEFLOAT,
		magic.FILE_DOUBLE, magic.FILE_BEDOUBLE, magic.FILE_LEDOUBLE,
		magic.FILE_BEVARINT, magic.FILE_LEVARINT, magic.FILE_DER,
		magic.FILE_GUID, magic.FILE_OFFSET, magic.FILE_MSDOSDATE,
		magic.FILE_BEMSDOSDATE, magic.FILE_LEMSDOSDATE, magic.FILE_MSDOSTIME,
		magic.FILE_BEMSDOSTIME, magic.FILE_LEMSDOSTIME, magic.FILE_OCTAL:
		entry.Flag |= magic.BINTEST
		
	// String types check str_flags for overrides
	case magic.FILE_STRING, magic.FILE_PSTRING, magic.FILE_BESTRING16,
		magic.FILE_LESTRING16, magic.FILE_REGEX, magic.FILE_SEARCH:
		// Check for explicit STRING_BINTEST flag (stored in NumMask for string types)
		if (entry.NumMask & 0x40) != 0 { // STRING_BINTEST = BIT(6)
			entry.Flag |= magic.BINTEST
		} else if (entry.NumMask & 0x20) != 0 { // STRING_TEXTTEST = BIT(5)
			entry.Flag |= magic.TEXTTEST
		} else {
			// Default for strings: compatibility mode (both)
			// But for -l listing, prefer text mode
			entry.Flag |= magic.TEXTTEST
		}
		
	// Other types default to binary
	default:
		entry.Flag |= magic.BINTEST
	}
}

// printMagicEntry prints a single magic entry in the official format
func printMagicEntry(entry *magic.MagicEntry) {
	desc := entry.GetDescription()
	mime := entry.GetMimeType()
	
	// Clean output - no debug
	
	// Format: Strength = value@offset: description [mime_type]
	// Note: Official file command shows empty brackets [] for entries without MIME
	mimeStr := fmt.Sprintf(" [%s]", mime)
	
	// For string types, file -l shows the string length (Vallen) after @
	// For other types, it shows the offset
	offsetValue := entry.Offset
	if entry.IsString() && entry.Vallen > 0 {
		offsetValue = int32(entry.Vallen)
	}
	
	fmt.Printf("Strength = %d@%d: %s%s\n",
		entry.Strength, offsetValue, desc, mimeStr)
}

// isTextPattern determines if an entry represents a text pattern
func isTextPattern(entry *magic.MagicEntry) bool {
	switch entry.Type {
	case magic.FILE_STRING, magic.FILE_PSTRING, magic.FILE_BESTRING16, magic.FILE_LESTRING16:
		return true
	case magic.FILE_REGEX, magic.FILE_SEARCH:
		return true
	default:
		return false
	}
}
