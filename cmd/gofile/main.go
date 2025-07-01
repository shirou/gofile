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

		// Process entries like the official file command
		var binaryPatterns, textPatterns []*magic.MagicEntry
		
		// Process both binary and text patterns
		for mode := 0; mode < 2; mode++ {
			var patterns *[]*magic.MagicEntry
			
			if mode == 0 {
				patterns = &binaryPatterns
			} else {
				patterns = &textPatterns
			}
			
			for i := 0; i < len(setEntries); i++ {
				entry := setEntries[i]
				if entry == nil {
					continue
				}
				
				// Determine if this entry should be included based on type
				// The BINTEST/TEXTTEST flags are not stored in the database
				// but are computed based on the entry type
				includeEntry := false
				
				if mode == 0 { // Binary mode
					// Check if this is a binary type
					switch entry.Type {
					case magic.FILE_BYTE, magic.FILE_SHORT, magic.FILE_LONG,
						magic.FILE_DATE, magic.FILE_BESHORT, magic.FILE_BELONG,
						magic.FILE_BEDATE, magic.FILE_LESHORT, magic.FILE_LELONG,
						magic.FILE_LEDATE, magic.FILE_LDATE, magic.FILE_BELDATE,
						magic.FILE_LELDATE, magic.FILE_MEDATE, magic.FILE_MELDATE,
						magic.FILE_MELONG, magic.FILE_QUAD, magic.FILE_LEQUAD,
						magic.FILE_BEQUAD, magic.FILE_QDATE, magic.FILE_LEQDATE,
						magic.FILE_BEQDATE, magic.FILE_QLDATE, magic.FILE_LEQLDATE,
						magic.FILE_BEQLDATE, magic.FILE_QWDATE, magic.FILE_LEQWDATE,
						magic.FILE_BEQWDATE, magic.FILE_FLOAT, magic.FILE_BEFLOAT,
						magic.FILE_LEFLOAT, magic.FILE_DOUBLE, magic.FILE_BEDOUBLE,
						magic.FILE_LEDOUBLE, magic.FILE_BEVARINT, magic.FILE_LEVARINT,
						magic.FILE_DER, magic.FILE_GUID, magic.FILE_OFFSET,
						magic.FILE_MSDOSDATE, magic.FILE_BEMSDOSDATE, magic.FILE_LEMSDOSDATE,
						magic.FILE_MSDOSTIME, magic.FILE_BEMSDOSTIME, magic.FILE_LEMSDOSTIME,
						magic.FILE_OCTAL:
						includeEntry = true
					case magic.FILE_STRING, magic.FILE_PSTRING, magic.FILE_BESTRING16,
						magic.FILE_LESTRING16, magic.FILE_REGEX, magic.FILE_SEARCH:
						// For string types, check str_flags (stored in NumMask for strings)
						// STRING_BINTEST = BIT(6) = 0x40
						if (entry.NumMask & 0x40) != 0 {
							includeEntry = true
						}
					}
				} else { // Text mode
					switch entry.Type {
					case magic.FILE_STRING, magic.FILE_PSTRING, magic.FILE_BESTRING16,
						magic.FILE_LESTRING16, magic.FILE_REGEX, magic.FILE_SEARCH:
						// For string types, check str_flags
						// STRING_TEXTTEST = BIT(5) = 0x20
						if (entry.NumMask & 0x20) != 0 {
							includeEntry = true
						} else if (entry.NumMask & 0x40) == 0 {
							// If neither BINTEST nor TEXTTEST is set,
							// default to text for string types
							includeEntry = true
						}
					}
				}
				
				if !includeEntry {
					// Skip all continuations of this entry
					for i+1 < len(setEntries) && setEntries[i+1].ContLevel > entry.ContLevel {
						i++
					}
					continue
				}
				
				// Skip certain types
				switch entry.Type {
				case magic.FILE_USE, magic.FILE_NAME, magic.FILE_DEFAULT, 
				     magic.FILE_CLEAR, magic.FILE_INDIRECT:
					// Skip all continuations too
					for i+1 < len(setEntries) && setEntries[i+1].ContLevel > entry.ContLevel {
						i++
					}
					continue
				}
				
				// Find the first non-empty description and MIME type
				// by looking at this entry and its continuations
				descIndex := i
				mimeIndex := i
				lineIndex := i
				
				// Look through continuations
				j := i + 1
				for j < len(setEntries) && setEntries[j].ContLevel > entry.ContLevel {
					if len(setEntries[descIndex].GetDescription()) == 0 && 
					   len(setEntries[j].GetDescription()) > 0 {
						descIndex = j
					}
					if len(setEntries[mimeIndex].GetMimeType()) == 0 && 
					   len(setEntries[j].GetMimeType()) > 0 {
						mimeIndex = j
					}
					j++
				}
				
				// Skip to end of this group
				i = j - 1
				
				// Only include if we have a description
				if len(setEntries[descIndex].GetDescription()) > 0 {
					// Create a synthetic entry for display
					displayEntry := &magic.MagicEntry{
						Type:     entry.Type,
						Offset:   entry.Offset,
						Strength: entry.Strength,
						Desc:     setEntries[descIndex].Desc,
						MimeType: setEntries[mimeIndex].MimeType,
						Lineno:   setEntries[lineIndex].Lineno,
					}
					*patterns = append(*patterns, displayEntry)
				}
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
