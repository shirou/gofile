package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shirou/gofile/internal/detector"
	"github.com/shirou/gofile/internal/magic"
)

var (
	brief        = flag.Bool("b", false, "Brief mode - don't prepend filenames to output lines")
	mimeType     = flag.Bool("i", false, "Output MIME type strings")
	magicFile    = flag.String("m", "", "Use specified magic file")
	version      = flag.Bool("version", false, "Show version information")
	help         = flag.Bool("h", false, "Show help")
)

const (
	programName = "gofile"
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

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] file...\n", programName)
		fmt.Fprintf(os.Stderr, "Try '%s -h' for more information.\n", programName)
		os.Exit(1)
	}

	// Load magic database
	parser := magic.NewParser()
	db, err := parser.ParseFile("test/testdata/magic/magic.mgc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading magic database: %v\n", err)
		os.Exit(1)
	}

	// Create flat database for detector
	flatDB := &FlatDatabase{}
	for set := 0; set < 2; set++ {
		for _, entry := range db.Magic[set] {
			if entry.Type != 0 {
				flatDB.entries = append(flatDB.entries, entry)
			}
		}
	}

	// Configure detector options
	opts := detector.DefaultOptions()
	opts.MIME = *mimeType
	opts.Brief = *brief
	opts.Debug = false // Disable debug mode for normal usage

	// Create detector
	det := detector.New(flatDB, opts)

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

type FlatDatabase struct {
	entries []*magic.MagicEntry
}

func (db *FlatDatabase) GetEntries() []*magic.MagicEntry {
	return db.entries
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
	fmt.Println("  -m FILE               Use specified magic file")
	fmt.Println("  --version             Show version information")
	fmt.Println("  -h                    Show this help")
	fmt.Println()
	fmt.Printf("Report bugs to: https://github.com/shirou/gofile\n")
}

func showVersion() {
	fmt.Printf("%s %s\n", programName, programVersion)
	fmt.Println("Go implementation of the file command")
}