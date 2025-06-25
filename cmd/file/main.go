package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shirou/gofile"
)

var (
	brief        = flag.Bool("b", false, "Brief mode - don't prepend filenames to output lines")
	mimeType     = flag.Bool("i", false, "Output MIME type strings")
	mimeEncoding = flag.Bool("mime-encoding", false, "Output MIME encoding")
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

	// Create detector with options
	opts := gofile.DefaultOptions()
	opts.Brief = *brief
	opts.MimeType = *mimeType
	opts.MimeEncoding = *mimeEncoding
	if *magicFile != "" {
		opts.MagicFile = *magicFile
	}

	detector, err := gofile.NewDetectorWithOptions(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		os.Exit(1)
	}

	// Process each file
	exitCode := 0
	for _, filename := range args {
		if err := processFile(detector, filename); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %v\n", programName, filename, err)
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func processFile(detector *gofile.Detector, filename string) error {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("cannot stat (%s)", err)
	}

	// Detect file type
	info, err := detector.DetectFile(filename)
	if err != nil {
		return err
	}

	// Format output
	output := formatOutput(filename, info)
	fmt.Println(output)

	return nil
}

func formatOutput(filename string, info *gofile.FileInfo) string {
	var result string

	if *brief {
		// Brief mode - no filename prefix
		result = getOutputContent(info)
	} else {
		// Normal mode - include filename
		result = fmt.Sprintf("%s: %s", filename, getOutputContent(info))
	}

	return result
}

func getOutputContent(info *gofile.FileInfo) string {
	if *mimeType {
		return info.MimeType
	}
	
	if *mimeEncoding {
		if info.Encoding != "" {
			return info.Encoding
		}
		return "binary"
	}

	return info.Description
}

func showHelp() {
	fmt.Printf("Usage: %s [OPTION...] [FILE...]\n", programName)
	fmt.Println("Determine file type")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -b                    Brief mode - don't prepend filenames")
	fmt.Println("  -i                    Output MIME type strings")
	fmt.Println("  --mime-encoding       Output MIME encoding")
	fmt.Println("  -m FILE               Use specified magic file")
	fmt.Println("  --version             Show version information")
	fmt.Println("  -h                    Show this help")
	fmt.Println()
	fmt.Printf("Report bugs to: https://github.com/shirou/gofile\n")
}

func showVersion() {
	fmt.Printf("%s %s\n", programName, programVersion)
	fmt.Println("Go implementation of the file command")
	fmt.Println()
	
	// Show magic database stats if available
	if detector, err := gofile.NewDetector(); err == nil {
		stats := detector.GetStats()
		fmt.Printf("Magic database: %d entries, version %d\n", 
			stats.TotalEntries, stats.Version)
	}
}
