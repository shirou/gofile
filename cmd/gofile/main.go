package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shirou/gofile/internal/magic"
)

func main() {
	brief := flag.Bool("b", false, "brief mode (no filename)")
	mimeType := flag.Bool("i", false, "output MIME type")
	listMode := flag.Bool("l", false, "list magic entries with strength")
	magicFile := flag.String("m", "", "magic file or directory path")
	separator := flag.String("F", ":", "separator")
	flag.Parse()

	opts := magic.Options{
		MimeType: *mimeType,
		Brief:    *brief,
	}

	var fi *magic.FileIdentifier
	var err error

	if *magicFile != "" {
		fi, err = magic.NewFromDir(*magicFile, opts)
	} else {
		fi, err = magic.New(opts)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "file: %v\n", err)
		os.Exit(1)
	}

	if *listMode {
		entries := fi.List()
		var binEntries, textEntries []magic.ListEntry
		for _, e := range entries {
			if e.IsText {
				textEntries = append(textEntries, e)
			} else {
				binEntries = append(binEntries, e)
			}
		}
		fmt.Println("Set 0:")
		fmt.Println("Binary patterns:")
		for _, e := range binEntries {
			mime := ""
			if e.MimeType != "" {
				mime = e.MimeType
			}
			fmt.Printf("Strength = %3d@%d: %s [%s]\n", e.Strength, e.LineNo, e.Desc, mime)
		}
		fmt.Println("Text patterns:")
		for _, e := range textEntries {
			mime := ""
			if e.MimeType != "" {
				mime = e.MimeType
			}
			fmt.Printf("Strength = %3d@%d: %s [%s]\n", e.Strength, e.LineNo, e.Desc, mime)
		}
		fmt.Println("Set 1:")
		fmt.Println("Binary patterns:")
		fmt.Println("Text patterns:")
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: file [-bil] [-m magic] [-F separator] file ...\n")
		os.Exit(1)
	}

	for _, path := range args {
		result, err := fi.IdentifyFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "file: %s: %v\n", path, err)
			continue
		}
		if *brief {
			fmt.Println(result)
		} else {
			fmt.Printf("%s%s %s\n", path, *separator, result)
		}
	}
}
