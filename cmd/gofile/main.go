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
		for _, e := range entries {
			fmt.Printf("%4d %-40s", e.Strength, e.Desc)
			if e.MimeType != "" {
				fmt.Printf(" [%s]", e.MimeType)
			}
			if e.Ext != "" {
				fmt.Printf(" {%s}", e.Ext)
			}
			fmt.Println()
		}
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
