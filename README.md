# gofile

A pure Go implementation of the Unix [`file(1)`](https://github.com/file/file) command.

This project is a port of Ian F. Darwin's `file` command (maintained by Christos Zoulas) to Go. It identifies file types using magic number rules, just like the original C implementation.

## Origin

This project is based on the [file](https://github.com/file/file) command, originally written by Ian F. Darwin (1986) and maintained by Christos Zoulas since 1994. The magic database files (`internal/magic/magicdata/Magdir/`) are copied directly from the original project. The matching engine, parser, and CLI are reimplemented in Go from scratch, referencing the original C source as the specification.

See [LICENSE](LICENSE) for the original file(1) license terms.

## Features

- Pure Go, no cgo dependencies
- Self-contained binary with embedded magic database (`go:embed`)
- Custom magic file/directory support (`-m` flag)
- Filesystem magic detection (directory, symlink, pipe, socket, device, empty)
- Text encoding detection (ASCII, UTF-8, UTF-16, UTF-32, ISO-8859, binary)
- JSON / NDJSON detection
- Printf-style description formatting
- Named rules (`name`/`use` type) for reusable pattern sets
- Strength-based rule sorting

## Install

```sh
go install github.com/shirou/gofile/cmd/gofile@latest
```

## Usage

```sh
# Identify files
gofile document.pdf
gofile image.png archive.tar.gz

# Brief mode (no filename prefix)
gofile -b document.pdf

# MIME type output
gofile -i document.pdf

# Use a custom magic file or directory
gofile -m /path/to/magic document.pdf

# List all magic entries with strength
gofile -l

# Custom separator
gofile -F ' --' document.pdf
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-b` | Brief mode (do not prepend filename) |
| `-i` | Output MIME type instead of description |
| `-l` | List magic entries with strength values |
| `-m` | Specify a custom magic file or directory |
| `-F` | Use a custom separator (default: `:`) |

## Library Usage

```go
package main

import (
    "fmt"
    "github.com/shirou/gofile/internal/magic"
)

func main() {
    fi, err := magic.New(magic.Options{})
    if err != nil {
        panic(err)
    }

    result, err := fi.IdentifyFile("document.pdf")
    if err != nil {
        panic(err)
    }
    fmt.Println(result)
}
```

## Project Structure

```
gofile/
├── cmd/gofile/         CLI entry point
├── internal/magic/     Core implementation (parser, matcher, value extraction)
│   └── magicdata/      Embedded magic database (from file(1))
├── docs/               Architecture, format spec, progress
└── repos/file/         Original file(1) source (not included in module)
```

## Acknowledgments

This project would not be possible without the original [file(1)](https://github.com/file/file) command:

- **Ian F. Darwin** - Original author (1986)
- **Christos Zoulas** - Maintainer (1994-present)
- **Guy Harris** - Major contributor (byte-order independence)
- **Mans Rullgard** - Major contributor (libmagic refactoring)

The magic database, representing decades of community contributions, is the heart of file type identification. This Go port aims to make that knowledge accessible in the Go ecosystem.

## License

BSD 2-Clause License. See [LICENSE](LICENSE).

The magic database files are derived from the original file(1) project and are subject to its own BSD license (also included in [LICENSE](LICENSE)).
