# GoFile Project - Pure Go Implementation of Linux file Command

## Project Overview

This project aims to implement the Linux `file` command in pure Go, providing a cross-platform solution for file type detection without external dependencies. The `file` command is a standard Unix utility that determines file types by examining file contents using "magic" patterns.

### Project Goals

1. **Pure Go Implementation**: No CGO or external command dependencies
2. **Cross-Platform**: Works on Linux, macOS, Windows, and other Go-supported platforms
3. **Compatible**: Maintains compatibility with the original file command's magic file format
4. **Performant**: Efficient file type detection with optimized pattern matching
5. **Extensible**: Easy to add new file type definitions

### Reference Implementation

The original file command source code: https://github.com/file/file/

## Documentation Structure

The project documentation is organized in the `docs/` directory with three comprehensive specifications:

### 1. Command-Line Interface Specification (`docs/file-command-cli-spec.md`)

This document provides a complete specification of the file command's CLI, including:

- **Command Synopsis**: All usage patterns and syntax
- **Options Reference**: Detailed documentation of all command-line flags
  - Output control options (-b, -F, -N, -n, -0, -r)
  - File type detection options (-i, --mime-type, --mime-encoding, -k, -e)
  - Symlink handling options (-L, -h)
  - Compressed file options (-z, -Z)
  - Magic file options (-m, -C, -c, -l)
  - File handling options (-f, -s, -p, -E)
  - System options (-P, -S)
  - Debugging options (-d, -v, --help)
- **Environment Variables**: POSIXLY_CORRECT, MAGIC
- **Exit Status Codes**
- **Common Usage Examples**: Practical command-line examples
- **Implementation Notes**: Go-specific considerations

### 2. Magic File Format Specification (`docs/magic-file-format.md`)

This document details the magic file format used for pattern matching:

- **Basic Structure**: offset, type, test, message format
- **Offset Specification**: Basic, negative, indirect, and relative offsets
- **Data Types**: 
  - Basic types (byte, short, long, quad, float, double)
  - String types with modifiers
  - Endian-specific types (big, little, middle)
  - Date types (Unix, Windows timestamps)
  - Special types (regex, search, indirect, guid, der)
- **Test Operators**: Numeric comparisons, bitwise operations, string matching
- **Message Format**: Printf-style formatting
- **Continuation Lines**: Hierarchical test structures using '>' levels
- **Special Directives**: MIME types, file extensions, Apple types, strength modifiers
- **Complex Examples**: Nested patterns, calculated offsets, default cases
- **Binary vs Text Classification**
- **Best Practices and Debugging**

### 3. Magic Strength Specification (`docs/magic-strength-spec.md`)

This document explains the magic strength system for pattern priority:

- **Strength Calculation Algorithm**: Base formula and modifiers
- **Type-Specific Calculations**:
  - Numeric types: strength based on size
  - String types: strength based on length
  - Regex types: based on literal character count
  - Special types: predefined strength values
- **Operator Modifiers**: How comparison operators affect strength
- **!:strength Directive**: Manual strength adjustment syntax
- **Calculation Examples**: Real-world pattern strength calculations
- **Implementation Guidelines**: Go data structures and algorithms
- **Common Strength Values**: Reference table for typical patterns
- **Troubleshooting**: Debugging and optimization techniques

## Implementation Status

### Planned Components

1. **Core Library** (`gofile.go`)
   - Magic file parser
   - Pattern matcher
   - File type detector
   - Strength calculator

2. **Command-Line Tool** (`cmd/file/main.go`)
   - Argument parser
   - Option handling
   - Output formatting

3. **Internal Packages**
   - `internal/magic/parser.go`: Magic file parsing
   - `internal/magic/types.go`: Type definitions and structures
   - `internal/magic/database.go`: Magic pattern database

4. **Testing**
   - Unit tests for parser
   - Integration tests with sample files
   - Benchmark tests for performance
   - Comparison tests with original file command

## Development Guidelines

### Code Organization

```
gofile/
├── cmd/
│   └── file/
│       └── main.go          # CLI entry point
├── internal/
│   └── magic/
│       ├── parser.go         # Magic file parser
│       ├── types.go          # Type definitions
│       └── database.go       # Pattern database
├── docs/
│   ├── file-command-cli-spec.md
│   ├── magic-file-format.md
│   └── magic-strength-spec.md
├── test/
│   ├── integration/          # Integration tests
│   ├── benchmark/            # Performance tests
│   └── utils/                # Test utilities
├── gofile.go                 # Main library interface
├── gofile_test.go            # Library tests
├── go.mod                    # Go module definition
└── CLAUDE.md                 # This file
```

### Key Implementation Considerations

1. **Magic File Parsing**
   - Handle complex offset expressions with parentheses
   - Support all data types and endianness variations
   - Implement indirect and relative offset resolution
   - Parse special directives and continuation levels

2. **Pattern Matching**
   - Efficient byte-level comparisons
   - String matching with all modifier flags
   - Regular expression support with performance considerations
   - Binary and text dual-phase matching

3. **Strength Calculation**
   - Implement the complete strength algorithm
   - Sort patterns by strength for optimal matching order
   - Support manual strength adjustments

4. **Performance Optimization**
   - Cache compiled patterns
   - Optimize common file type detections
   - Minimize file I/O operations
   - Parallel processing where applicable

5. **Compatibility**
   - Maintain compatibility with standard magic file format
   - Support common file command options
   - Provide similar output format

### Testing Strategy

1. **Unit Tests**: Test individual components (parser, matcher, strength calculator)
2. **Integration Tests**: Test complete file type detection workflow
3. **Compatibility Tests**: Compare results with original file command
4. **Performance Tests**: Benchmark against various file types and sizes
5. **Edge Cases**: Test malformed files, empty files, special files

### Next Steps

1. Implement the magic file parser based on the format specification
2. Create the pattern matching engine with all data types
3. Build the strength calculation system
4. Develop the CLI tool with all documented options
5. Create comprehensive test suites
6. Optimize performance based on profiling results
7. Document the Go API for library usage

## Resources

- Original file command: https://github.com/file/file/
- File command man page: `man file`
- Magic file format: `man 5 magic`
- Sample magic files: `/usr/share/file/magic/`

## Contributing

When contributing to this project:

1. Follow the specifications in the docs/ directory
2. Maintain compatibility with the original file command
3. Write tests for new features
4. Update documentation as needed
5. Ensure cross-platform compatibility