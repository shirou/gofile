package magic

import (
	"bytes"
	"fmt"
	"sort"
)

// SortEntriesByStrength sorts entries by strength in descending order
func SortEntriesByStrength(entries []*Entry) {
	sort.Slice(entries, func(i, j int) bool {
		// Skip entries without Magic struct
		if entries[i].Mp == nil || entries[j].Mp == nil {
			return false
		}
		// Sort by strength (descending)
		if entries[i].Mp.Strength != entries[j].Mp.Strength {
			return entries[i].Mp.Strength > entries[j].Mp.Strength
		}
		// If strength is equal, sort by line number (ascending)
		return entries[i].Mp.Lineno < entries[j].Mp.Lineno
	})
}

// FormatForList formats the database for --list output
func (db *Database) FormatForList() []string {
	var output []string

	for _, set := range db.Sets {
		output = append(output, fmt.Sprintf("Set %d:", set.Number))

		// Binary patterns
		output = append(output, "Binary patterns:")
		if len(set.BinaryEntries) > 0 {
			// Sort by strength
			sorted := make([]*Entry, len(set.BinaryEntries))
			copy(sorted, set.BinaryEntries)
			SortEntriesByStrength(sorted)

			for _, entry := range sorted {
				if entry.Mp == nil {
					continue
				}

				// Get message - if parent's message is empty, look for child's message
				message := entry.Mp.MessageStr
				if message == "" && len(entry.Children) > 0 {
					// Find first child with non-empty message
					for _, child := range entry.Children {
						if child.Mp != nil && child.Mp.MessageStr != "" {
							message = child.Mp.MessageStr
							break
						}
					}
				}

				// Convert MIME type byte array to string
				mimeBytes := entry.Mp.Mimetype[:]
				// Find null terminator
				if idx := bytes.IndexByte(mimeBytes, 0); idx >= 0 {
					mimeBytes = mimeBytes[:idx]
				}
				mimeStr := string(mimeBytes)

				// If parent's MIME type is empty, look for child's MIME type
				if mimeStr == "" && len(entry.Children) > 0 {
					for _, child := range entry.Children {
						if child.Mp != nil {
							childMimeBytes := child.Mp.Mimetype[:]
							if idx := bytes.IndexByte(childMimeBytes, 0); idx >= 0 {
								childMimeBytes = childMimeBytes[:idx]
							}
							childMimeStr := string(childMimeBytes)
							if childMimeStr != "" {
								mimeStr = childMimeStr
								break
							}
						}
					}
				}

				info := StrengthInfo{
					Value:      entry.Mp.Strength,
					LineNumber: int(entry.Mp.Lineno),
					Message:    message,
					MimeType:   mimeStr,
				}
				output = append(output, info.String())
			}
		}

		// Text patterns
		output = append(output, "Text patterns:")
		if len(set.TextEntries) > 0 {
			// Sort by strength
			sorted := make([]*Entry, len(set.TextEntries))
			copy(sorted, set.TextEntries)
			SortEntriesByStrength(sorted)

			for _, entry := range sorted {
				if entry.Mp == nil {
					continue
				}

				// Get message - if parent's message is empty, look for child's message
				message := entry.Mp.MessageStr
				if message == "" && len(entry.Children) > 0 {
					// Find first child with non-empty message
					for _, child := range entry.Children {
						if child.Mp != nil && child.Mp.MessageStr != "" {
							message = child.Mp.MessageStr
							break
						}
					}
				}

				// Convert MIME type byte array to string
				mimeBytes := entry.Mp.Mimetype[:]
				// Find null terminator
				if idx := bytes.IndexByte(mimeBytes, 0); idx >= 0 {
					mimeBytes = mimeBytes[:idx]
				}
				mimeStr := string(mimeBytes)

				// If parent's MIME type is empty, look for child's MIME type
				if mimeStr == "" && len(entry.Children) > 0 {
					for _, child := range entry.Children {
						if child.Mp != nil {
							childMimeBytes := child.Mp.Mimetype[:]
							if idx := bytes.IndexByte(childMimeBytes, 0); idx >= 0 {
								childMimeBytes = childMimeBytes[:idx]
							}
							childMimeStr := string(childMimeBytes)
							if childMimeStr != "" {
								mimeStr = childMimeStr
								break
							}
						}
					}
				}

				info := StrengthInfo{
					Value:      entry.Mp.Strength,
					LineNumber: int(entry.Mp.Lineno),
					Message:    message,
					MimeType:   mimeStr,
				}
				output = append(output, info.String())
			}
		}
	}

	return output
}

// CompileMagic compiles magic files (placeholder for future implementation)
func CompileMagic(inputFiles []string, outputFile string) error {
	// This would compile magic files into a binary format
	// For now, just parse and validate
	parser := NewParser()

	for _, file := range inputFiles {
		if err := parser.LoadFile(file); err != nil {
			return fmt.Errorf("failed to parse %s: %w", file, err)
		}
	}

	if len(parser.GetErrors()) > 0 {
		return fmt.Errorf("compilation failed with %d errors", len(parser.GetErrors()))
	}

	// TODO: Write compiled format to outputFile
	return fmt.Errorf("compiled magic format not yet implemented")
}

// CheckMagic checks magic files for errors
func CheckMagic(files []string) error {
	parser := NewParser()

	for _, file := range files {
		if err := parser.LoadFile(file); err != nil {
			return fmt.Errorf("failed to parse %s: %w", file, err)
		}
	}

	errors := parser.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			fmt.Printf("Error: %v\n", err)
		}
		return fmt.Errorf("found %d errors in magic files", len(errors))
	}

	fmt.Println("Magic files are valid")
	return nil
}
