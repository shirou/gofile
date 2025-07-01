package detector

import (
	"strings"

	"github.com/shirou/gofile/internal/magic"
)

// ContinuationResult represents the result of processing continuation entries
type ContinuationResult struct {
	Match       bool
	Description string
	Parts       []string // Individual parts that make up the description
}

// processContinuationEntries processes a chain of continuation entries starting from a parent
func (d *Detector) processContinuationEntries(data []byte, entries []*magic.MagicEntry, startIndex int, fullData []byte) *ContinuationResult {
	if startIndex >= len(entries) {
		return &ContinuationResult{Match: false}
	}

	parentEntry := entries[startIndex]

	// First, match the parent entry
	match, result := d.matchEntry(data, parentEntry, fullData)
	if !match {
		return &ContinuationResult{Match: false}
	}

	if d.options.Debug {
		d.logger.Debug("CONTINUATION: Parent entry matched",
			"index", startIndex,
			"cont_level", parentEntry.ContLevel,
			"result", result)
	}

	// Initialize the result
	contResult := &ContinuationResult{
		Match:       true,
		Description: result,
		Parts:       []string{},
	}

	if len(strings.TrimSpace(result)) > 0 {
		contResult.Parts = append(contResult.Parts, result)
	}

	// Process continuation entries (ContLevel > parent's ContLevel)
	parentLevel := parentEntry.ContLevel
	currentIndex := startIndex + 1

	for currentIndex < len(entries) && currentIndex < startIndex+100 {
		entry := entries[currentIndex]

		// Stop if we've moved beyond continuation entries for this parent
		if entry.ContLevel <= parentLevel {
			break
		}

		// Process all continuation entries, even deeply nested ones
		// This is necessary for complex formats like 7z that use ContLevel 32

		// Try to match this continuation entry
		contMatch, contResultStr := d.matchEntry(data, entry, fullData)

		if d.options.Debug {
			d.logger.Debug("CONTINUATION: Testing child entry",
				"index", currentIndex,
				"cont_level", entry.ContLevel,
				"parent_level", parentLevel,
				"match", contMatch,
				"result", contResultStr)
		}

		if contMatch {
			// Add the continuation result if it's meaningful
			if len(strings.TrimSpace(contResultStr)) > 0 {
				contResult.Parts = append(contResult.Parts, contResultStr)
			}

			// For some magic entries, a successful match means we should continue
			// For others, it might mean we should stop
			// This depends on the specific magic file structure
		}

		currentIndex++
	}

	// Combine all parts into a final description
	if len(contResult.Parts) > 0 {
		contResult.Description = strings.Join(contResult.Parts, ", ")
	}

	return contResult
}

// findContinuationSequences identifies potential parent-child entry sequences
func (d *Detector) findContinuationSequences(entries []*magic.MagicEntry) []ContinuationSequence {
	var sequences []ContinuationSequence

	for i := 0; i < len(entries); i++ {
		entry := entries[i]

		// Look for potential parent entries (ContLevel 0 or low level)
		if entry.ContLevel == 0 || (entry.ContLevel > 0 && entry.ContLevel < 16) {
			// Check if there are continuation entries following this one
			hasChildren := false
			childCount := 0

			for j := i + 1; j < len(entries) && j < i+20; j++ { // Look ahead up to 20 entries
				nextEntry := entries[j]

				// Stop if we hit another parent at the same or lower level
				if nextEntry.ContLevel <= entry.ContLevel {
					break
				}

				// Found a potential child
				if nextEntry.ContLevel > entry.ContLevel {
					hasChildren = true
					childCount++
				}
			}

			if hasChildren {
				sequences = append(sequences, ContinuationSequence{
					ParentIndex: i,
					ParentLevel: entry.ContLevel,
					ChildCount:  childCount,
				})
			}
		}
	}

	return sequences
}

// ContinuationSequence represents a parent entry and its continuation entries
type ContinuationSequence struct {
	ParentIndex int
	ParentLevel uint8
	ChildCount  int
}

// evaluateWithContinuations evaluates an entry along with its continuation entries
func (d *Detector) evaluateWithContinuations(data []byte, entries []*magic.MagicEntry, startIndex int, fullData []byte) (bool, string) {
	if startIndex >= len(entries) {
		return false, ""
	}

	// Use the new continuation processing system
	result := d.processContinuationEntries(data, entries, startIndex, fullData)

	if result.Match && len(strings.TrimSpace(result.Description)) > 0 {
		return true, result.Description
	}

	return false, ""
}

// isContinuationCandidate checks if an entry could be a parent in a continuation sequence
func (d *Detector) isContinuationCandidate(entry *magic.MagicEntry, entries []*magic.MagicEntry, index int) bool {
	// Must be at offset 0 to be a file signature
	if entry.Offset != 0 {
		return false
	}

	// Look for continuation entries following this one (check further ahead for deep nesting)
	for i := index + 1; i < len(entries) && i < index+50; i++ {
		nextEntry := entries[i]

		// Found a continuation entry at any higher level
		if nextEntry.ContLevel > entry.ContLevel {
			return true
		}

		// Stop if we've gone too far and hit too many entries at the same or lower level
		if nextEntry.ContLevel <= entry.ContLevel {
			// Allow a few entries at the same level before giving up
			sameOrLowerCount := 0
			for j := i; j < len(entries) && j < i+5; j++ {
				if entries[j].ContLevel <= entry.ContLevel {
					sameOrLowerCount++
				}
			}
			if sameOrLowerCount >= 3 {
				break
			}
		}
	}

	return false
}
