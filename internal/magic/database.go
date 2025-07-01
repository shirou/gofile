package magic

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Database manages the magic database
type Database struct {
	db        *MagicDatabase
	parser    *Parser
	nameIndex map[string]*MagicEntry // Named patterns for FILE_USE
}

// NewDatabase creates a new magic database
func NewDatabase() *Database {
	return &Database{
		parser:    NewParser(),
		nameIndex: make(map[string]*MagicEntry),
	}
}

// Load loads a magic database from file
func (d *Database) Load(filename string) error {
	db, err := d.parser.ParseFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load magic database: %w", err)
	}

	d.db = db
	d.buildNameIndex()
	return nil
}

// LoadDefault loads the default system magic database
func (d *Database) LoadDefault() error {
	// Try common locations for magic.mgc
	locations := []string{
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc",
		"/usr/share/file/magic.mgc",
		"/etc/magic.mgc",
		"./magic.mgc",
	}

	for _, location := range locations {
		if _, err := os.Stat(location); err == nil {
			return d.Load(location)
		}
	}

	return fmt.Errorf("no magic database found in standard locations")
}

// IsLoaded returns true if a database is loaded
func (d *Database) IsLoaded() bool {
	return d.db != nil
}

// GetDatabase returns the loaded magic database
func (d *Database) GetDatabase() *MagicDatabase {
	return d.db
}

// GetEntriesForSet returns all magic entries for a specific set
func (d *Database) GetEntriesForSet(set int) []*MagicEntry {
	if d.db == nil || set < 0 || set >= MAGIC_SETS {
		return nil
	}
	return d.db.Magic[set]
}

// GetAllEntries returns all magic entries from all sets
func (d *Database) GetAllEntries() []*MagicEntry {
	if d.db == nil {
		return nil
	}

	var entries []*MagicEntry
	for set := 0; set < MAGIC_SETS; set++ {
		entries = append(entries, d.db.Magic[set]...)
	}
	return entries
}

// GetEntries returns all magic entries (alias for GetAllEntries for compatibility)
func (d *Database) GetEntries() []*MagicEntry {
	return d.GetAllEntries()
}

// GetEntriesSortedByStrength returns all magic entries sorted by strength (descending)
func (d *Database) GetEntriesSortedByStrength() []*MagicEntry {
	entries := d.GetAllEntries()
	if len(entries) == 0 {
		return entries
	}
	
	// Create a copy to avoid modifying the original slice
	sortedEntries := make([]*MagicEntry, len(entries))
	copy(sortedEntries, entries)
	
	// Sort by strength (descending), with tie-breaking by original order
	sort.SliceStable(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].Strength > sortedEntries[j].Strength
	})
	
	return sortedEntries
}

// GetEntriesByType returns entries of a specific type
func (d *Database) GetEntriesByType(fileType uint8) []*MagicEntry {
	var entries []*MagicEntry

	for _, entry := range d.GetAllEntries() {
		if entry.Type == fileType {
			entries = append(entries, entry)
		}
	}

	return entries
}

// GetEntriesByMimeType returns entries with a specific MIME type
func (d *Database) GetEntriesByMimeType(mimeType string) []*MagicEntry {
	var entries []*MagicEntry

	for _, entry := range d.GetAllEntries() {
		if entry.GetMimeType() == mimeType {
			entries = append(entries, entry)
		}
	}

	return entries
}

// Stats returns statistics about the loaded database
func (d *Database) Stats() *DatabaseStats {
	if d.db == nil {
		return &DatabaseStats{}
	}

	stats := &DatabaseStats{
		Version:    d.db.Version,
		TotalSets:  MAGIC_SETS,
		SetCounts:  make([]uint32, MAGIC_SETS),
		TypeCounts: make(map[uint8]int),
	}

	// Count entries per set
	for i := 0; i < MAGIC_SETS; i++ {
		stats.SetCounts[i] = d.db.NMagic[i]
		stats.TotalEntries += d.db.NMagic[i]
	}

	// Count entries by type
	for _, entry := range d.GetAllEntries() {
		stats.TypeCounts[entry.Type]++
	}

	return stats
}

// DatabaseStats contains statistics about a magic database
type DatabaseStats struct {
	Version      uint32
	TotalSets    int
	TotalEntries uint32
	SetCounts    []uint32
	TypeCounts   map[uint8]int
}

// String returns a string representation of the database stats
func (s *DatabaseStats) String() string {
	return fmt.Sprintf("Magic Database Stats:\n"+
		"  Version: %d\n"+
		"  Total Sets: %d\n"+
		"  Total Entries: %d\n"+
		"  Entries per Set: %v\n"+
		"  Types: %d unique types",
		s.Version, s.TotalSets, s.TotalEntries, s.SetCounts, len(s.TypeCounts))
}

// FindMagicFile finds a magic file in common locations
func FindMagicFile() (string, error) {
	locations := []string{
		"/usr/lib/file/magic.mgc",
		"/usr/share/misc/magic.mgc",
		"/usr/share/file/magic.mgc",
		"/etc/magic.mgc",
		"./magic.mgc",
	}

	// Also check relative to executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		locations = append(locations,
			filepath.Join(execDir, "magic.mgc"),
			filepath.Join(execDir, "..", "share", "magic.mgc"),
		)
	}

	for _, location := range locations {
		if _, err := os.Stat(location); err == nil {
			return location, nil
		}
	}

	return "", fmt.Errorf("magic file not found in any standard location")
}

// buildNameIndex builds an index of named magic patterns for FILE_USE resolution
func (d *Database) buildNameIndex() {
	if d.db == nil {
		return
	}

	// Clear existing index
	d.nameIndex = make(map[string]*MagicEntry)

	// Scan all entries for named patterns
	for set := 0; set < MAGIC_SETS; set++ {
		for _, entry := range d.db.Magic[set] {
			if entry == nil {
				continue
			}

			// Check if this entry has a name in the Apple field
			// Many named patterns store their name in the Apple field
			name := entry.GetApple()
			if len(name) > 0 {
				d.nameIndex[name] = entry
			}

			// Also check the description for pattern names
			// Some patterns use specific description formats that indicate names
			desc := entry.GetDescription()
			if len(desc) > 0 {
				// Look for patterns like "use \name" or similar
				if strings.HasPrefix(strings.ToLower(desc), "use ") {
					patternName := strings.TrimSpace(desc[4:])
					if len(patternName) > 0 {
						d.nameIndex[patternName] = entry
					}
				}
			}

			// Check for TYPE_NAME entries which define named patterns
			if entry.Type == FILE_NAME {
				valueStr := entry.GetValueAsString()
				if len(valueStr) > 0 {
					d.nameIndex[valueStr] = entry
				}
			}
		}
	}
}

// FindNamedEntry finds a magic entry by name for FILE_USE resolution
func (d *Database) FindNamedEntry(name string) *MagicEntry {
	return d.nameIndex[name]
}

// GetNamedEntries returns all named entries (for debugging)
func (d *Database) GetNamedEntries() map[string]*MagicEntry {
	result := make(map[string]*MagicEntry)
	for k, v := range d.nameIndex {
		result[k] = v
	}
	return result
}

// LoadDatabase loads the default magic database (convenience function)
func LoadDatabase() (*Database, error) {
	db := NewDatabase()
	err := db.LoadDefault()
	if err != nil {
		return nil, err
	}
	return db, nil
}
