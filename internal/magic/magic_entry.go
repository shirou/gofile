package magic

// Entry represents the struct magic_entry from apprentice.c
// This contains a Magic struct plus management fields
type Entry struct {
	Mp        *Magic   // Pointer to the magic struct
	ContCount uint32   // Number of continuation entries
	MaxCount  uint32   // Maximum allocated entries
	Children  []*Entry // Child entries (continuation lines)
}

// GetTestType is a wrapper method that calls the Magic's GetTestType
func (e *Entry) GetTestType() TestType {
	if e.Mp == nil {
		return BINTEST // Default to binary if no magic struct
	}
	return e.Mp.GetTestType()
}
