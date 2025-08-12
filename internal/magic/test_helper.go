package magic

// Helper functions for tests to create Entry with Magic struct

// NewTestEntry creates an Entry with an initialized Magic struct for testing
func NewTestEntry(typeStr, testStr, operatorStr, messageStr string, level int) *Entry {
	magic := &Magic{
		TypeStr:     typeStr,
		TestStr:     testStr,
		OperatorStr: operatorStr,
		MessageStr:  messageStr,
		ContLevel:   uint8(level),
	}
	return &Entry{
		Mp: magic,
	}
}

// NewTestEntryWithStrength creates an Entry with strength modifier for testing
func NewTestEntryWithStrength(typeStr, testStr, operatorStr, messageStr string, level int, strengthMod string) *Entry {
	magic := &Magic{
		TypeStr:     typeStr,
		TestStr:     testStr,
		OperatorStr: operatorStr,
		MessageStr:  messageStr,
		ContLevel:   uint8(level),
		StrengthMod: strengthMod,
	}
	return &Entry{
		Mp: magic,
	}
}