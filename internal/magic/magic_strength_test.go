package magic

func createTestMagic(typeStr, testStr, operatorStr string, level int) *Magic {
	return &Magic{
		TypeStr:     typeStr,
		TestStr:     testStr,
		OperatorStr: operatorStr,
		ContLevel:   uint8(level),
	}
}

func createTestMagicWithStrengthMod(typeStr, testStr, operatorStr string, level int, strengthMod string) *Magic {
	return &Magic{
		TypeStr:     typeStr,
		TestStr:     testStr,
		OperatorStr: operatorStr,
		ContLevel:   uint8(level),
		StrengthMod: strengthMod,
	}
}

func createTestMagicWithFlags(typeStr, testStr, operatorStr string, level int, flags uint32) *Magic {
	return &Magic{
		TypeStr:     typeStr,
		TestStr:     testStr,
		OperatorStr: operatorStr,
		ContLevel:   uint8(level),
		Flags:       flags,
	}
}
