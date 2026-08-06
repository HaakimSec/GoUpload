# Adding New Payloads to GoUpload

## Overview

GoUpload's payload system is modular. Each attack technique is in its own file under `internal/payload/`.

## Quick Start

### 1. Create Module File

Create `internal/payload/module.h.go`:

```go
package payload

func moduleH() []*Payload {
    var tests []*Payload
    
    tests = append(tests, &Payload{
        TestType:    TestTypeExtensionEvasion,
        Technique:   "Your technique description",
        Filename:    "test.php",
        Extension:   ".php",
        Body:        phpWebshell,
        ContentType: "image/jpeg",
        Tags:        []string{"custom", "bypass"},
    })
    
    return tests
}
```

### 2. Register TestType

In `generator.go`, add to the `const` block:

```go 
const (
    TestTypeYourModule TestType = "Your Module Name"
)
```

### 3. Register Module
In `modules.go`, add to `ModuleRegistry`:

```go
{
    Name:        "your-module",
    Description: "Your Module Description",
    TestType:    TestTypeYourModule,
    Enabled:     true,
},
```

### 4. Add to AllPayloads

In `generator.go`, add your module to `AllPayloads()`:

```go
if IsModuleEnabled(TestTypeYourModule) {
    all = append(all, moduleH()...)
}
```

### 5. Add to Module Order
In `app.go`, add to `moduleOrder` and `moduleNames`:

```go
moduleOrder := []payload.TestType{
    payload.TestTypeYourModule,
    // ...
}

moduleNames := map[payload.TestType]string{
    payload.TestTypeYourModule: "MODULE H: Your Module Name",
}
```
### Payload Struct Reference

```go
type Payload struct {
    TestType    TestType       // Module category
    Technique   string         // Human-readable description
    Filename    string         // Upload filename
    Extension   string         // File extension
    Body        []byte         // File content
    ContentType string         // MIME type override
    Tags        []string       // Categorization tags
    GraphQL     *GraphQLFields // GraphQL-specific (optional)
}
```

### Best Practices

- Use existing payload bodies (phpWebshell, aspShell, etc.)

- Tag payloads with relevant categories

- Include multiple variations (case, encoding, etc.)

- Test against the Battle Lab before submitting
