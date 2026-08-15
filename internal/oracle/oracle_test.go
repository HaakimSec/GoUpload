package oracle

import (
    "testing"
    
    "github.com/HaakimSec/GoUpload/internal/payload"
    "github.com/HaakimSec/GoUpload/internal/types"
)

func TestDetectPHPUpload(t *testing.T) {
    baseline := &Baseline{
        StatusCode:     200,
        ResponseLength: 100,
        ContentType:    "text/html",
        BodySnippet:    "File uploaded",
    }
    
    result := &types.Result{
        StatusCode:  200,
        RespLen:     100,
        RespCT:      "text/html",
        BodySnippet: "File uploaded successfully",
        Filename:    "shell.php",
    }
    
    pl := &payload.Payload{
        TestType:  payload.TestTypeExtensionEvasion,
        Filename:  "shell.php",
        Extension: ".php",
    }
    
    verdict := Analyze(baseline, result, pl)
    if verdict.Verdict != VerdictVulnerable {
        t.Errorf("Expected VULNERABLE, got %s", verdict.Verdict)
    }
}

func TestDetectSafeUpload(t *testing.T) {
    baseline := &Baseline{
        StatusCode:     200,
        ResponseLength: 100,
        BodySnippet:    "File uploaded",
    }
    
    result := &types.Result{
        StatusCode:  403,
        RespLen:     50,
        BodySnippet: "File type not allowed",
        Filename:    "shell.php",
    }
    
    pl := &payload.Payload{
        TestType:  payload.TestTypeExtensionEvasion,
        Filename:  "shell.php",
        Extension: ".php",
    }
    
    verdict := Analyze(baseline, result, pl)
    if verdict.Verdict == VerdictVulnerable {
        t.Errorf("Expected SAFE, got VULNERABLE")
    }
}

func TestDetectGraphQLUpload(t *testing.T) {
    baseline := &Baseline{
        StatusCode:     200,
        ResponseLength: 100,
        BodySnippet:    `{"data":{"id":"123"}}`,
    }
    
    result := &types.Result{
        StatusCode:  200,
        RespLen:     100,
        BodySnippet: `{"data":{"uploadFile":{"id":"123","filename":"test.php"}}}`,
        Filename:    "test.php",
    }
    
    pl := &payload.Payload{
        TestType:  payload.TestTypeGraphQL,
        Filename:  "test.php",
        Extension: ".php",
        GraphQL:   &payload.GraphQLFields{},
    }
    
    verdict := Analyze(baseline, result, pl)
    if verdict.Verdict != VerdictVulnerable {
        t.Errorf("Expected VULNERABLE for GraphQL, got %s", verdict.Verdict)
    }
}
