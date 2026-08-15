package payload

import "testing"

func TestModuleACount(t *testing.T) {
    payloads := moduleA()
    if len(payloads) < 20 {
        t.Errorf("Module A should have 20+ payloads, got %d", len(payloads))
    }
}

func TestModuleBCount(t *testing.T) {
    payloads := moduleB()
    if len(payloads) < 20 {
        t.Errorf("Module B should have 20+ payloads, got %d", len(payloads))
    }
}

func TestModuleXXECount(t *testing.T) {
    payloads := moduleXXE()
    if len(payloads) < 10 {
        t.Errorf("Module XXE should have 10+ payloads, got %d", len(payloads))
    }
}

func TestModuleRaceCount(t *testing.T) {
    payloads := moduleRace()
    if len(payloads) < 20 {
        t.Errorf("Module Race should have 20+ payloads, got %d", len(payloads))
    }
}

func TestModuleFilter(t *testing.T) {
    EnableModules([]string{"extension"})
    if !IsModuleEnabled(TestTypeExtensionEvasion) {
        t.Error("Extension should be enabled")
    }
    if IsModuleEnabled(TestTypeGraphQL) {
        t.Error("GraphQL should be disabled")
    }
    EnableAllModules()
}
